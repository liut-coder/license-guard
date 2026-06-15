package licenseguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyLicenseToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := LicenseTokenClaims{
		Iss:               "license-guard",
		AppID:             "app_test",
		LicenseID:         "lic_test",
		DeviceID:          "dev_test",
		Entitlements:      []string{"export.enabled"},
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(time.Hour).Unix(),
		OfflineGraceUntil: time.Now().Add(24 * time.Hour).Unix(),
	}
	token := signTestToken(t, priv, claims)

	got, err := VerifyLicenseToken(base64.StdEncoding.EncodeToString(pub), token, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != claims.AppID || !HasEntitlement(got.Entitlements, "export.enabled") {
		t.Fatalf("unexpected claims: %#v", got)
	}
}

func TestVerifyCapabilityPolicyBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := CapabilityPolicyBundle{
		AppID:        "app_test",
		LicenseID:    "lic_test",
		DeviceID:     "dev_test",
		Entitlements: []string{"visionflow.automation"},
		Decisions: []CapabilityDecision{{
			Capability:          "automation.run",
			RequiredEntitlement: "visionflow.automation",
			ConfiguredMode:      "block",
			EffectiveMode:       "allow",
			Allowed:             true,
		}},
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	signed := signTestCapabilityPolicy(t, priv, bundle)
	if err := VerifyCapabilityPolicyBundle(base64.StdEncoding.EncodeToString(pub), signed); err != nil {
		t.Fatal(err)
	}
	decision, ok := signed.Decision("automation.run")
	if !ok || !decision.Allowed {
		t.Fatalf("decision = %#v ok=%v, want allowed automation.run", decision, ok)
	}

	tamperedBundle := bundle
	tamperedBundle.Decisions = []CapabilityDecision{{
		Capability:          "automation.run",
		RequiredEntitlement: "visionflow.automation",
		ConfiguredMode:      "block",
		EffectiveMode:       "block",
		Allowed:             false,
	}}
	tampered := signed
	tampered.Bundle = tamperedBundle
	if err := VerifyCapabilityPolicyBundle(base64.StdEncoding.EncodeToString(pub), tampered); err == nil {
		t.Fatal("expected tampered capability policy signature to fail")
	}
}

func TestCachedAuthorizationAllowsSignedOfflineGrace(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	expiresAt := now.Add(-time.Hour)
	graceUntil := now.Add(time.Hour)
	claims := LicenseTokenClaims{
		Iss:               "license-guard",
		AppID:             "app_test",
		LicenseID:         "lic_test",
		DeviceID:          "dev_test",
		Entitlements:      []string{"export.enabled"},
		IssuedAt:          now.Add(-2 * time.Hour).Unix(),
		ExpiresAt:         expiresAt.Unix(),
		OfflineGraceUntil: graceUntil.Unix(),
	}
	token := signTestToken(t, priv, claims)

	t.Setenv("LG_TOKEN_CACHE_PATH", t.TempDir()+"/token.json")
	if err := SaveToken("app_test", VerifyResult{
		LicenseToken:      token,
		ExpiresAt:         &expiresAt,
		OfflineGraceUntil: &graceUntil,
		Entitlements:      []string{"tampered.cache.entitlement"},
	}); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(Options{
		AppID:      "app_test",
		Endpoint:   "http://127.0.0.1:8090/v1",
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		AppVersion: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	auth, err := client.CachedAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	if !auth.Allowed || !auth.InOfflineGrace || !auth.RequiresOnline {
		t.Fatalf("unexpected cached authorization: %#v", auth)
	}
	if !client.IsAllowed("export.enabled") {
		t.Fatal("expected signed entitlement to be allowed")
	}
	if client.IsAllowed("tampered.cache.entitlement") {
		t.Fatal("cache entitlement should not override signed token claims")
	}
}

func TestCachedAuthorizationKeepsVerifiedCapabilityPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := LicenseTokenClaims{
		Iss:          "license-guard",
		AppID:        "app_test",
		LicenseID:    "lic_test",
		DeviceID:     "dev_test",
		Entitlements: []string{"visionflow.automation"},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	}
	token := signTestToken(t, priv, claims)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	policy := signTestCapabilityPolicy(t, priv, CapabilityPolicyBundle{
		AppID:        "app_test",
		LicenseID:    "lic_test",
		DeviceID:     "dev_test",
		Entitlements: []string{"visionflow.automation"},
		Decisions: []CapabilityDecision{{
			Capability:          "automation.run",
			RequiredEntitlement: "visionflow.automation",
			ConfiguredMode:      "block",
			EffectiveMode:       "allow",
			Allowed:             true,
		}},
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	})

	t.Setenv("LG_TOKEN_CACHE_PATH", t.TempDir()+"/token.json")
	if err := SaveToken("app_test", VerifyResult{
		Allowed:          true,
		LicenseToken:     token,
		ExpiresAt:        &expiresAt,
		Entitlements:     []string{"tampered.cache.entitlement"},
		CapabilityPolicy: &policy,
	}); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(Options{
		AppID:      "app_test",
		Endpoint:   "http://127.0.0.1:8090/v1",
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		AppVersion: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.CachedAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	if auth.CapabilityPolicy == nil {
		t.Fatal("expected verified capability policy in cached authorization")
	}
	decision, ok := auth.CapabilityPolicy.Decision("automation.run")
	if !ok || !decision.Allowed {
		t.Fatalf("cached policy decision = %#v ok=%v, want allowed automation.run", decision, ok)
	}
}

func TestCachedAuthorizationRejectsTamperedToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := LicenseTokenClaims{
		Iss:          "license-guard",
		AppID:        "app_test",
		LicenseID:    "lic_test",
		DeviceID:     "dev_test",
		Entitlements: []string{"visionflow.automation"},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	}
	token := signTestToken(t, priv, claims)
	tampered := tamperTokenPayload(t, token, func(payload *LicenseTokenClaims) {
		payload.Entitlements = append(payload.Entitlements, "visionflow.admin")
	})
	expiresAt := time.Unix(claims.ExpiresAt, 0)

	t.Setenv("LG_TOKEN_CACHE_PATH", t.TempDir()+"/token.json")
	if err := SaveToken("app_test", VerifyResult{
		Allowed:      true,
		LicenseToken: tampered,
		ExpiresAt:    &expiresAt,
		Entitlements: []string{"visionflow.admin"},
	}); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(Options{
		AppID:      "app_test",
		Endpoint:   "http://127.0.0.1:8090/v1",
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		AppVersion: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CachedAuthorization(); err == nil {
		t.Fatal("expected tampered cached token to fail signature verification")
	}
}

func TestCachedAuthorizationRejectsTokenAppMismatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := LicenseTokenClaims{
		Iss:          "license-guard",
		AppID:        "other_app",
		LicenseID:    "lic_test",
		DeviceID:     "dev_test",
		Entitlements: []string{"visionflow.automation"},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	}
	token := signTestToken(t, priv, claims)
	expiresAt := time.Unix(claims.ExpiresAt, 0)

	t.Setenv("LG_TOKEN_CACHE_PATH", t.TempDir()+"/token.json")
	if err := SaveToken("app_test", VerifyResult{
		Allowed:      true,
		LicenseToken: token,
		ExpiresAt:    &expiresAt,
		Entitlements: []string{"visionflow.automation"},
	}); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(Options{
		AppID:      "app_test",
		Endpoint:   "http://127.0.0.1:8090/v1",
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		AppVersion: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CachedAuthorization(); err == nil {
		t.Fatal("expected cached token app mismatch to fail")
	}
}

func signTestToken(t *testing.T, privateKey ed25519.PrivateKey, claims LicenseTokenClaims) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "LG-LICENSE"})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func tamperTokenPayload(t *testing.T, token string, mutate func(*LicenseTokenClaims)) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d, want 3", len(parts))
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims LicenseTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("unmarshal token payload: %v", err)
	}
	mutate(&claims)
	payloadJSON, err = json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(payloadJSON)
	return strings.Join(parts, ".")
}

func signTestCapabilityPolicy(t *testing.T, privateKey ed25519.PrivateKey, bundle CapabilityPolicyBundle) SignedCapabilityPolicyBundle {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, payload)
	return SignedCapabilityPolicyBundle{
		Alg:       "EdDSA",
		KeyType:   "Ed25519",
		Bundle:    bundle,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
}
