package licenseguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
