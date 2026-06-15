package licenseguard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrPublicKeyRequired = errors.New("license guard public key is required")
	ErrTokenExpired      = errors.New("license token expired")
)

type LicenseTokenClaims struct {
	Iss               string   `json:"iss"`
	AppID             string   `json:"app_id"`
	LicenseID         string   `json:"license_id"`
	DeviceID          string   `json:"device_id"`
	Entitlements      []string `json:"entitlements"`
	IssuedAt          int64    `json:"iat"`
	ExpiresAt         int64    `json:"exp"`
	OfflineGraceUntil int64    `json:"offline_grace_until,omitempty"`
}

type CachedAuthorization struct {
	Allowed           bool                          `json:"allowed"`
	RequiresOnline    bool                          `json:"requires_online"`
	InOfflineGrace    bool                          `json:"in_offline_grace"`
	ExpiresAt         *time.Time                    `json:"expires_at,omitempty"`
	OfflineGraceUntil *time.Time                    `json:"offline_grace_until,omitempty"`
	Entitlements      []string                      `json:"entitlements,omitempty"`
	CapabilityPolicy  *SignedCapabilityPolicyBundle `json:"capability_policy,omitempty"`
	Claims            *LicenseTokenClaims           `json:"claims,omitempty"`
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "ed25519:")
	value = strings.TrimPrefix(value, "lgpk_")
	if value == "" {
		return nil, ErrPublicKeyRequired
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func VerifyLicenseToken(publicKeyValue string, token string, allowExpired bool) (*LicenseTokenClaims, error) {
	publicKey, err := ParsePublicKey(publicKeyValue)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, []byte(signingInput), signature) {
		return nil, fmt.Errorf("invalid token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims LicenseTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if !allowExpired && time.Now().Unix() > claims.ExpiresAt {
		return &claims, ErrTokenExpired
	}
	return &claims, nil
}

func VerifyCapabilityPolicyBundle(publicKeyValue string, signed SignedCapabilityPolicyBundle) error {
	publicKey, err := ParsePublicKey(publicKeyValue)
	if err != nil {
		return err
	}
	if strings.TrimSpace(signed.Signature) == "" {
		return fmt.Errorf("capability policy signature is required")
	}
	payload, err := json.Marshal(signed.Bundle)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("invalid capability policy signature")
	}
	return nil
}

func (c *Client) CachedAuthorization() (*CachedAuthorization, error) {
	cached, err := LoadToken(c.options.AppID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	auth := &CachedAuthorization{Entitlements: append([]string(nil), cached.Entitlements...)}
	if c.options.PublicKey == "" {
		auth.Allowed = cachedTokenTimeValid(cached.ExpiresAt, now)
		auth.RequiresOnline = !auth.Allowed
		auth.InOfflineGrace = !auth.Allowed && cachedTokenTimeValid(cached.OfflineGraceUntil, now)
		if auth.InOfflineGrace {
			auth.Allowed = true
			auth.RequiresOnline = true
		}
		auth.ExpiresAt = parseCacheTimePtr(cached.ExpiresAt)
		auth.OfflineGraceUntil = parseCacheTimePtr(cached.OfflineGraceUntil)
		return auth, nil
	}

	claims, err := VerifyLicenseToken(c.options.PublicKey, cached.LicenseToken, true)
	if err != nil {
		return nil, err
	}
	if claims.AppID != c.options.AppID {
		return nil, fmt.Errorf("cached token app mismatch")
	}
	if cached.CapabilityPolicy != nil {
		if err := VerifyCapabilityPolicyBundle(c.options.PublicKey, *cached.CapabilityPolicy); err != nil {
			return nil, err
		}
		if cached.CapabilityPolicy.Bundle.AppID != c.options.AppID {
			return nil, fmt.Errorf("cached capability policy app mismatch")
		}
		auth.CapabilityPolicy = cached.CapabilityPolicy
	}

	expiresAt := time.Unix(claims.ExpiresAt, 0)
	auth.Claims = claims
	auth.ExpiresAt = &expiresAt
	auth.Entitlements = append([]string(nil), claims.Entitlements...)
	if now.Before(expiresAt) || now.Equal(expiresAt) {
		auth.Allowed = true
		return auth, nil
	}

	graceUnix := claims.OfflineGraceUntil
	if graceUnix == 0 {
		graceUnix = parseCacheUnix(cached.OfflineGraceUntil)
	}
	if graceUnix > 0 {
		graceUntil := time.Unix(graceUnix, 0)
		auth.OfflineGraceUntil = &graceUntil
		if now.Before(graceUntil) || now.Equal(graceUntil) {
			auth.Allowed = true
			auth.RequiresOnline = true
			auth.InOfflineGrace = true
		}
	}
	return auth, nil
}

func (c *Client) CurrentEntitlements() []string {
	auth, err := c.CachedAuthorization()
	if err != nil || !auth.Allowed {
		return nil
	}
	return append([]string(nil), auth.Entitlements...)
}

func (c *Client) IsAllowed(feature string) bool {
	return HasEntitlement(c.CurrentEntitlements(), feature)
}

func cachedTokenTimeValid(value string, now time.Time) bool {
	parsed := parseCacheTimePtr(value)
	return parsed != nil && (now.Before(*parsed) || now.Equal(*parsed))
}

func parseCacheUnix(value string) int64 {
	parsed := parseCacheTimePtr(value)
	if parsed == nil {
		return 0
	}
	return parsed.Unix()
}

func parseCacheTimePtr(value string) *time.Time {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &parsed
}
