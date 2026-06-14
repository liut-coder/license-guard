//go:build !windows

package licenseguard

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type CachedToken struct {
	LicenseToken      string   `json:"license_token"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	OfflineGraceUntil string   `json:"offline_grace_until,omitempty"`
	Entitlements      []string `json:"entitlements,omitempty"`
}

func SaveToken(appID string, result VerifyResult) error {
	path, err := cachePath(appID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	cache := CachedToken{LicenseToken: result.LicenseToken, Entitlements: result.Entitlements}
	if result.ExpiresAt != nil {
		cache.ExpiresAt = result.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}
	if result.OfflineGraceUntil != nil {
		cache.OfflineGraceUntil = result.OfflineGraceUntil.Format("2006-01-02T15:04:05Z07:00")
	}
	payload, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func LoadToken(appID string) (CachedToken, error) {
	path, err := cachePath(appID)
	if err != nil {
		return CachedToken{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return CachedToken{}, err
	}
	var cache CachedToken
	if err := json.Unmarshal(raw, &cache); err != nil {
		return CachedToken{}, err
	}
	return cache, nil
}
