//go:build windows

package licenseguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

type CachedToken struct {
	LicenseToken      string   `json:"license_token"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	OfflineGraceUntil string   `json:"offline_grace_until,omitempty"`
	Entitlements      []string `json:"entitlements,omitempty"`
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

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
	payload, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	protected, err := dpapiProtect(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(path, protected, 0o600)
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
	plain, err := dpapiUnprotect(raw)
	if err != nil {
		return CachedToken{}, err
	}
	var cache CachedToken
	if err := json.Unmarshal(plain, &cache); err != nil {
		return CachedToken{}, err
	}
	return cache, nil
}

func dpapiProtect(plain []byte) ([]byte, error) {
	in := dataBlob{cbData: uint32(len(plain))}
	if len(plain) > 0 {
		in.pbData = &plain[0]
	}
	var out dataBlob
	ret, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return copyDataBlob(out), nil
}

func dpapiUnprotect(protected []byte) ([]byte, error) {
	in := dataBlob{cbData: uint32(len(protected))}
	if len(protected) > 0 {
		in.pbData = &protected[0]
	}
	var out dataBlob
	ret, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return copyDataBlob(out), nil
}

func copyDataBlob(blob dataBlob) []byte {
	if blob.cbData == 0 {
		return []byte{}
	}
	return append([]byte(nil), unsafe.Slice(blob.pbData, blob.cbData)...)
}
