package licenseguard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func LoadOrCreateInstallID(appID string) (string, error) {
	path, err := installIDPath(appID)
	if err != nil {
		return "", err
	}
	if raw, err := os.ReadFile(path); err == nil {
		value := strings.TrimSpace(string(raw))
		if value != "" {
			return value, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	installID := newUUIDLike()
	if err := os.WriteFile(path, []byte(installID+"\n"), 0o600); err != nil {
		return "", err
	}
	return installID, nil
}

func CollectDeviceInfo(installID string) (DeviceInfo, error) {
	hostname, _ := os.Hostname()
	return DeviceInfo{
		InstallID:       installID,
		Fingerprint:     hashText(strings.Join([]string{installID, hostname, runtime.GOOS, runtime.GOARCH}, "|")),
		OS:              runtime.GOOS,
		OSVersion:       runtime.GOOS + "/" + runtime.GOARCH,
		MachineNameHash: hashText(hostname),
	}, nil
}

func CollectIntegrity(appVersion string, binaryHashOverride string, signerThumbprint string) (IntegrityReport, error) {
	hash := binaryHashOverride
	if hash == "" {
		var err error
		hash, err = CurrentExecutableHash()
		if err != nil {
			return IntegrityReport{}, err
		}
	}
	return IntegrityReport{
		AppVersion:        appVersion,
		MainBinaryHash:    hash,
		SignerThumbprint:  signerThumbprint,
		DebuggerDetected:  IsDebuggerPresent(),
		SuspiciousModules: nil,
		VMIndicators:      nil,
	}, nil
}

func CurrentExecutableHash() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return FileSHA256(exe)
}

func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func IsDebuggerPresent() bool {
	return false
}

func installIDPath(appID string) (string, error) {
	if override := os.Getenv("LG_INSTALL_ID_PATH"); override != "" {
		return override, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "LicenseGuard", sanitizePathPart(appID), "install_id"), nil
}

func cachePath(appID string) (string, error) {
	if override := os.Getenv("LG_TOKEN_CACHE_PATH"); override != "" {
		return override, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "LicenseGuard", sanitizePathPart(appID), "license_token.json"), nil
}

func DeleteToken(appID string) error {
	path, err := cachePath(appID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func sanitizePathPart(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "\\", "_")
	value = strings.ReplaceAll(value, ":", "_")
	if value == "" {
		return "default"
	}
	return value
}

func hashText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newUUIDLike() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
