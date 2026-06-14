package licensecore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrTokenExpired = errors.New("license token expired")

type keyFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func LoadOrCreateSigningKey(dataDir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, nil, err
	}

	path := filepath.Join(dataDir, "signing-key.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		var saved keyFile
		if err := json.Unmarshal(raw, &saved); err != nil {
			return nil, nil, err
		}
		pub, err := base64.StdEncoding.DecodeString(saved.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		priv, err := base64.StdEncoding.DecodeString(saved.PrivateKey)
		if err != nil {
			return nil, nil, err
		}
		return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	payload, err := json.MarshalIndent(keyFile{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

func SignLicenseToken(privateKey ed25519.PrivateKey, claims LicenseTokenClaims) (string, error) {
	header := map[string]string{"alg": "EdDSA", "typ": "LG-LICENSE"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerPart + "." + payloadPart
	signature := ed25519.Sign(privateKey, []byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func VerifyLicenseToken(publicKey ed25519.PublicKey, token string, allowExpired bool) (*LicenseTokenClaims, error) {
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
