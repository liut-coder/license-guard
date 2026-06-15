package licenseguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Options struct {
	AppID              string
	Endpoint           string
	PublicKey          string
	AppVersion         string
	BinaryHashOverride string
	SignerThumbprint   string
	IntegrityHook      func(context.Context, IntegrityReport) (IntegrityReport, error)
	HTTPClient         *http.Client
}

type Client struct {
	options Options
	http    *http.Client
}

type ChallengeRequest struct {
	AppID      string `json:"app_id"`
	Platform   string `json:"platform"`
	InstallID  string `json:"install_id"`
	AppVersion string `json:"app_version"`
}

type ChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
	ServerTime  time.Time `json:"server_time"`
}

type PublicKeyResponse struct {
	Algorithm string `json:"alg"`
	KeyType   string `json:"key_type"`
	PublicKey string `json:"public_key"`
}

type DeviceInfo struct {
	InstallID       string `json:"install_id"`
	Fingerprint     string `json:"fingerprint"`
	OS              string `json:"os"`
	OSVersion       string `json:"os_version"`
	MachineNameHash string `json:"machine_name_hash"`
}

type IntegrityReport struct {
	AppVersion                     string   `json:"app_version"`
	MainBinaryHash                 string   `json:"main_binary_hash"`
	SignerThumbprint               string   `json:"signer_thumbprint"`
	BusinessManifestSHA256         string   `json:"business_manifest_sha256,omitempty"`
	BusinessManifestSignatureValid *bool    `json:"business_manifest_signature_valid,omitempty"`
	ProtectedDBSchemaHash          string   `json:"protected_db_schema_hash,omitempty"`
	ProtectedDBTablesHash          string   `json:"protected_db_tables_hash,omitempty"`
	AssetsManifestSHA256           string   `json:"assets_manifest_sha256,omitempty"`
	WorkflowManifestSHA256         string   `json:"workflow_manifest_sha256,omitempty"`
	BusinessIntegrityStatus        string   `json:"business_integrity_status,omitempty"`
	BusinessIntegrityErrors        []string `json:"business_integrity_errors,omitempty"`
	DebuggerDetected               bool     `json:"debugger_detected"`
	SuspiciousModules              []string `json:"suspicious_modules"`
	VMIndicators                   []string `json:"vm_indicators"`
}

type ActivateRequest struct {
	AppID       string          `json:"app_id"`
	Platform    string          `json:"platform"`
	LicenseKey  string          `json:"license_key"`
	ChallengeID string          `json:"challenge_id"`
	Nonce       string          `json:"nonce"`
	Device      DeviceInfo      `json:"device"`
	Integrity   IntegrityReport `json:"integrity"`
}

type VerifyRequest struct {
	AppID        string          `json:"app_id"`
	Platform     string          `json:"platform"`
	LicenseKey   string          `json:"license_key,omitempty"`
	LicenseToken string          `json:"license_token,omitempty"`
	ChallengeID  string          `json:"challenge_id"`
	Nonce        string          `json:"nonce"`
	Device       DeviceInfo      `json:"device"`
	Integrity    IntegrityReport `json:"integrity"`
}

type HeartbeatRequest struct {
	AppID        string           `json:"app_id"`
	LicenseToken string           `json:"license_token"`
	InstallID    string           `json:"install_id"`
	AppVersion   string           `json:"app_version"`
	Integrity    *IntegrityReport `json:"integrity,omitempty"`
	Runtime      map[string]any   `json:"runtime,omitempty"`
}

type DeactivateRequest struct {
	AppID        string `json:"app_id"`
	LicenseToken string `json:"license_token"`
	InstallID    string `json:"install_id"`
}

type RiskResult struct {
	Level   string   `json:"level"`
	Score   int      `json:"score"`
	Actions []string `json:"actions"`
}

type UpdateInfo struct {
	Available     bool   `json:"available"`
	Required      bool   `json:"required"`
	LatestVersion string `json:"latest_version"`
	DownloadURL   string `json:"download_url,omitempty"`
	PackageSHA256 string `json:"package_sha256,omitempty"`
	ReleaseNotes  string `json:"release_notes,omitempty"`
}

type CapabilityDecision struct {
	Capability          string         `json:"capability"`
	RequiredEntitlement string         `json:"required_entitlement"`
	ConfiguredMode      string         `json:"configured_mode"`
	EffectiveMode       string         `json:"effective_mode"`
	Allowed             bool           `json:"allowed"`
	Reason              string         `json:"reason,omitempty"`
	Message             string         `json:"message,omitempty"`
	LimitsJSON          map[string]any `json:"limits_json,omitempty"`
}

type CapabilityPolicyBundle struct {
	AppID        string               `json:"app_id"`
	LicenseID    string               `json:"license_id"`
	DeviceID     string               `json:"device_id"`
	Entitlements []string             `json:"entitlements"`
	Decisions    []CapabilityDecision `json:"decisions"`
	IssuedAt     int64                `json:"issued_at"`
	ExpiresAt    int64                `json:"expires_at"`
}

type SignedCapabilityPolicyBundle struct {
	Alg       string                 `json:"alg"`
	KeyType   string                 `json:"key_type"`
	Bundle    CapabilityPolicyBundle `json:"bundle"`
	Signature string                 `json:"signature"`
}

func (b *SignedCapabilityPolicyBundle) Decision(capability string) (CapabilityDecision, bool) {
	if b == nil {
		return CapabilityDecision{}, false
	}
	for _, decision := range b.Bundle.Decisions {
		if decision.Capability == capability {
			return decision, true
		}
	}
	return CapabilityDecision{}, false
}

type VerifyResult struct {
	Allowed           bool                          `json:"allowed"`
	Code              string                        `json:"code,omitempty"`
	Message           string                        `json:"message,omitempty"`
	LicenseToken      string                        `json:"license_token,omitempty"`
	ExpiresAt         *time.Time                    `json:"expires_at,omitempty"`
	OfflineGraceUntil *time.Time                    `json:"offline_grace_until,omitempty"`
	Entitlements      []string                      `json:"entitlements,omitempty"`
	CapabilityPolicy  *SignedCapabilityPolicyBundle `json:"capability_policy,omitempty"`
	DeviceStatus      string                        `json:"device_status,omitempty"`
	Risk              RiskResult                    `json:"risk"`
	Update            *UpdateInfo                   `json:"update,omitempty"`
}

func (r *VerifyResult) CapabilityDecision(capability string) (CapabilityDecision, bool) {
	if r == nil || r.CapabilityPolicy == nil {
		return CapabilityDecision{}, false
	}
	return r.CapabilityPolicy.Decision(capability)
}

type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("license guard api returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewClient(options Options) (*Client, error) {
	if options.AppID == "" {
		return nil, fmt.Errorf("AppID is required")
	}
	if options.Endpoint == "" {
		return nil, fmt.Errorf("Endpoint is required")
	}
	if options.AppVersion == "" {
		options.AppVersion = "0.0.0"
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 12 * time.Second}
	}
	options.Endpoint = strings.TrimRight(options.Endpoint, "/")
	return &Client{options: options, http: httpClient}, nil
}

func (c *Client) Challenge(ctx context.Context, installID string) (*ChallengeResponse, error) {
	req := ChallengeRequest{
		AppID:      c.options.AppID,
		Platform:   "windows",
		InstallID:  installID,
		AppVersion: c.options.AppVersion,
	}
	var resp ChallengeResponse
	if err := c.postJSON(ctx, "/challenge", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) FetchPublicKey(ctx context.Context) (*PublicKeyResponse, error) {
	var resp PublicKeyResponse
	if err := c.getJSON(ctx, "/public-key", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Activate(ctx context.Context, licenseKey string) (*VerifyResult, error) {
	installID, err := LoadOrCreateInstallID(c.options.AppID)
	if err != nil {
		return nil, err
	}
	challenge, err := c.Challenge(ctx, installID)
	if err != nil {
		return nil, err
	}
	device, err := CollectDeviceInfo(installID)
	if err != nil {
		return nil, err
	}
	integrity, err := c.collectIntegrity(ctx)
	if err != nil {
		return nil, err
	}

	var result VerifyResult
	if err := c.postJSON(ctx, "/activate", ActivateRequest{
		AppID:       c.options.AppID,
		Platform:    "windows",
		LicenseKey:  licenseKey,
		ChallengeID: challenge.ChallengeID,
		Nonce:       challenge.Nonce,
		Device:      device,
		Integrity:   integrity,
	}, &result); err != nil {
		return nil, err
	}
	if result.Allowed && result.LicenseToken != "" {
		_ = SaveToken(c.options.AppID, result)
	}
	return &result, nil
}

func (c *Client) Verify(ctx context.Context) (*VerifyResult, error) {
	cached, err := LoadToken(c.options.AppID)
	if err != nil {
		return nil, err
	}
	return c.VerifyWithToken(ctx, cached.LicenseToken)
}

func (c *Client) VerifyWithToken(ctx context.Context, token string) (*VerifyResult, error) {
	installID, err := LoadOrCreateInstallID(c.options.AppID)
	if err != nil {
		return nil, err
	}
	challenge, err := c.Challenge(ctx, installID)
	if err != nil {
		return nil, err
	}
	device, err := CollectDeviceInfo(installID)
	if err != nil {
		return nil, err
	}
	integrity, err := c.collectIntegrity(ctx)
	if err != nil {
		return nil, err
	}

	var result VerifyResult
	if err := c.postJSON(ctx, "/verify", VerifyRequest{
		AppID:        c.options.AppID,
		Platform:     "windows",
		LicenseToken: token,
		ChallengeID:  challenge.ChallengeID,
		Nonce:        challenge.Nonce,
		Device:       device,
		Integrity:    integrity,
	}, &result); err != nil {
		return nil, err
	}
	if result.Allowed && result.LicenseToken != "" {
		_ = SaveToken(c.options.AppID, result)
	}
	return &result, nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	cached, err := LoadToken(c.options.AppID)
	if err != nil {
		return err
	}
	installID, err := LoadOrCreateInstallID(c.options.AppID)
	if err != nil {
		return err
	}
	request := HeartbeatRequest{
		AppID:        c.options.AppID,
		LicenseToken: cached.LicenseToken,
		InstallID:    installID,
		AppVersion:   c.options.AppVersion,
		Runtime: map[string]any{
			"heartbeat_at": time.Now().UTC(),
		},
	}
	if c.options.IntegrityHook != nil {
		integrity, err := c.collectIntegrity(ctx)
		if err != nil {
			return err
		}
		request.Integrity = &integrity
	}
	var resp map[string]any
	return c.postJSON(ctx, "/heartbeat", request, &resp)
}

func (c *Client) Deactivate(ctx context.Context) error {
	cached, err := LoadToken(c.options.AppID)
	if err != nil {
		return err
	}
	installID, err := LoadOrCreateInstallID(c.options.AppID)
	if err != nil {
		return err
	}
	var resp map[string]any
	if err := c.postJSON(ctx, "/deactivate", DeactivateRequest{
		AppID:        c.options.AppID,
		LicenseToken: cached.LicenseToken,
		InstallID:    installID,
	}, &resp); err != nil {
		return err
	}
	return DeleteToken(c.options.AppID)
}

func HasEntitlement(entitlements []string, required string) bool {
	for _, entitlement := range entitlements {
		if entitlement == required {
			return true
		}
	}
	return false
}

func (c *Client) collectIntegrity(ctx context.Context) (IntegrityReport, error) {
	integrity, err := CollectIntegrity(c.options.AppVersion, c.options.BinaryHashOverride, c.options.SignerThumbprint)
	if err != nil {
		return IntegrityReport{}, err
	}
	if c.options.IntegrityHook == nil {
		return integrity, nil
	}
	return c.options.IntegrityHook(ctx, integrity)
}

func (c *Client) postJSON(ctx context.Context, path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.options.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LG-App-Id", c.options.AppID)
	req.Header.Set("X-LG-SDK-Version", "go-windows-0.1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		return &APIError{StatusCode: resp.StatusCode, Code: payload.Error.Code, Message: payload.Error.Message}
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.options.Endpoint+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-LG-App-Id", c.options.AppID)
	req.Header.Set("X-LG-SDK-Version", "go-windows-0.1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		return &APIError{StatusCode: resp.StatusCode, Code: payload.Error.Code, Message: payload.Error.Message}
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
