package licensecore

import "time"

type Admin struct {
	ID           string    `json:"id"`
	Account      string    `json:"account"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"password_hash"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type App struct {
	ID          string    `json:"id"`
	AppKey      string    `json:"app_key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	OwnerTeam   string    `json:"owner_team"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AppRelease struct {
	ID                   string    `json:"id"`
	AppID                string    `json:"app_id"`
	Platform             string    `json:"platform"`
	Version              string    `json:"version"`
	BuildNumber          int       `json:"build_number"`
	Channel              string    `json:"channel"`
	Status               string    `json:"status"`
	SignerThumbprint     string    `json:"signer_thumbprint"`
	MainBinaryHash       string    `json:"main_binary_hash"`
	ResourceManifestHash string    `json:"resource_manifest_hash"`
	DownloadURL          string    `json:"download_url"`
	PackageSHA256        string    `json:"package_sha256"`
	Mandatory            bool      `json:"mandatory"`
	MinSupportedVersion  string    `json:"min_supported_version"`
	RolloutPercent       int       `json:"rollout_percent"`
	ReleaseNotes         string    `json:"release_notes"`
	CreatedAt            time.Time `json:"created_at"`
}

type SDKKey struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	PublicKey  string     `json:"public_key"`
	SecretHash string     `json:"secret_hash"`
	KeyPrefix  string     `json:"key_prefix"`
	Status     string     `json:"status"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

type SDKKeyView struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	PublicKey  string     `json:"public_key"`
	KeyPrefix  string     `json:"key_prefix"`
	Status     string     `json:"status"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

type License struct {
	ID               string    `json:"id"`
	LicenseKeyHash   string    `json:"license_key_hash"`
	LicenseKeyPrefix string    `json:"license_key_prefix"`
	AppID            string    `json:"app_id"`
	PlanName         string    `json:"plan_name"`
	OwnerType        string    `json:"owner_type"`
	OwnerRef         string    `json:"owner_ref"`
	MaxDevices       int       `json:"max_devices"`
	Entitlements     []string  `json:"entitlements"`
	ExpiresAt        time.Time `json:"expires_at"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type CapabilityPolicy struct {
	AppID               string         `json:"app_id"`
	Capability          string         `json:"capability"`
	RequiredEntitlement string         `json:"required_entitlement"`
	Mode                string         `json:"mode"`
	Message             string         `json:"message"`
	LimitsJSON          map[string]any `json:"limits_json,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

type Device struct {
	ID                    string    `json:"id"`
	DeviceFingerprintHash string    `json:"device_fingerprint_hash"`
	InstallIDHash         string    `json:"install_id_hash"`
	Platform              string    `json:"platform"`
	OSVersion             string    `json:"os_version"`
	MachineNameHash       string    `json:"machine_name_hash"`
	RiskScore             int       `json:"risk_score"`
	Status                string    `json:"status"`
	FirstSeenAt           time.Time `json:"first_seen_at"`
	LastSeenAt            time.Time `json:"last_seen_at"`
}

type Activation struct {
	ID               string     `json:"id"`
	LicenseID        string     `json:"license_id"`
	DeviceID         string     `json:"device_id"`
	AppID            string     `json:"app_id"`
	ActivationStatus string     `json:"activation_status"`
	ActivatedAt      time.Time  `json:"activated_at"`
	LastVerifiedAt   time.Time  `json:"last_verified_at"`
	DeactivatedAt    *time.Time `json:"deactivated_at,omitempty"`
}

type IntegrityReport struct {
	ID                             string    `json:"id"`
	AppID                          string    `json:"app_id"`
	DeviceID                       string    `json:"device_id"`
	ReleaseID                      string    `json:"release_id"`
	VerifySessionID                string    `json:"verify_session_id"`
	Platform                       string    `json:"platform"`
	AppVersion                     string    `json:"app_version"`
	MainBinaryHash                 string    `json:"main_binary_hash"`
	SignerThumbprint               string    `json:"signer_thumbprint"`
	BusinessManifestSHA256         string    `json:"business_manifest_sha256,omitempty"`
	BusinessManifestSignatureValid *bool     `json:"business_manifest_signature_valid,omitempty"`
	ProtectedDBSchemaHash          string    `json:"protected_db_schema_hash,omitempty"`
	ProtectedDBTablesHash          string    `json:"protected_db_tables_hash,omitempty"`
	AssetsManifestSHA256           string    `json:"assets_manifest_sha256,omitempty"`
	WorkflowManifestSHA256         string    `json:"workflow_manifest_sha256,omitempty"`
	BusinessIntegrityStatus        string    `json:"business_integrity_status,omitempty"`
	BusinessIntegrityErrors        []string  `json:"business_integrity_errors,omitempty"`
	DebuggerDetected               bool      `json:"debugger_detected"`
	SuspiciousModules              []string  `json:"suspicious_modules"`
	VMIndicators                   []string  `json:"vm_indicators"`
	CreatedAt                      time.Time `json:"created_at"`
}

type RiskEvent struct {
	ID         string         `json:"id"`
	AppID      string         `json:"app_id"`
	DeviceID   string         `json:"device_id,omitempty"`
	LicenseID  string         `json:"license_id,omitempty"`
	EventType  string         `json:"event_type"`
	Severity   string         `json:"severity"`
	Action     string         `json:"action"`
	Summary    string         `json:"summary"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
}

type AuditLog struct {
	ID         string         `json:"id"`
	AdminID    string         `json:"admin_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	IP         string         `json:"ip"`
	UserAgent  string         `json:"user_agent"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

type SystemSettings struct {
	DefaultTokenTTLMinutes    int       `json:"default_token_ttl_minutes"`
	MediumRiskTokenTTLMinutes int       `json:"medium_risk_token_ttl_minutes"`
	OfflineGraceDays          int       `json:"offline_grace_days"`
	DefaultMaxDevices         int       `json:"default_max_devices"`
	DefaultLicenseDays        int       `json:"default_license_days"`
	AuditLogRetentionDays     int       `json:"audit_log_retention_days"`
	MFARequired               bool      `json:"mfa_required"`
	SensitiveActionConfirm    bool      `json:"sensitive_action_confirm"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type Data struct {
	Admins             []Admin            `json:"admins"`
	Apps               []App              `json:"apps"`
	Releases           []AppRelease       `json:"releases"`
	SDKKeys            []SDKKey           `json:"sdk_keys"`
	Licenses           []License          `json:"licenses"`
	CapabilityPolicies []CapabilityPolicy `json:"capability_policies"`
	Devices            []Device           `json:"devices"`
	Activations        []Activation       `json:"activations"`
	IntegrityReports   []IntegrityReport  `json:"integrity_reports"`
	RiskEvents         []RiskEvent        `json:"risk_events"`
	AuditLogs          []AuditLog         `json:"audit_logs"`
	Settings           SystemSettings     `json:"settings"`
}

type Challenge struct {
	ID        string    `json:"challenge_id"`
	Nonce     string    `json:"nonce"`
	AppID     string    `json:"app_id"`
	InstallID string    `json:"install_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type DeviceInfo struct {
	InstallID       string `json:"install_id"`
	Fingerprint     string `json:"fingerprint"`
	OS              string `json:"os"`
	OSVersion       string `json:"os_version"`
	MachineNameHash string `json:"machine_name_hash"`
}

type IntegrityRequest struct {
	AppVersion                     string   `json:"app_version"`
	MainBinaryHash                 string   `json:"main_binary_hash"`
	SignerThumbprint               string   `json:"signer_thumbprint"`
	BusinessManifestSHA256         string   `json:"business_manifest_sha256"`
	BusinessManifestSignatureValid *bool    `json:"business_manifest_signature_valid,omitempty"`
	ProtectedDBSchemaHash          string   `json:"protected_db_schema_hash"`
	ProtectedDBTablesHash          string   `json:"protected_db_tables_hash"`
	AssetsManifestSHA256           string   `json:"assets_manifest_sha256"`
	WorkflowManifestSHA256         string   `json:"workflow_manifest_sha256"`
	BusinessIntegrityStatus        string   `json:"business_integrity_status"`
	BusinessIntegrityErrors        []string `json:"business_integrity_errors"`
	DebuggerDetected               bool     `json:"debugger_detected"`
	SuspiciousModules              []string `json:"suspicious_modules"`
	VMIndicators                   []string `json:"vm_indicators"`
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

type VerifyResponse struct {
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

type OnboardingStep struct {
	ID       string         `json:"id"`
	Label    string         `json:"label"`
	Status   string         `json:"status"`
	Source   string         `json:"source"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

type OnboardingResponse struct {
	AppID                 string           `json:"app_id"`
	App                   App              `json:"app"`
	HasActiveSDKKey       bool             `json:"has_active_sdk_key"`
	HasRelease            bool             `json:"has_release"`
	HasLicense            bool             `json:"has_license"`
	LatestRelease         *AppRelease      `json:"latest_release,omitempty"`
	LatestDevice          *Device          `json:"latest_device,omitempty"`
	LatestIntegrityReport *IntegrityReport `json:"latest_integrity_report,omitempty"`
	LatestRiskEvent       *RiskEvent       `json:"latest_risk_event,omitempty"`
	OfflineGraceDays      int              `json:"offline_grace_days"`
	Steps                 []OnboardingStep `json:"steps"`
	GeneratedAt           time.Time        `json:"generated_at"`
}

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
