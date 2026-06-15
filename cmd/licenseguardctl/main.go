package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) >= 2 && args[0] == "release" && args[1] == "publish" {
		return runReleasePublishWithIO(ctx, args[2:], os.Stdout)
	}
	if len(args) >= 2 && args[0] == "visionflow" && args[1] == "bootstrap" {
		return runVisionFlowBootstrapWithIO(ctx, args[2:], os.Stdout)
	}
	return fmt.Errorf("usage: licenseguardctl release publish [flags]\n       licenseguardctl visionflow bootstrap [flags]")
}

func runReleasePublish(ctx context.Context, args []string) error {
	return runReleasePublishWithIO(ctx, args, os.Stdout)
}

func runReleasePublishWithIO(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("release publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	server := fs.String("server", envOrDefault("LICENSE_GUARD_ADMIN_URL", ""), "License Guard server URL, for example https://license.example")
	adminToken := fs.String("admin-token", os.Getenv("LICENSE_GUARD_ADMIN_TOKEN"), "admin bearer token")
	adminAccount := fs.String("admin-account", os.Getenv("LICENSE_GUARD_ADMIN_ACCOUNT"), "admin account used when admin-token is empty")
	adminPassword := fs.String("admin-password", os.Getenv("LICENSE_GUARD_ADMIN_PASSWORD"), "admin password used when admin-token is empty")
	appID := fs.String("app-id", "", "app id")
	platform := fs.String("platform", "windows", "release platform")
	version := fs.String("version", "", "app version")
	buildNumber := fs.Int("build-number", 0, "monotonic build number")
	channel := fs.String("channel", "production", "release channel")
	status := fs.String("status", "active", "release status")
	mainBinary := fs.String("main-binary", "", "path to the signed main binary")
	mainBinaryHash := fs.String("main-binary-hash", "", "signed main binary sha256 override")
	signerThumbprint := fs.String("signer-thumbprint", "", "code signing certificate thumbprint")
	packageFile := fs.String("package", "", "path to the installer or distribution package")
	packageSHA256 := fs.String("package-sha256", "", "package sha256 override")
	resourceManifestHash := fs.String("resource-manifest-hash", "", "optional resource manifest hash")
	businessManifest := fs.String("business-manifest", "", "path to signed VisionFlow business manifest; computes business_manifest_sha256 and legacy resource_manifest_hash when resource-manifest-hash is empty")
	businessManifestSHA256 := fs.String("business-manifest-sha256", "", "VisionFlow business manifest sha256 override")
	protectedDBSchemaHash := fs.String("protected-db-schema-hash", "", "protected DB schema hash")
	protectedDBTablesHash := fs.String("protected-db-tables-hash", "", "protected DB tables hash")
	assetsManifestSHA256 := fs.String("assets-manifest-sha256", "", "assets manifest sha256")
	workflowManifestSHA256 := fs.String("workflow-manifest-sha256", "", "workflow manifest sha256")
	downloadURL := fs.String("download-url", "", "release download URL")
	releaseNotes := fs.String("release-notes", "", "release notes text")
	releaseNotesFile := fs.String("release-notes-file", "", "release notes file")
	mandatory := fs.Bool("mandatory", false, "force this update")
	minSupportedVersion := fs.String("min-supported-version", "", "minimum supported version")
	rolloutPercent := fs.Int("rollout-percent", 100, "rollout percent 0-100")
	dryRun := fs.Bool("dry-run", false, "print payload without publishing")

	if err := fs.Parse(args); err != nil {
		return err
	}

	payload, err := buildReleasePayload(releaseInput{
		appID:                  *appID,
		platform:               *platform,
		version:                *version,
		buildNumber:            *buildNumber,
		channel:                *channel,
		status:                 *status,
		mainBinary:             *mainBinary,
		mainBinaryHash:         *mainBinaryHash,
		signerThumbprint:       *signerThumbprint,
		packageFile:            *packageFile,
		packageSHA256:          *packageSHA256,
		resourceManifestHash:   *resourceManifestHash,
		businessManifest:       *businessManifest,
		businessManifestSHA256: *businessManifestSHA256,
		protectedDBSchemaHash:  *protectedDBSchemaHash,
		protectedDBTablesHash:  *protectedDBTablesHash,
		assetsManifestSHA256:   *assetsManifestSHA256,
		workflowManifestSHA256: *workflowManifestSHA256,
		downloadURL:            *downloadURL,
		releaseNotes:           *releaseNotes,
		releaseNotesFile:       *releaseNotesFile,
		mandatory:              *mandatory,
		minSupportedVersion:    *minSupportedVersion,
		rolloutPercent:         *rolloutPercent,
	})
	if err != nil {
		return err
	}

	if *dryRun {
		return writeJSON(out, payload)
	}

	baseURL := normalizeServerURL(*server)
	if baseURL == "" {
		return errors.New("server URL is required")
	}
	token := strings.TrimSpace(*adminToken)
	if token == "" {
		var err error
		token, err = loginAdmin(ctx, baseURL, strings.TrimSpace(*adminAccount), strings.TrimSpace(*adminPassword))
		if err != nil {
			return err
		}
	}

	response, err := postAdminJSON(ctx, baseURL, token, "/admin/apps/"+url.PathEscape(payload.AppID)+"/releases", payload)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "published release %s %s build %d\n", payload.AppID, payload.Version, payload.BuildNumber)
	return writeJSON(out, response)
}

func runVisionFlowBootstrapWithIO(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("visionflow bootstrap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	server := fs.String("server", envOrDefault("LICENSE_GUARD_ADMIN_URL", ""), "License Guard server URL, for example http://127.0.0.1:8090")
	endpoint := fs.String("endpoint", "", "client endpoint URL; defaults to <server>/v1")
	adminToken := fs.String("admin-token", os.Getenv("LICENSE_GUARD_ADMIN_TOKEN"), "admin bearer token")
	adminAccount := fs.String("admin-account", os.Getenv("LICENSE_GUARD_ADMIN_ACCOUNT"), "admin account used when admin-token is empty")
	adminPassword := fs.String("admin-password", os.Getenv("LICENSE_GUARD_ADMIN_PASSWORD"), "admin password used when admin-token is empty")
	appID := fs.String("app-id", "app_visionflow_windows_prod", "VisionFlow app id")
	appName := fs.String("app-name", "VisionFlow Windows", "VisionFlow app display name")
	ownerTeam := fs.String("owner-team", "VisionFlow", "app owner team")
	platform := fs.String("platform", "windows", "release platform")
	version := fs.String("version", "0.1.0", "VisionFlow app version")
	buildNumber := fs.Int("build-number", 1, "VisionFlow build number")
	binaryHash := fs.String("binary-hash", "dev-visionflow-main-binary-sha256", "VisionFlow main binary sha256")
	signerThumbprint := fs.String("signer-thumbprint", "dev-visionflow-signer-thumbprint", "VisionFlow signer thumbprint")
	packageSHA256 := fs.String("package-sha256", "dev-visionflow-package-sha256", "VisionFlow package sha256")
	downloadURL := fs.String("download-url", "http://127.0.0.1:8090/downloads/VisionFlowSetup.exe", "VisionFlow download URL")
	releaseNotes := fs.String("release-notes", "VisionFlow local development bootstrap release", "release notes")
	licenseOwner := fs.String("license-owner", "visionflow-local-dev", "license owner reference")
	licenseDays := fs.Int("license-days", 30, "license validity days when expires-at is empty")
	expiresAt := fs.String("expires-at", "", "license expiration date in YYYY-MM-DD")
	maxDevices := fs.Int("max-devices", 1, "license max devices")
	entitlements := fs.String("entitlements", strings.Join(defaultVisionFlowEntitlements(), ","), "comma-separated entitlements")
	writeEnvPath := fs.String("write-env", "", "optional path to write env output")
	format := fs.String("format", "env", "output format: env or json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	input := visionFlowBootstrapInput{
		server:           *server,
		endpoint:         *endpoint,
		adminToken:       *adminToken,
		adminAccount:     *adminAccount,
		adminPassword:    *adminPassword,
		appID:            *appID,
		appName:          *appName,
		ownerTeam:        *ownerTeam,
		platform:         *platform,
		version:          *version,
		buildNumber:      *buildNumber,
		binaryHash:       *binaryHash,
		signerThumbprint: *signerThumbprint,
		packageSHA256:    *packageSHA256,
		downloadURL:      *downloadURL,
		releaseNotes:     *releaseNotes,
		licenseOwner:     *licenseOwner,
		licenseDays:      *licenseDays,
		expiresAt:        *expiresAt,
		maxDevices:       *maxDevices,
		entitlements:     parseCSV(*entitlements),
		writeEnvPath:     *writeEnvPath,
		format:           *format,
	}
	result, err := bootstrapVisionFlow(ctx, input)
	if err != nil {
		return err
	}
	rendered, err := renderVisionFlowBootstrapResult(result, input.format)
	if err != nil {
		return err
	}
	if input.writeEnvPath != "" {
		if err := os.MkdirAll(filepath.Dir(filepath.Clean(input.writeEnvPath)), 0o755); err != nil && filepath.Dir(filepath.Clean(input.writeEnvPath)) != "." {
			return err
		}
		if err := os.WriteFile(filepath.Clean(input.writeEnvPath), []byte(rendered), 0o600); err != nil {
			return err
		}
	}
	_, err = io.WriteString(out, rendered)
	return err
}

type releaseInput struct {
	appID                  string
	platform               string
	version                string
	buildNumber            int
	channel                string
	status                 string
	mainBinary             string
	mainBinaryHash         string
	signerThumbprint       string
	packageFile            string
	packageSHA256          string
	resourceManifestHash   string
	businessManifest       string
	businessManifestSHA256 string
	protectedDBSchemaHash  string
	protectedDBTablesHash  string
	assetsManifestSHA256   string
	workflowManifestSHA256 string
	downloadURL            string
	releaseNotes           string
	releaseNotesFile       string
	mandatory              bool
	minSupportedVersion    string
	rolloutPercent         int
}

type releasePayload struct {
	AppID                  string `json:"app_id"`
	Platform               string `json:"platform"`
	Version                string `json:"version"`
	BuildNumber            int    `json:"build_number"`
	Channel                string `json:"channel"`
	Status                 string `json:"status"`
	SignerThumbprint       string `json:"signer_thumbprint"`
	MainBinaryHash         string `json:"main_binary_hash"`
	ResourceManifestHash   string `json:"resource_manifest_hash,omitempty"`
	BusinessManifestSHA256 string `json:"business_manifest_sha256,omitempty"`
	ProtectedDBSchemaHash  string `json:"protected_db_schema_hash,omitempty"`
	ProtectedDBTablesHash  string `json:"protected_db_tables_hash,omitempty"`
	AssetsManifestSHA256   string `json:"assets_manifest_sha256,omitempty"`
	WorkflowManifestSHA256 string `json:"workflow_manifest_sha256,omitempty"`
	DownloadURL            string `json:"download_url"`
	PackageSHA256          string `json:"package_sha256"`
	Mandatory              bool   `json:"mandatory"`
	MinSupportedVersion    string `json:"min_supported_version,omitempty"`
	RolloutPercent         int    `json:"rollout_percent"`
	ReleaseNotes           string `json:"release_notes"`
}

type signedVisionFlowBusinessManifest struct {
	Alg       string                     `json:"alg"`
	KeyType   string                     `json:"keyType"`
	Manifest  visionFlowBusinessManifest `json:"manifest"`
	Signature string                     `json:"signature"`
}

type visionFlowBusinessManifest struct {
	SchemaVersion string                      `json:"schemaVersion"`
	AppID         string                      `json:"appId,omitempty"`
	Release       string                      `json:"release,omitempty"`
	RuntimeTables []visionFlowTableDigest     `json:"runtimeTables,omitempty"`
	FileSets      []visionFlowBusinessFileSet `json:"fileSets,omitempty"`
}

type visionFlowTableDigest struct {
	Name     string `json:"name"`
	RowCount int    `json:"rowCount"`
	SHA256   string `json:"sha256"`
}

type visionFlowBusinessFileSet struct {
	Name      string                 `json:"name"`
	Root      string                 `json:"root,omitempty"`
	FileCount int                    `json:"fileCount"`
	SHA256    string                 `json:"sha256"`
	Files     []visionFlowFileDigest `json:"files,omitempty"`
}

type visionFlowFileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type visionFlowBootstrapInput struct {
	server           string
	endpoint         string
	adminToken       string
	adminAccount     string
	adminPassword    string
	appID            string
	appName          string
	ownerTeam        string
	platform         string
	version          string
	buildNumber      int
	binaryHash       string
	signerThumbprint string
	packageSHA256    string
	downloadURL      string
	releaseNotes     string
	licenseOwner     string
	licenseDays      int
	expiresAt        string
	maxDevices       int
	entitlements     []string
	writeEnvPath     string
	format           string
}

type visionFlowBootstrapResult struct {
	AppID              string            `json:"app_id"`
	Endpoint           string            `json:"endpoint"`
	PublicKey          string            `json:"public_key"`
	Version            string            `json:"version"`
	BinaryHash         string            `json:"binary_hash"`
	SignerThumbprint   string            `json:"signer_thumbprint"`
	LicenseKey         string            `json:"license_key"`
	Entitlements       []string          `json:"entitlements"`
	AppCreated         bool              `json:"app_created"`
	ReleaseID          string            `json:"release_id,omitempty"`
	ReleaseCreated     bool              `json:"release_created"`
	ReleasePatched     bool              `json:"release_patched"`
	CapabilityPolicies int               `json:"capability_policies"`
	LicenseID          string            `json:"license_id,omitempty"`
	ExpiresAt          string            `json:"expires_at"`
	VisionFlowEnv      map[string]string `json:"visionflow_env"`
}

type adminApp struct {
	ID          string `json:"id"`
	AppKey      string `json:"app_key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerTeam   string `json:"owner_team"`
	Status      string `json:"status"`
}

type adminRelease struct {
	ID                     string `json:"id"`
	AppID                  string `json:"app_id"`
	Platform               string `json:"platform"`
	Version                string `json:"version"`
	BuildNumber            int    `json:"build_number"`
	Channel                string `json:"channel"`
	Status                 string `json:"status"`
	SignerThumbprint       string `json:"signer_thumbprint"`
	MainBinaryHash         string `json:"main_binary_hash"`
	ResourceManifestHash   string `json:"resource_manifest_hash"`
	BusinessManifestSHA256 string `json:"business_manifest_sha256"`
	ProtectedDBSchemaHash  string `json:"protected_db_schema_hash"`
	ProtectedDBTablesHash  string `json:"protected_db_tables_hash"`
	AssetsManifestSHA256   string `json:"assets_manifest_sha256"`
	WorkflowManifestSHA256 string `json:"workflow_manifest_sha256"`
	DownloadURL            string `json:"download_url"`
	PackageSHA256          string `json:"package_sha256"`
	Mandatory              bool   `json:"mandatory"`
	MinSupportedVersion    string `json:"min_supported_version"`
	RolloutPercent         int    `json:"rollout_percent"`
	ReleaseNotes           string `json:"release_notes"`
}

type adminLicense struct {
	ID           string   `json:"id"`
	AppID        string   `json:"app_id"`
	PlanName     string   `json:"plan_name"`
	OwnerRef     string   `json:"owner_ref"`
	MaxDevices   int      `json:"max_devices"`
	Entitlements []string `json:"entitlements"`
	Status       string   `json:"status"`
}

type adminAppDetail struct {
	App      adminApp       `json:"app"`
	Releases []adminRelease `json:"releases"`
	Licenses []adminLicense `json:"licenses"`
}

type publicKeyResponse struct {
	Algorithm string `json:"alg"`
	KeyType   string `json:"key_type"`
	PublicKey string `json:"public_key"`
}

func bootstrapVisionFlow(ctx context.Context, input visionFlowBootstrapInput) (visionFlowBootstrapResult, error) {
	baseURL := normalizeServerURL(input.server)
	if baseURL == "" {
		return visionFlowBootstrapResult{}, errors.New("server URL is required")
	}
	input.endpoint = normalizeClientEndpoint(input.endpoint, baseURL)
	input.appID = strings.TrimSpace(input.appID)
	input.appName = fallback(strings.TrimSpace(input.appName), "VisionFlow Windows")
	input.ownerTeam = fallback(strings.TrimSpace(input.ownerTeam), "VisionFlow")
	input.platform = fallback(strings.TrimSpace(input.platform), "windows")
	input.version = fallback(strings.TrimSpace(input.version), "0.1.0")
	input.binaryHash = fallback(strings.TrimSpace(input.binaryHash), "dev-visionflow-main-binary-sha256")
	input.signerThumbprint = fallback(strings.TrimSpace(input.signerThumbprint), "dev-visionflow-signer-thumbprint")
	input.packageSHA256 = fallback(strings.TrimSpace(input.packageSHA256), "dev-visionflow-package-sha256")
	input.downloadURL = fallback(strings.TrimSpace(input.downloadURL), baseURL+"/downloads/VisionFlowSetup.exe")
	input.releaseNotes = fallback(strings.TrimSpace(input.releaseNotes), "VisionFlow local development bootstrap release")
	input.licenseOwner = fallback(strings.TrimSpace(input.licenseOwner), "visionflow-local-dev")
	input.entitlements = normalizeStringList(input.entitlements)
	if input.appID == "" {
		return visionFlowBootstrapResult{}, errors.New("app-id is required")
	}
	if input.buildNumber <= 0 {
		return visionFlowBootstrapResult{}, errors.New("build-number must be greater than zero")
	}
	if input.maxDevices <= 0 {
		return visionFlowBootstrapResult{}, errors.New("max-devices must be greater than zero")
	}
	if len(input.entitlements) == 0 {
		input.entitlements = defaultVisionFlowEntitlements()
	}

	token := strings.TrimSpace(input.adminToken)
	if token == "" {
		var err error
		token, err = loginAdmin(ctx, baseURL, strings.TrimSpace(input.adminAccount), strings.TrimSpace(input.adminPassword))
		if err != nil {
			return visionFlowBootstrapResult{}, err
		}
	}

	appCreated, err := ensureVisionFlowApp(ctx, baseURL, token, input)
	if err != nil {
		return visionFlowBootstrapResult{}, err
	}
	capabilityPolicies, err := ensureVisionFlowCapabilityDefaults(ctx, baseURL, token, input.appID)
	if err != nil {
		return visionFlowBootstrapResult{}, err
	}
	detail, err := fetchAppDetail(ctx, baseURL, token, input.appID)
	if err != nil {
		return visionFlowBootstrapResult{}, err
	}
	release, releaseCreated, releasePatched, err := ensureVisionFlowRelease(ctx, baseURL, token, input, detail.Releases)
	if err != nil {
		return visionFlowBootstrapResult{}, err
	}
	publicKey, err := fetchClientPublicKey(ctx, input.endpoint)
	if err != nil {
		return visionFlowBootstrapResult{}, err
	}
	licenseKey, licenseID, expiresAt, err := createVisionFlowLicense(ctx, baseURL, token, input)
	if err != nil {
		return visionFlowBootstrapResult{}, err
	}

	env := map[string]string{
		"LICENSE_GUARD_ENDPOINT":          input.endpoint,
		"LICENSE_GUARD_APP_ID":            input.appID,
		"LICENSE_GUARD_PUBLIC_KEY":        publicKey,
		"LICENSE_GUARD_APP_VERSION":       input.version,
		"LICENSE_GUARD_BINARY_HASH":       input.binaryHash,
		"LICENSE_GUARD_SIGNER_THUMBPRINT": input.signerThumbprint,
		"VISIONFLOW_LICENSE_KEY":          licenseKey,
	}
	return visionFlowBootstrapResult{
		AppID:              input.appID,
		Endpoint:           input.endpoint,
		PublicKey:          publicKey,
		Version:            input.version,
		BinaryHash:         input.binaryHash,
		SignerThumbprint:   input.signerThumbprint,
		LicenseKey:         licenseKey,
		Entitlements:       input.entitlements,
		AppCreated:         appCreated,
		ReleaseID:          release.ID,
		ReleaseCreated:     releaseCreated,
		ReleasePatched:     releasePatched,
		CapabilityPolicies: capabilityPolicies,
		LicenseID:          licenseID,
		ExpiresAt:          expiresAt,
		VisionFlowEnv:      env,
	}, nil
}

func buildReleasePayload(input releaseInput) (releasePayload, error) {
	appID := strings.TrimSpace(input.appID)
	version := strings.TrimSpace(input.version)
	if appID == "" {
		return releasePayload{}, errors.New("app-id is required")
	}
	if version == "" {
		return releasePayload{}, errors.New("version is required")
	}
	if input.buildNumber <= 0 {
		return releasePayload{}, errors.New("build-number must be greater than zero")
	}

	mainHash, err := hashOrOverride(input.mainBinary, input.mainBinaryHash, "main-binary")
	if err != nil {
		return releasePayload{}, err
	}
	packageHash, err := hashOrOverride(input.packageFile, input.packageSHA256, "package")
	if err != nil {
		return releasePayload{}, err
	}
	resourceManifestHash := strings.TrimSpace(input.resourceManifestHash)
	businessManifestHash := strings.ToLower(strings.TrimSpace(input.businessManifestSHA256))
	if businessManifestHash == "" && strings.TrimSpace(input.businessManifest) != "" {
		businessManifestHash, err = visionFlowBusinessManifestSHA256(input.businessManifest)
		if err != nil {
			return releasePayload{}, err
		}
	}
	if resourceManifestHash == "" && businessManifestHash != "" {
		resourceManifestHash = businessManifestHash
	}
	notes, err := releaseNotesValue(input.releaseNotes, input.releaseNotesFile)
	if err != nil {
		return releasePayload{}, err
	}
	if strings.TrimSpace(input.signerThumbprint) == "" {
		return releasePayload{}, errors.New("signer-thumbprint is required")
	}
	if strings.TrimSpace(input.downloadURL) == "" {
		return releasePayload{}, errors.New("download-url is required")
	}
	rollout := input.rolloutPercent
	if rollout < 0 {
		rollout = 0
	}
	if rollout > 100 {
		rollout = 100
	}

	return releasePayload{
		AppID:                  appID,
		Platform:               fallback(strings.TrimSpace(input.platform), "windows"),
		Version:                version,
		BuildNumber:            input.buildNumber,
		Channel:                fallback(strings.TrimSpace(input.channel), "production"),
		Status:                 fallback(strings.TrimSpace(input.status), "active"),
		SignerThumbprint:       strings.TrimSpace(input.signerThumbprint),
		MainBinaryHash:         mainHash,
		ResourceManifestHash:   resourceManifestHash,
		BusinessManifestSHA256: businessManifestHash,
		ProtectedDBSchemaHash:  strings.ToLower(strings.TrimSpace(input.protectedDBSchemaHash)),
		ProtectedDBTablesHash:  strings.ToLower(strings.TrimSpace(input.protectedDBTablesHash)),
		AssetsManifestSHA256:   strings.ToLower(strings.TrimSpace(input.assetsManifestSHA256)),
		WorkflowManifestSHA256: strings.ToLower(strings.TrimSpace(input.workflowManifestSHA256)),
		DownloadURL:            strings.TrimSpace(input.downloadURL),
		PackageSHA256:          packageHash,
		Mandatory:              input.mandatory,
		MinSupportedVersion:    strings.TrimSpace(input.minSupportedVersion),
		RolloutPercent:         rollout,
		ReleaseNotes:           notes,
	}, nil
}

func ensureVisionFlowApp(ctx context.Context, baseURL string, token string, input visionFlowBootstrapInput) (bool, error) {
	var apps struct {
		Items []adminApp `json:"items"`
	}
	if err := getAdminJSON(ctx, baseURL, token, "/admin/apps", &apps); err != nil {
		return false, err
	}
	for _, app := range apps.Items {
		if app.AppKey == input.appID {
			return false, nil
		}
	}
	payload := map[string]any{
		"app_key":     input.appID,
		"name":        input.appName,
		"description": "VisionFlow Windows client",
		"owner_team":  input.ownerTeam,
		"platform":    input.platform,
		"version":     input.version,
	}
	if _, err := postAdminJSON(ctx, baseURL, token, "/admin/apps", payload); err != nil {
		return false, err
	}
	return true, nil
}

func fetchAppDetail(ctx context.Context, baseURL string, token string, appID string) (adminAppDetail, error) {
	var detail adminAppDetail
	err := getAdminJSON(ctx, baseURL, token, "/admin/apps/"+url.PathEscape(appID), &detail)
	return detail, err
}

func ensureVisionFlowCapabilityDefaults(ctx context.Context, baseURL string, token string, appID string) (int, error) {
	var response struct {
		Items []map[string]any `json:"items"`
		Added int              `json:"added"`
	}
	err := postJSON(ctx, baseURL+"/admin/apps/"+url.PathEscape(appID)+"/capability-policies/visionflow-defaults", token, map[string]any{}, &response)
	if err != nil {
		return 0, err
	}
	if response.Added > 0 {
		return response.Added, nil
	}
	return len(response.Items), nil
}

func ensureVisionFlowRelease(ctx context.Context, baseURL string, token string, input visionFlowBootstrapInput, releases []adminRelease) (adminRelease, bool, bool, error) {
	var existing *adminRelease
	for i := range releases {
		release := releases[i]
		if release.Platform == input.platform && release.Version == input.version {
			existing = &release
			break
		}
	}
	payload := map[string]any{
		"platform":          input.platform,
		"version":           input.version,
		"build_number":      input.buildNumber,
		"channel":           "production",
		"status":            "active",
		"signer_thumbprint": input.signerThumbprint,
		"main_binary_hash":  input.binaryHash,
		"download_url":      input.downloadURL,
		"package_sha256":    input.packageSHA256,
		"mandatory":         false,
		"rollout_percent":   100,
		"release_notes":     input.releaseNotes,
	}

	if existing != nil {
		var response struct {
			Release adminRelease `json:"release"`
		}
		err := patchAdminJSON(ctx, baseURL, token, "/admin/apps/"+url.PathEscape(input.appID)+"/releases/"+url.PathEscape(existing.ID), payload, &response)
		return response.Release, false, true, err
	}

	var response struct {
		Release adminRelease `json:"release"`
	}
	err := postJSON(ctx, baseURL+"/admin/apps/"+url.PathEscape(input.appID)+"/releases", token, payload, &response)
	return response.Release, true, false, err
}

func fetchClientPublicKey(ctx context.Context, endpoint string) (string, error) {
	var response publicKeyResponse
	if err := getJSON(ctx, strings.TrimRight(endpoint, "/")+"/public-key", "", &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.PublicKey) == "" {
		return "", errors.New("public-key endpoint returned no public_key")
	}
	return strings.TrimSpace(response.PublicKey), nil
}

func createVisionFlowLicense(ctx context.Context, baseURL string, token string, input visionFlowBootstrapInput) (string, string, string, error) {
	expiresAt := strings.TrimSpace(input.expiresAt)
	if expiresAt == "" {
		days := input.licenseDays
		if days <= 0 {
			days = 30
		}
		expiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Format("2006-01-02")
	}
	payload := map[string]any{
		"app_id":       input.appID,
		"plan_name":    "VisionFlow Dev",
		"owner_ref":    input.licenseOwner,
		"max_devices":  input.maxDevices,
		"expires_at":   expiresAt,
		"entitlements": input.entitlements,
	}
	var response struct {
		License    adminLicense `json:"license"`
		LicenseKey string       `json:"license_key"`
	}
	if err := postJSON(ctx, baseURL+"/admin/licenses", token, payload, &response); err != nil {
		return "", "", "", err
	}
	if strings.TrimSpace(response.LicenseKey) == "" {
		return "", "", "", errors.New("license creation returned no license_key")
	}
	return strings.TrimSpace(response.LicenseKey), response.License.ID, expiresAt, nil
}

func renderVisionFlowBootstrapResult(result visionFlowBootstrapResult, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "env":
		keys := []string{
			"LICENSE_GUARD_ENDPOINT",
			"LICENSE_GUARD_APP_ID",
			"LICENSE_GUARD_PUBLIC_KEY",
			"LICENSE_GUARD_APP_VERSION",
			"LICENSE_GUARD_BINARY_HASH",
			"LICENSE_GUARD_SIGNER_THUMBPRINT",
			"VISIONFLOW_LICENSE_KEY",
		}
		var b strings.Builder
		for _, key := range keys {
			b.WriteString(key)
			b.WriteString("=")
			b.WriteString(result.VisionFlowEnv[key])
			b.WriteString("\n")
		}
		return b.String(), nil
	case "json":
		var b bytes.Buffer
		if err := writeJSON(&b, result); err != nil {
			return "", err
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func normalizeClientEndpoint(endpoint string, baseURL string) string {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint != "" {
		return endpoint
	}
	return strings.TrimRight(baseURL, "/") + "/v1"
}

func defaultVisionFlowEntitlements() []string {
	return []string{
		"visionflow.automation",
		"visionflow.batch",
		"visionflow.export",
		"visionflow.plugin",
		"visionflow.update",
	}
}

func parseCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return normalizeStringList(strings.Split(value, ","))
}

func normalizeStringList(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func hashOrOverride(path string, override string, label string) (string, error) {
	value := strings.TrimSpace(override)
	if value != "" {
		return strings.ToLower(value), nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("%s path or %s-hash is required", label, label)
	}
	return fileSHA256Hex(path)
}

func fileSHA256Hex(path string) (string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func visionFlowBusinessManifestSHA256(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("business-manifest path is required")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read VisionFlow business manifest: %w", err)
	}
	var signed signedVisionFlowBusinessManifest
	if err := json.Unmarshal(data, &signed); err != nil {
		return "", fmt.Errorf("decode VisionFlow business manifest: %w", err)
	}
	if signed.Alg != "EdDSA" || signed.KeyType != "Ed25519" {
		return "", fmt.Errorf("unsupported VisionFlow business manifest signature type %s/%s", signed.Alg, signed.KeyType)
	}
	if strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("VisionFlow business manifest signature is required")
	}
	if signed.Manifest.SchemaVersion != "visionflow.business.v1" {
		return "", fmt.Errorf("unsupported VisionFlow business manifest schema %q", signed.Manifest.SchemaVersion)
	}
	payload, err := json.Marshal(signed.Manifest)
	if err != nil {
		return "", fmt.Errorf("encode VisionFlow business manifest signing payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func releaseNotesValue(value string, file string) (string, error) {
	if strings.TrimSpace(file) == "" {
		return strings.TrimSpace(value), nil
	}
	raw, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func loginAdmin(ctx context.Context, baseURL string, account string, password string) (string, error) {
	if account == "" || password == "" {
		return "", errors.New("admin-token or admin-account/admin-password is required")
	}
	var response struct {
		AdminToken string `json:"admin_token"`
	}
	if err := postJSON(ctx, baseURL+"/admin/login", "", map[string]string{"account": account, "password": password}, &response); err != nil {
		return "", err
	}
	if response.AdminToken == "" {
		return "", errors.New("admin login returned no token")
	}
	return response.AdminToken, nil
}

func postAdminJSON(ctx context.Context, baseURL string, token string, path string, payload any) (map[string]any, error) {
	var response map[string]any
	if err := postJSON(ctx, baseURL+path, token, payload, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func getAdminJSON(ctx context.Context, baseURL string, token string, path string, out any) error {
	return getJSON(ctx, baseURL+path, token, out)
}

func patchAdminJSON(ctx context.Context, baseURL string, token string, path string, payload any, out any) error {
	return patchJSON(ctx, baseURL+path, token, payload, out)
}

func getJSON(ctx context.Context, target string, token string, out any) error {
	return requestJSON(ctx, http.MethodGet, target, token, nil, out)
}

func patchJSON(ctx context.Context, target string, token string, payload any, out any) error {
	return requestJSON(ctx, http.MethodPatch, target, token, payload, out)
}

func postJSON(ctx context.Context, target string, token string, payload any, out any) error {
	return requestJSON(ctx, http.MethodPost, target, token, payload, out)
}

func requestJSON(ctx context.Context, method string, target string, token string, payload any, out any) error {
	var body io.Reader = http.NoBody
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, target, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("license guard returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func normalizeServerURL(value string) string {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	value = strings.TrimSuffix(value, "/v1")
	return strings.TrimRight(value, "/")
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func envOrDefault(key string, fallbackValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallbackValue
	}
	return value
}

func fallback(value string, fallbackValue string) string {
	if value == "" {
		return fallbackValue
	}
	return value
}
