package licenseguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"license-guard/internal/licensecore"
)

func TestSDKBusinessIntegrityEndToEndWithServer(t *testing.T) {
	server, err := licensecore.NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	adminToken := loginSDKTestAdmin(t, httpServer.URL)
	releaseID := findSDKTestReleaseID(t, httpServer.URL, adminToken, licensecore.DemoAppID, "1.4.2")
	patchSDKTestRelease(t, httpServer.URL, adminToken, licensecore.DemoAppID, releaseID, map[string]any{
		"business_manifest_sha256": "business-v1",
		"protected_db_schema_hash": "schema-v1",
		"protected_db_tables_hash": "tables-v1",
		"assets_manifest_sha256":   "assets-v1",
		"workflow_manifest_sha256": "workflow-v1",
	})

	publicKey := fetchSDKTestPublicKey(t, httpServer.URL+"/v1")
	cacheRoot := t.TempDir()
	t.Setenv("LG_INSTALL_ID_PATH", filepath.Join(cacheRoot, "install_id"))
	t.Setenv("LG_TOKEN_CACHE_PATH", filepath.Join(cacheRoot, "license_token.json"))

	signatureValid := true
	assetsHash := "assets-v1"
	client, err := NewClient(Options{
		AppID:              licensecore.DemoAppID,
		Endpoint:           httpServer.URL + "/v1",
		PublicKey:          publicKey,
		AppVersion:         "1.4.2",
		BinaryHashOverride: licensecore.DemoBinaryHash,
		SignerThumbprint:   licensecore.DemoSigner,
		IntegrityHook: func(ctx context.Context, base IntegrityReport) (IntegrityReport, error) {
			base.BusinessManifestSHA256 = "business-v1"
			base.BusinessManifestSignatureValid = &signatureValid
			base.ProtectedDBSchemaHash = "schema-v1"
			base.ProtectedDBTablesHash = "tables-v1"
			base.AssetsManifestSHA256 = assetsHash
			base.WorkflowManifestSHA256 = "workflow-v1"
			base.BusinessIntegrityStatus = "ok"
			base.DBEncryptionStatus = "ok"
			return base, nil
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	activateResult, err := client.Activate(context.Background(), licensecore.DemoLicenseKey)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !activateResult.Allowed || activateResult.LicenseToken == "" {
		t.Fatalf("activate result = %#v, want allowed with token", activateResult)
	}
	verifyResult, err := client.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verifyResult.Allowed {
		t.Fatalf("verify result = %#v, want allowed", verifyResult)
	}
	if err := client.Heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	assetsHash = "assets-v2"
	verifyResult, err = client.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify with mismatch: %v", err)
	}
	if verifyResult.Allowed || verifyResult.Code != "INTEGRITY_FAILED" {
		t.Fatalf("verify result = %#v, want integrity denial", verifyResult)
	}

	err = client.Heartbeat(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "INTEGRITY_FAILED" {
		t.Fatalf("heartbeat error = %#v, want INTEGRITY_FAILED APIError", err)
	}
	latest := getSDKTestLatestIntegrityReport(t, httpServer.URL, adminToken, licensecore.DemoAppID)
	if latest.AssetsManifestSHA256 != "assets-v2" || latest.BusinessIntegrityStatus != "ok" || latest.DBEncryptionStatus != "ok" {
		t.Fatalf("latest integrity report = %#v, want mismatched asset hash persisted", latest)
	}
}

type sdkTestIntegrityReport struct {
	AssetsManifestSHA256    string `json:"assets_manifest_sha256"`
	BusinessIntegrityStatus string `json:"business_integrity_status"`
	DBEncryptionStatus      string `json:"db_encryption_status"`
}

func fetchSDKTestPublicKey(t *testing.T, endpoint string) string {
	t.Helper()
	client, err := NewClient(Options{
		AppID:    licensecore.DemoAppID,
		Endpoint: endpoint,
	})
	if err != nil {
		t.Fatalf("new public key client: %v", err)
	}
	resp, err := client.FetchPublicKey(context.Background())
	if err != nil {
		t.Fatalf("fetch public key: %v", err)
	}
	if resp.PublicKey == "" {
		t.Fatal("public key is empty")
	}
	return resp.PublicKey
}

func loginSDKTestAdmin(t *testing.T, baseURL string) string {
	t.Helper()
	var resp struct {
		AdminToken string `json:"admin_token"`
	}
	postSDKTestJSON(t, baseURL+"/admin/login", "", map[string]any{
		"account":  licensecore.DemoAdminAccount,
		"password": licensecore.DemoAdminPass,
	}, &resp)
	if resp.AdminToken == "" {
		t.Fatal("admin token is empty")
	}
	return resp.AdminToken
}

func findSDKTestReleaseID(t *testing.T, baseURL string, adminToken string, appID string, version string) string {
	t.Helper()
	var detail struct {
		Releases []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"releases"`
	}
	getSDKTestJSON(t, baseURL+"/admin/apps/"+appID, adminToken, &detail)
	for _, release := range detail.Releases {
		if release.Version == version {
			return release.ID
		}
	}
	t.Fatalf("release %s not found in %#v", version, detail.Releases)
	return ""
}

func patchSDKTestRelease(t *testing.T, baseURL string, adminToken string, appID string, releaseID string, payload map[string]any) {
	t.Helper()
	patchSDKTestJSON(t, baseURL+"/admin/apps/"+appID+"/releases/"+releaseID, adminToken, payload, &struct{}{})
}

func getSDKTestLatestIntegrityReport(t *testing.T, baseURL string, adminToken string, appID string) sdkTestIntegrityReport {
	t.Helper()
	var diag struct {
		LatestIntegrityReport sdkTestIntegrityReport `json:"latest_integrity_report"`
	}
	getSDKTestJSON(t, baseURL+"/admin/apps/"+appID+"/diagnostics?platform=windows&app_version=1.4.2", adminToken, &diag)
	return diag.LatestIntegrityReport
}

func getSDKTestJSON(t *testing.T, url string, adminToken string, out any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new GET request: %v", err)
	}
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	doSDKTestRequest(t, req, out)
}

func postSDKTestJSON(t *testing.T, url string, adminToken string, input any, out any) {
	t.Helper()
	requestWithJSON(t, http.MethodPost, url, adminToken, input, out)
}

func patchSDKTestJSON(t *testing.T, url string, adminToken string, input any, out any) {
	t.Helper()
	requestWithJSON(t, http.MethodPatch, url, adminToken, input, out)
}

func requestWithJSON(t *testing.T, method string, url string, adminToken string, input any, out any) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new %s request: %v", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	doSDKTestRequest(t, req, out)
}

func doSDKTestRequest(t *testing.T, req *http.Request, out any) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s %s status = %d", req.Method, req.URL, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}
