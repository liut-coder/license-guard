package licensecore

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompareVersionStrings(t *testing.T) {
	cases := []struct {
		left  string
		right string
		want  int
	}{
		{left: "1.4.2", right: "1.5.0", want: -1},
		{left: "1.5.0", right: "1.5.0", want: 0},
		{left: "1.10.0", right: "1.9.9", want: 1},
		{left: "2.0.0-beta.1", right: "2.0.0", want: 1},
	}
	for _, tc := range cases {
		got := compareVersionStrings(tc.left, tc.right)
		if got != tc.want {
			t.Fatalf("compareVersionStrings(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestReleaseInRollout(t *testing.T) {
	if releaseInRollout("app", "windows", "rel", "device", -10) {
		t.Fatal("negative rollout should be disabled")
	}
	if releaseInRollout("app", "windows", "rel", "device", 0) {
		t.Fatal("zero rollout should be disabled")
	}
	if !releaseInRollout("app", "windows", "rel", "device", 100) {
		t.Fatal("full rollout should be enabled")
	}

	first := releaseInRollout("app", "windows", "rel", "device", 35)
	second := releaseInRollout("app", "windows", "rel", "device", 35)
	if first != second {
		t.Fatal("rollout decision should be stable for the same device")
	}
}

func TestDefaultCORSAllowsWildcard(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://admin.example.com")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
	}
}

func TestConfiguredCORSAllowsOnlyMatchingOrigin(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetCORSAllowedOrigins([]string{"https://admin.example.com", "https://ops.example.com/"})

	allowedReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	allowedReq.Header.Set("Origin", "https://ops.example.com")
	allowedRec := httptest.NewRecorder()
	server.ServeHTTP(allowedRec, allowedReq)
	if got := allowedRec.Header().Get("Access-Control-Allow-Origin"); got != "https://ops.example.com" {
		t.Fatalf("allowed origin header = %q, want exact origin", got)
	}
	if got := allowedRec.Header().Values("Vary"); !containsString(got, "Origin") {
		t.Fatalf("Vary headers = %#v, want Origin", got)
	}

	blockedReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	blockedReq.Header.Set("Origin", "https://evil.example.com")
	blockedRec := httptest.NewRecorder()
	server.ServeHTTP(blockedRec, blockedReq)
	if got := blockedRec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("blocked origin header = %q, want empty", got)
	}
}

func TestAdminLoginRateLimitsFailedAttempts(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetFailureRateLimit(2, time.Minute)

	for i := 0; i < 2; i++ {
		rec := postJSONRecorder(t, server, "/admin/login", map[string]any{
			"account":  DemoAdminAccount,
			"password": "wrong-password",
		})
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "INVALID_CREDENTIALS") {
			t.Fatalf("login attempt %d status/body = %d/%s, want invalid credentials", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := postJSONRecorder(t, server, "/admin/login", map[string]any{
		"account":  DemoAdminAccount,
		"password": "wrong-password",
	})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "RATE_LIMITED") {
		t.Fatalf("rate-limited login status/body = %d/%s", rec.Code, rec.Body.String())
	}
}

func TestChallengeRateLimitsUnknownApp(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetFailureRateLimit(2, time.Minute)

	for i := 0; i < 2; i++ {
		rec := postJSONRecorder(t, server, "/v1/challenge", map[string]any{
			"app_id":      "missing-app",
			"platform":    "windows",
			"install_id":  "rate-limit-install",
			"app_version": "1.4.2",
		})
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "APP_NOT_FOUND") {
			t.Fatalf("challenge attempt %d status/body = %d/%s, want app not found", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := postJSONRecorder(t, server, "/v1/challenge", map[string]any{
		"app_id":      "missing-app",
		"platform":    "windows",
		"install_id":  "rate-limit-install",
		"app_version": "1.4.2",
	})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "RATE_LIMITED") {
		t.Fatalf("rate-limited challenge status/body = %d/%s", rec.Code, rec.Body.String())
	}
}

func TestActivateRateLimitsInvalidLicenseAttempts(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetFailureRateLimit(2, time.Minute)

	for i := 0; i < 2; i++ {
		rec := activateInvalidLicenseRecorder(t, server, "rate-limit-activate-install")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "INVALID_LICENSE") {
			t.Fatalf("activate attempt %d status/body = %d/%s, want invalid license", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := activateInvalidLicenseRecorder(t, server, "rate-limit-activate-install")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "RATE_LIMITED") {
		t.Fatalf("rate-limited activate status/body = %d/%s", rec.Code, rec.Body.String())
	}
}

func TestVerifyRateLimitsInvalidTokenAttempts(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetFailureRateLimit(2, time.Minute)

	for i := 0; i < 2; i++ {
		rec := verifyInvalidTokenRecorder(t, server, "rate-limit-verify-install")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "INVALID_TOKEN") {
			t.Fatalf("verify attempt %d status/body = %d/%s, want invalid token", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := verifyInvalidTokenRecorder(t, server, "rate-limit-verify-install")
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "RATE_LIMITED") {
		t.Fatalf("rate-limited verify status/body = %d/%s", rec.Code, rec.Body.String())
	}
}

func TestChallengeEndpointCleansExpiredChallenges(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	now := time.Now()
	server.mu.Lock()
	server.challenges["expired"] = Challenge{
		ID:        "expired",
		Nonce:     "expired-nonce",
		AppID:     DemoAppID,
		InstallID: "expired-install",
		ExpiresAt: now.Add(-time.Minute),
		CreatedAt: now.Add(-6 * time.Minute),
	}
	server.challenges["active"] = Challenge{
		ID:        "active",
		Nonce:     "active-nonce",
		AppID:     DemoAppID,
		InstallID: "active-install",
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}
	server.mu.Unlock()

	body := []byte(`{"app_id":"` + DemoAppID + `","platform":"windows","install_id":"new-install","app_version":"1.4.2"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if _, ok := server.challenges["expired"]; ok {
		t.Fatalf("expired challenge was not cleaned: %#v", server.challenges)
	}
	if _, ok := server.challenges["active"]; !ok {
		t.Fatalf("active challenge was removed: %#v", server.challenges)
	}
	if len(server.challenges) != 2 {
		t.Fatalf("challenges = %#v, want active plus newly created challenge", server.challenges)
	}
}

func TestVerifyReturnsOptionalUpdateInfo(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	addDemoUpdateRelease(t, server, AppRelease{
		ID:             "rel_demo_nax_150_optional",
		Version:        "1.5.0",
		BuildNumber:    10500,
		DownloadURL:    "https://download.example.com/nax-desktop/1.5.0/setup.exe",
		PackageSHA256:  "package-150-sha256",
		ReleaseNotes:   "Optional 1.5.0 update.",
		RolloutPercent: 100,
	})

	activateResp := activateDemoLicense(t, server, "optional-update-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	verifyResp := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "optional-update-install", "1.4.2", nil)
	if !verifyResp.Allowed {
		t.Fatalf("verify response = %#v, want allowed", verifyResp)
	}
	if verifyResp.Update == nil {
		t.Fatal("verify response missing update info")
	}
	if !verifyResp.Update.Available ||
		verifyResp.Update.Required ||
		verifyResp.Update.LatestVersion != "1.5.0" ||
		verifyResp.Update.DownloadURL != "https://download.example.com/nax-desktop/1.5.0/setup.exe" ||
		verifyResp.Update.PackageSHA256 != "package-150-sha256" ||
		verifyResp.Update.ReleaseNotes != "Optional 1.5.0 update." {
		t.Fatalf("update info = %#v, want optional 1.5.0 update", verifyResp.Update)
	}
}

func TestVerifyReturnsRequiredUpdateForMandatoryRelease(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	addDemoUpdateRelease(t, server, AppRelease{
		ID:             "rel_demo_nax_150_mandatory",
		Version:        "1.5.0",
		BuildNumber:    10500,
		DownloadURL:    "https://download.example.com/nax-desktop/1.5.0/setup.exe",
		PackageSHA256:  "package-150-sha256",
		Mandatory:      true,
		RolloutPercent: 0,
	})

	activateResp := activateDemoLicense(t, server, "mandatory-update-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	verifyResp := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "mandatory-update-install", "1.4.2", nil)
	if !verifyResp.Allowed {
		t.Fatalf("verify response = %#v, want allowed", verifyResp)
	}
	if verifyResp.Update == nil || !verifyResp.Update.Available || !verifyResp.Update.Required || verifyResp.Update.LatestVersion != "1.5.0" {
		t.Fatalf("update info = %#v, want required 1.5.0 update", verifyResp.Update)
	}
}

func TestVerifyReturnsRequiredUpdateBelowMinSupportedVersion(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	addDemoUpdateRelease(t, server, AppRelease{
		ID:                  "rel_demo_nax_150_min_supported",
		Version:             "1.5.0",
		BuildNumber:         10500,
		DownloadURL:         "https://download.example.com/nax-desktop/1.5.0/setup.exe",
		PackageSHA256:       "package-150-sha256",
		MinSupportedVersion: "1.5.0",
		RolloutPercent:      0,
	})

	activateResp := activateDemoLicense(t, server, "min-supported-update-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	verifyResp := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "min-supported-update-install", "1.4.2", nil)
	if !verifyResp.Allowed {
		t.Fatalf("verify response = %#v, want allowed", verifyResp)
	}
	if verifyResp.Update == nil || !verifyResp.Update.Available || !verifyResp.Update.Required || verifyResp.Update.LatestVersion != "1.5.0" {
		t.Fatalf("update info = %#v, want min-supported required 1.5.0 update", verifyResp.Update)
	}
}

func TestVerifySuppressesOptionalUpdateOutsideRollout(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	addDemoUpdateRelease(t, server, AppRelease{
		ID:             "rel_demo_nax_150_rollout_zero",
		Version:        "1.5.0",
		BuildNumber:    10500,
		DownloadURL:    "https://download.example.com/nax-desktop/1.5.0/setup.exe",
		PackageSHA256:  "package-150-sha256",
		RolloutPercent: 0,
	})

	activateResp := activateDemoLicense(t, server, "zero-rollout-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	verifyResp := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "zero-rollout-install", "1.4.2", nil)
	if !verifyResp.Allowed {
		t.Fatalf("verify response = %#v, want allowed", verifyResp)
	}
	if verifyResp.Update != nil {
		t.Fatalf("update info = %#v, want nil outside rollout", verifyResp.Update)
	}
}

func TestVerifyOptionalUpdateRolloutStableForSameDevice(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	addDemoUpdateRelease(t, server, AppRelease{
		ID:             "rel_demo_nax_150_rollout_stable",
		Version:        "1.5.0",
		BuildNumber:    10500,
		DownloadURL:    "https://download.example.com/nax-desktop/1.5.0/setup.exe",
		PackageSHA256:  "package-150-sha256",
		RolloutPercent: 35,
	})

	activateResp := activateDemoLicense(t, server, "stable-rollout-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	first := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "stable-rollout-install", "1.4.2", nil)
	second := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "stable-rollout-install", "1.4.2", nil)
	if !first.Allowed || !second.Allowed {
		t.Fatalf("verify responses = %#v / %#v, want allowed", first, second)
	}
	if (first.Update != nil) != (second.Update != nil) {
		t.Fatalf("rollout update changed for same device: first=%#v second=%#v", first.Update, second.Update)
	}
	if first.Update != nil && first.Update.LatestVersion != "1.5.0" {
		t.Fatalf("first update info = %#v, want 1.5.0", first.Update)
	}
}

func TestBlockedAppVersionDeniesVerification(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	activateResp := activateDemoLicense(t, server, "blocked-version-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}

	server.mu.Lock()
	release := server.findReleaseByIDLocked(DemoAppID, "rel_demo_nax_142")
	if release == nil {
		server.mu.Unlock()
		t.Fatal("demo release not found")
	}
	release.Status = "blocked"
	server.mu.Unlock()

	verifyResp := verifyLicenseTokenForApp(t, server, DemoAppID, activateResp.LicenseToken, "blocked-version-install", "1.4.2", nil)
	if verifyResp.Allowed || verifyResp.Code != "INTEGRITY_FAILED" {
		t.Fatalf("verify response = %#v, want blocked release integrity denial", verifyResp)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if !hasRiskEvent(server.data.RiskEvents, "app_version_blocked") {
		t.Fatalf("app_version_blocked risk event not found in %#v", server.data.RiskEvents)
	}
}

func TestResolveRiskEventWritesResolvedAtAndAuditLog(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	server.mu.Lock()
	server.addRiskEventLocked(DemoAppID, "dev_test", "lic_demo_windows", "binary_hash_mismatch", "high", "deny", "主程序 hash 与发布版本不匹配", nil)
	eventID := server.data.RiskEvents[len(server.data.RiskEvents)-1].ID
	if err := server.saveLocked(); err != nil {
		server.mu.Unlock()
		t.Fatalf("saveLocked() error = %v", err)
	}
	server.mu.Unlock()

	token := loginTestAdmin(t, server)
	req := httptest.NewRequest(http.MethodPost, "/admin/risk-events/"+eventID+"/resolve", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resolveResp struct {
		RiskEvent RiskEvent `json:"risk_event"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resolveResp); err != nil {
		t.Fatalf("decode resolve response: %v", err)
	}
	if resolveResp.RiskEvent.ID != eventID {
		t.Fatalf("resolved event id = %q, want %q", resolveResp.RiskEvent.ID, eventID)
	}
	if resolveResp.RiskEvent.ResolvedAt == nil {
		t.Fatal("resolved_at was not set")
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit log status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Items []AuditLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	found := false
	for _, item := range auditResp.Items {
		if item.Action == "risk.resolve" && item.TargetType == "risk_event" && item.TargetID == eventID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("risk.resolve audit log for %s not found in %#v", eventID, auditResp.Items)
	}
}

func TestAdminLogoutInvalidatesSessionAndWritesAuditLog(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	token := loginTestAdmin(t, server)
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("logged out token status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	secondToken := loginTestAdmin(t, server)
	req = httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	req.Header.Set("Authorization", "Bearer "+secondToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit log status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Items []AuditLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	found := false
	for _, item := range auditResp.Items {
		if item.Action == "admin.logout" && item.TargetType == "admin" && item.TargetID == "admin_demo" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("admin.logout audit log not found in %#v", auditResp.Items)
	}
}

func TestAuditLogRedactsSensitiveMetadata(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/test", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.Header.Set("User-Agent", "audit-test")

	server.mu.Lock()
	server.auditLocked("admin_demo", "test.sensitive", "test", "target", req, map[string]any{
		"license_key":        "LG-SHOULD-NOT-LEAK",
		"license_key_prefix": "LG-SAFE-PREFIX",
		"admin_token":        "adm_should_not_leak",
		"database_url":       "postgres://user:password@example/license_guard",
		"safe":               "kept",
		"nested": map[string]any{
			"sdk_secret": "lgsk_should_not_leak",
			"count":      2,
		},
	})
	event := server.data.AuditLogs[len(server.data.AuditLogs)-1]
	server.mu.Unlock()

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	all := string(metadataJSON)
	for _, leaked := range []string{"LG-SHOULD-NOT-LEAK", "adm_should_not_leak", "password@example", "lgsk_should_not_leak"} {
		if strings.Contains(all, leaked) {
			t.Fatalf("audit metadata leaked %q: %s", leaked, all)
		}
	}
	if event.Metadata["safe"] != "kept" || event.Metadata["license_key_prefix"] != "LG-SAFE-PREFIX" {
		t.Fatalf("safe metadata was not preserved: %#v", event.Metadata)
	}
	nested, ok := event.Metadata["nested"].(map[string]any)
	if !ok || nested["sdk_secret"] != "[redacted]" || nested["count"] != 2 {
		t.Fatalf("nested metadata was not sanitized correctly: %#v", event.Metadata["nested"])
	}
}

func TestAdminPasswordChangeUpdatesHashInvalidatesOtherSessionsAndWritesAuditLog(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	token := loginTestAdmin(t, server)
	otherToken := loginTestAdmin(t, server)
	body := []byte(`{"current_password":"ChangeMe123!","new_password":"NewChangeMe123!"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/me/password", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("current session status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/me", nil)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader([]byte(`{"account":"admin@example.com","password":"ChangeMe123!"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password login status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	newToken := loginTestAdminWithPassword(t, server, "NewChangeMe123!")
	req = httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit log status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Items []AuditLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	found := false
	for _, item := range auditResp.Items {
		if item.Action == "admin.password.update" && item.TargetType == "admin" && item.TargetID == "admin_demo" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("admin.password.update audit log not found in %#v", auditResp.Items)
	}
}

func TestSettingsPatchAppliesDefaultsAndTokenPolicy(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	settingsBody := []byte(`{
		"default_token_ttl_minutes": 60,
		"medium_risk_token_ttl_minutes": 15,
		"offline_grace_days": 2,
		"default_max_devices": 5,
		"default_license_days": 45,
		"audit_log_retention_days": 180,
		"mfa_required": true,
		"sensitive_action_confirm": true
	}`)
	req := httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(settingsBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("settings patch status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var settingsResp struct {
		Settings SystemSettings `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &settingsResp); err != nil {
		t.Fatalf("decode settings response: %v", err)
	}
	if settingsResp.Settings.DefaultMaxDevices != 5 || settingsResp.Settings.DefaultLicenseDays != 45 || !settingsResp.Settings.MFARequired || !settingsResp.Settings.SensitiveActionConfirm {
		t.Fatalf("unexpected settings response: %#v", settingsResp.Settings)
	}

	licenseBody := []byte(`{"app_id":"app_nax_desktop_prod","owner_ref":"settings-defaults"}`)
	req = httptest.NewRequest(http.MethodPost, "/admin/licenses", bytes.NewReader(licenseBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	beforeLicense := time.Now()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("license create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var licenseResp struct {
		License    License `json:"license"`
		LicenseKey string  `json:"license_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &licenseResp); err != nil {
		t.Fatalf("decode license response: %v", err)
	}
	if licenseResp.License.MaxDevices != 5 {
		t.Fatalf("max devices = %d, want 5", licenseResp.License.MaxDevices)
	}
	minExpires := beforeLicense.Add(44 * 24 * time.Hour)
	maxExpires := beforeLicense.Add(46 * 24 * time.Hour)
	if licenseResp.License.ExpiresAt.Before(minExpires) || licenseResp.License.ExpiresAt.After(maxExpires) {
		t.Fatalf("expires_at = %s, want about 45 days from %s", licenseResp.License.ExpiresAt, beforeLicense)
	}
	if licenseResp.LicenseKey == "" {
		t.Fatal("license_key was not returned")
	}

	challengeReq := []byte(`{"app_id":"app_nax_desktop_prod","platform":"windows","install_id":"settings-install","app_version":"1.4.2"}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(challengeReq))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var challengeResp struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}

	activatePayload := map[string]any{
		"app_id":       DemoAppID,
		"platform":     "windows",
		"license_key":  licenseResp.LicenseKey,
		"challenge_id": challengeResp.ChallengeID,
		"nonce":        challengeResp.Nonce,
		"device": map[string]any{
			"install_id":        "settings-install",
			"fingerprint":       "settings-fingerprint",
			"os":                "windows",
			"os_version":        "Windows 11",
			"machine_name_hash": "settings-machine",
		},
		"integrity": map[string]any{
			"app_version":       "1.4.2",
			"main_binary_hash":  DemoBinaryHash,
			"signer_thumbprint": DemoSigner,
		},
	}
	activateBody, err := json.Marshal(activatePayload)
	if err != nil {
		t.Fatalf("marshal activate payload: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/activate", bytes.NewReader(activateBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	beforeActivate := time.Now()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var verifyResp VerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode activate response: %v", err)
	}
	if !verifyResp.Allowed || verifyResp.ExpiresAt == nil || verifyResp.OfflineGraceUntil == nil {
		t.Fatalf("unexpected activate response: %#v", verifyResp)
	}
	minToken := beforeActivate.Add(55 * time.Minute)
	maxToken := beforeActivate.Add(65 * time.Minute)
	if verifyResp.ExpiresAt.Before(minToken) || verifyResp.ExpiresAt.After(maxToken) {
		t.Fatalf("token expires_at = %s, want about 60 minutes from %s", *verifyResp.ExpiresAt, beforeActivate)
	}
	minGrace := beforeActivate.Add(47 * time.Hour)
	maxGrace := beforeActivate.Add(49 * time.Hour)
	if verifyResp.OfflineGraceUntil.Before(minGrace) || verifyResp.OfflineGraceUntil.After(maxGrace) {
		t.Fatalf("offline_grace_until = %s, want about 2 days from %s", *verifyResp.OfflineGraceUntil, beforeActivate)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit log status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Items []AuditLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	foundSettingsAudit := false
	for _, item := range auditResp.Items {
		if item.Action == "settings.update" && item.TargetType == "settings" && item.TargetID == "system" {
			foundSettingsAudit = true
			break
		}
	}
	if !foundSettingsAudit {
		t.Fatalf("settings.update audit log not found in %#v", auditResp.Items)
	}
}

func TestBusinessManifestMismatchDeniesVerificationAndPersistsReport(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	server.mu.Lock()
	release := server.findReleaseByIDLocked(DemoAppID, "rel_demo_nax_142")
	if release == nil {
		server.mu.Unlock()
		t.Fatal("demo release not found")
	}
	release.ResourceManifestHash = "expected-business-manifest"
	server.mu.Unlock()

	verifyResp := activateDemoLicense(t, server, "business-mismatch-install", map[string]any{
		"business_manifest_sha256":          "actual-business-manifest",
		"business_manifest_signature_valid": true,
		"protected_db_schema_hash":          "schema-v1",
		"protected_db_tables_hash":          "tables-v1",
		"assets_manifest_sha256":            "assets-v1",
		"workflow_manifest_sha256":          "workflow-v1",
		"business_integrity_status":         "ok",
	})
	if verifyResp.Allowed || verifyResp.Code != "INTEGRITY_FAILED" {
		t.Fatalf("verify response = %#v, want integrity denial", verifyResp)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.data.IntegrityReports) == 0 {
		t.Fatal("integrity report was not persisted")
	}
	report := server.data.IntegrityReports[len(server.data.IntegrityReports)-1]
	if report.BusinessManifestSHA256 != "actual-business-manifest" ||
		report.ProtectedDBSchemaHash != "schema-v1" ||
		report.ProtectedDBTablesHash != "tables-v1" ||
		report.AssetsManifestSHA256 != "assets-v1" ||
		report.WorkflowManifestSHA256 != "workflow-v1" {
		t.Fatalf("business integrity fields were not persisted: %#v", report)
	}
	if report.BusinessManifestSignatureValid == nil || !*report.BusinessManifestSignatureValid {
		t.Fatalf("business manifest signature flag = %#v, want true", report.BusinessManifestSignatureValid)
	}
	if !hasRiskEvent(server.data.RiskEvents, "business_manifest_mismatch") {
		t.Fatalf("business_manifest_mismatch risk event not found in %#v", server.data.RiskEvents)
	}
}

func TestReleaseResourceManifestFieldsDenyVerification(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	server.mu.Lock()
	release := server.findReleaseByIDLocked(DemoAppID, "rel_demo_nax_142")
	if release == nil {
		server.mu.Unlock()
		t.Fatal("demo release not found")
	}
	release.BusinessManifestSHA256 = "business-v1"
	release.ProtectedDBSchemaHash = "schema-v1"
	release.ProtectedDBTablesHash = "tables-v1"
	release.AssetsManifestSHA256 = "assets-v1"
	release.WorkflowManifestSHA256 = "workflow-v1"
	server.mu.Unlock()

	verifyResp := activateDemoLicense(t, server, "resource-mismatch-install", map[string]any{
		"business_manifest_sha256":          "business-v1",
		"business_manifest_signature_valid": true,
		"protected_db_schema_hash":          "schema-v2",
		"protected_db_tables_hash":          "tables-v2",
		"assets_manifest_sha256":            "assets-v2",
		"workflow_manifest_sha256":          "workflow-v2",
		"business_integrity_status":         "ok",
	})
	if verifyResp.Allowed || verifyResp.Code != "INTEGRITY_FAILED" {
		t.Fatalf("verify response = %#v, want integrity denial", verifyResp)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	for _, eventType := range []string{"protected_db_definition_mismatch", "asset_manifest_mismatch", "workflow_manifest_mismatch"} {
		if !hasRiskEvent(server.data.RiskEvents, eventType) {
			t.Fatalf("%s risk event not found in %#v", eventType, server.data.RiskEvents)
		}
	}
}

func TestAdminReleaseCreateRejectsMissingIntegrityFieldsWhenValidationEnabled(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)
	body := []byte(`{
		"platform":"windows",
		"version":"1.5.0",
		"build_number":10500,
		"status":"active",
		"validate_integrity_fields":true
	}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/"+DemoAppID+"/releases", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("release create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	bodyText := rec.Body.String()
	for _, want := range []string{"RELEASE_FIELDS_MISSING", "main_binary_hash", "business_manifest_sha256", "download_url"} {
		if !strings.Contains(bodyText, want) {
			t.Fatalf("release create error %q missing %q", bodyText, want)
		}
	}
}

func TestAdminReleasePatchPersistsVisionFlowResourceFields(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)
	body := []byte(`{
		"business_manifest_sha256":"business-v1",
		"protected_db_schema_hash":"schema-v1",
		"protected_db_tables_hash":"tables-v1",
		"assets_manifest_sha256":"assets-v1",
		"workflow_manifest_sha256":"workflow-v1",
		"validate_integrity_fields":true
	}`)
	req := httptest.NewRequest(http.MethodPatch, "/admin/apps/"+DemoAppID+"/releases/rel_demo_nax_142", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("release patch status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Release AppRelease `json:"release"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode release response: %v", err)
	}
	if resp.Release.BusinessManifestSHA256 != "business-v1" ||
		resp.Release.ProtectedDBSchemaHash != "schema-v1" ||
		resp.Release.ProtectedDBTablesHash != "tables-v1" ||
		resp.Release.AssetsManifestSHA256 != "assets-v1" ||
		resp.Release.WorkflowManifestSHA256 != "workflow-v1" {
		t.Fatalf("release response missing resource fields: %#v", resp.Release)
	}
}

func TestBusinessManifestSignatureInvalidDeniesVerification(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	verifyResp := activateDemoLicense(t, server, "signature-invalid-install", map[string]any{
		"business_manifest_sha256":          "signed-manifest",
		"business_manifest_signature_valid": false,
		"business_integrity_status":         "ok",
	})
	if verifyResp.Allowed || verifyResp.Code != "INTEGRITY_FAILED" {
		t.Fatalf("verify response = %#v, want integrity denial", verifyResp)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if !hasRiskEvent(server.data.RiskEvents, "business_manifest_signature_invalid") {
		t.Fatalf("business_manifest_signature_invalid risk event not found in %#v", server.data.RiskEvents)
	}
	report := server.data.IntegrityReports[len(server.data.IntegrityReports)-1]
	if report.BusinessManifestSignatureValid == nil || *report.BusinessManifestSignatureValid {
		t.Fatalf("business manifest signature flag = %#v, want false", report.BusinessManifestSignatureValid)
	}
}

func TestHeartbeatRecordsBusinessIntegrityAndDeniesTamperedStatus(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	activateResp := activateDemoLicense(t, server, "heartbeat-business-install", map[string]any{
		"business_manifest_sha256":          "heartbeat-manifest",
		"business_manifest_signature_valid": true,
		"business_integrity_status":         "ok",
	})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}

	heartbeatPayload := map[string]any{
		"app_id":        DemoAppID,
		"platform":      "windows",
		"license_token": activateResp.LicenseToken,
		"install_id":    "heartbeat-business-install",
		"app_version":   "1.4.2",
		"integrity": map[string]any{
			"business_manifest_sha256":          "heartbeat-manifest",
			"business_manifest_signature_valid": true,
			"protected_db_schema_hash":          "schema-v2",
			"protected_db_tables_hash":          "tables-v2",
			"business_integrity_status":         "tampered",
			"business_integrity_errors":         []string{"protected table hash mismatch"},
		},
	}
	heartbeatBody, err := json.Marshal(heartbeatPayload)
	if err != nil {
		t.Fatalf("marshal heartbeat payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(heartbeatBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var heartbeatResp struct {
		OK   bool   `json:"ok"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &heartbeatResp); err != nil {
		t.Fatalf("decode heartbeat response: %v", err)
	}
	if heartbeatResp.OK || heartbeatResp.Code != "INTEGRITY_FAILED" {
		t.Fatalf("heartbeat response = %#v, want integrity denial", heartbeatResp)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if !hasRiskEvent(server.data.RiskEvents, "business_integrity_failed") {
		t.Fatalf("business_integrity_failed risk event not found in %#v", server.data.RiskEvents)
	}
	report := server.data.IntegrityReports[len(server.data.IntegrityReports)-1]
	if report.BusinessIntegrityStatus != "tampered" ||
		report.ProtectedDBSchemaHash != "schema-v2" ||
		report.ProtectedDBTablesHash != "tables-v2" ||
		len(report.BusinessIntegrityErrors) != 1 {
		t.Fatalf("heartbeat integrity report = %#v, want business fields", report)
	}
}

func TestHighRiskSignalsUseShortTokenTTL(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.mu.Lock()
	server.data.Settings.DefaultTokenTTLMinutes = 120
	server.data.Settings.MediumRiskTokenTTLMinutes = 5
	server.mu.Unlock()

	verifyResp := activateDemoLicense(t, server, "high-risk-ttl-install", map[string]any{
		"suspicious_modules": []string{"mod1", "mod2", "mod3", "mod4", "mod5", "mod6", "mod7"},
	})
	if !verifyResp.Allowed || verifyResp.ExpiresAt == nil {
		t.Fatalf("verify response = %#v, want allowed short token", verifyResp)
	}
	if verifyResp.Risk.Level != "high" || !containsString(verifyResp.Risk.Actions, "shorten_token_ttl") {
		t.Fatalf("risk = %#v, want high risk with shorten_token_ttl action", verifyResp.Risk)
	}
	ttl := time.Until(*verifyResp.ExpiresAt)
	if ttl > 10*time.Minute {
		t.Fatalf("token ttl = %s, want shortened high-risk ttl near 5m", ttl)
	}
}

func TestRiskSignalsPersistIntegrityReportWithoutSingleSignalDeny(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	verifyResp := activateDemoLicense(t, server, "risk-signals-install", map[string]any{
		"debugger_detected":  true,
		"suspicious_modules": []string{"observer.dll"},
		"vm_indicators":      []string{"hypervisor"},
	})
	if !verifyResp.Allowed || verifyResp.Code != "" {
		t.Fatalf("verify response = %#v, want allowed risk scoring", verifyResp)
	}
	if verifyResp.Risk.Score < 80 || verifyResp.Risk.Level != "high" {
		t.Fatalf("risk = %#v, want high scoring risk", verifyResp.Risk)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	report := server.data.IntegrityReports[len(server.data.IntegrityReports)-1]
	if !report.DebuggerDetected ||
		len(report.SuspiciousModules) != 1 || report.SuspiciousModules[0] != "observer.dll" ||
		len(report.VMIndicators) != 1 || report.VMIndicators[0] != "hypervisor" {
		t.Fatalf("integrity report missing risk signals: %#v", report)
	}
	activation := server.latestActivationForLicenseLocked("lic_demo_windows")
	if activation == nil || activation.ActivationStatus != "active" {
		t.Fatalf("activation = %#v, want active despite risk signals", activation)
	}
	if hasRiskEvent(server.data.RiskEvents, "device_blocked") {
		t.Fatalf("risk signals should not block device by themselves: %#v", server.data.RiskEvents)
	}
	for _, eventType := range []string{"debugger_detected", "suspicious_module_loaded", "vm_indicator"} {
		if !hasRiskEvent(server.data.RiskEvents, eventType) {
			t.Fatalf("%s risk event not found in %#v", eventType, server.data.RiskEvents)
		}
	}
}

func TestVisionFlowAppCreateSeedsDefaultCapabilityPolicies(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	body := []byte(`{"app_key":"app_visionflow_windows_prod","name":"VisionFlow Windows","platform":"windows","version":"0.1.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/apps", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("app create status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/apps/app_visionflow_windows_prod/capability-policies", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("capability policies status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []CapabilityPolicy `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode capability policies: %v", err)
	}
	if len(resp.Items) != 7 {
		t.Fatalf("capability policy count = %d, want 7: %#v", len(resp.Items), resp.Items)
	}
	if !hasCapabilityPolicy(resp.Items, "automation.run", "visionflow.automation", "block") {
		t.Fatalf("default automation.run policy not found in %#v", resp.Items)
	}
	if !hasCapabilityPolicy(resp.Items, "export.video", "visionflow.export", "watermark") {
		t.Fatalf("default export.video policy not found in %#v", resp.Items)
	}
}

func TestVisionFlowLicenseDeviceLimit(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	appBody := []byte(`{"app_key":"app_visionflow_windows_prod","name":"VisionFlow Windows","platform":"windows","version":"0.1.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/apps", bytes.NewReader(appBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("app create status = %d, body = %s", rec.Code, rec.Body.String())
	}

	licenseBody := []byte(`{
		"app_id":"app_visionflow_windows_prod",
		"plan_name":"VisionFlow Dev",
		"owner_ref":"visionflow-device-limit",
		"max_devices":1,
		"entitlements":["visionflow.automation"]
	}`)
	req = httptest.NewRequest(http.MethodPost, "/admin/licenses", bytes.NewReader(licenseBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("license create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var licenseResp struct {
		License    License `json:"license"`
		LicenseKey string  `json:"license_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &licenseResp); err != nil {
		t.Fatalf("decode license response: %v", err)
	}
	if licenseResp.License.AppID != "app_visionflow_windows_prod" || licenseResp.License.MaxDevices != 1 || licenseResp.LicenseKey == "" {
		t.Fatalf("unexpected VisionFlow license response: %#v", licenseResp)
	}

	first := activateLicenseForApp(t, server, "app_visionflow_windows_prod", licenseResp.LicenseKey, "visionflow-device-1", "0.1.0", nil)
	if !first.Allowed || first.LicenseToken == "" {
		t.Fatalf("first activation = %#v, want allowed token", first)
	}
	second := activateLicenseForApp(t, server, "app_visionflow_windows_prod", licenseResp.LicenseKey, "visionflow-device-2", "0.1.0", nil)
	if second.Allowed || second.Code != "DEVICE_LIMIT_EXCEEDED" {
		t.Fatalf("second activation = %#v, want DEVICE_LIMIT_EXCEEDED", second)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if server.findAppLocked("app_visionflow_windows_prod") == nil {
		t.Fatal("VisionFlow app was not persisted")
	}
	if server.findReleaseLocked("app_visionflow_windows_prod", "windows", "0.1.0") == nil {
		t.Fatal("VisionFlow release was not persisted")
	}
	if server.findLicenseByIDLocked(licenseResp.License.ID) == nil {
		t.Fatal("VisionFlow license was not persisted")
	}
	activation := server.latestActivationForLicenseLocked(licenseResp.License.ID)
	if activation == nil || activation.ActivationStatus != "active" {
		t.Fatalf("VisionFlow activation = %#v, want active", activation)
	}
	if server.findDeviceByIDLocked(activation.DeviceID) == nil {
		t.Fatalf("VisionFlow device %q was not persisted", activation.DeviceID)
	}
	if !hasRiskEvent(server.data.RiskEvents, "device_limit_exceeded") {
		t.Fatalf("device_limit_exceeded risk event not found in %#v", server.data.RiskEvents)
	}
}

func TestCapabilityPolicyDeniesMissingEntitlementAndSignsVerifyBundle(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	upsertPayload := []byte(`{"items":[
		{"capability":"automation.run","required_entitlement":"feature.pro","mode":"block","message":"allowed for pro"},
		{"capability":"premium.run","required_entitlement":"visionflow.premium","mode":"allow","message":"should still require entitlement"}
	]}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/apps/"+DemoAppID+"/capability-policies", bytes.NewReader(upsertPayload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("capability policy upsert status = %d, body = %s", rec.Code, rec.Body.String())
	}

	activateResp := activateDemoLicense(t, server, "capability-policy-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	if activateResp.CapabilityPolicy == nil {
		t.Fatal("verify response did not include signed capability policy bundle")
	}
	assertCapabilityPolicySignature(t, server.publicKey, *activateResp.CapabilityPolicy)
	if !hasDecision(activateResp.CapabilityPolicy.Bundle.Decisions, "automation.run", true, "allow", "") {
		t.Fatalf("automation.run decision missing or not allowed: %#v", activateResp.CapabilityPolicy.Bundle.Decisions)
	}
	if !hasDecision(activateResp.CapabilityPolicy.Bundle.Decisions, "premium.run", false, "block", "missing_entitlement") {
		t.Fatalf("premium.run decision did not enforce missing entitlement: %#v", activateResp.CapabilityPolicy.Bundle.Decisions)
	}

	decision := capabilityCheck(t, server, activateResp.LicenseToken, "premium.run")
	if decision.Allowed || decision.ConfiguredMode != "allow" || decision.EffectiveMode != "block" || decision.Reason != "missing_entitlement" {
		t.Fatalf("premium.run capability decision = %#v, want missing entitlement denial with block effective mode", decision)
	}
	unknown := capabilityCheck(t, server, activateResp.LicenseToken, "unknown.capability")
	if unknown.Allowed || unknown.EffectiveMode != "block" || unknown.Reason != "unknown_capability" {
		t.Fatalf("unknown capability decision = %#v, want default deny", unknown)
	}
}

func TestAuthorizationDiagnosticsExplainsCapabilityDeny(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	upsertPayload := []byte(`{"items":[
		{"capability":"premium.run","required_entitlement":"visionflow.premium","mode":"allow","message":"premium required"}
	]}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/apps/"+DemoAppID+"/capability-policies", bytes.NewReader(upsertPayload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("capability policy upsert status = %d, body = %s", rec.Code, rec.Body.String())
	}

	activateResp := activateDemoLicense(t, server, "diagnostic-capability-install", map[string]any{})
	if !activateResp.Allowed || activateResp.LicenseToken == "" {
		t.Fatalf("activate response = %#v, want allowed token", activateResp)
	}
	decision := capabilityCheck(t, server, activateResp.LicenseToken, "premium.run")
	if decision.Allowed || decision.Reason != "missing_entitlement" {
		t.Fatalf("capability decision = %#v, want missing entitlement denial", decision)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/apps/"+DemoAppID+"/diagnostics?license_id=lic_demo_windows&platform=windows&app_version=1.4.2&capability=premium.run", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("diagnostics status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var diag AuthorizationDiagnosticResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &diag); err != nil {
		t.Fatalf("decode diagnostics response: %v", err)
	}
	if diag.License == nil || diag.License.ID != "lic_demo_windows" {
		t.Fatalf("diagnostic license = %#v, want demo license", diag.License)
	}
	if diag.Device == nil || diag.Activation == nil || diag.Activation.ActivationStatus != "active" {
		t.Fatalf("diagnostic device/activation = %#v / %#v, want inferred active activation", diag.Device, diag.Activation)
	}
	if diag.Release == nil || diag.Release.Version != "1.4.2" {
		t.Fatalf("diagnostic release = %#v, want 1.4.2", diag.Release)
	}
	if diag.CapabilityDecision == nil || diag.CapabilityDecision.Allowed || diag.CapabilityDecision.Reason != "missing_entitlement" || diag.CapabilityDecision.EffectiveMode != "block" {
		t.Fatalf("diagnostic capability decision = %#v, want missing entitlement block", diag.CapabilityDecision)
	}
	if diag.LatestCapabilityDeny == nil || diag.LatestCapabilityDeny.EventType != "capability_denied" {
		t.Fatalf("latest capability deny = %#v, want capability_denied", diag.LatestCapabilityDeny)
	}
	if !hasFinding(diag.Findings, "policy", "missing_entitlement") || !hasFinding(diag.Findings, "risk", "latest_capability_deny") {
		t.Fatalf("diagnostic findings missing policy/risk evidence: %#v", diag.Findings)
	}
	if diag.LatestIntegrityReport == nil {
		t.Fatalf("diagnostics did not include latest integrity report")
	}
}

func TestRotateSDKKeyReturnsSecretOnceAndWritesAuditLog(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	initialDetail := getAppDetailMap(t, server, token)
	initialKeys, ok := initialDetail["sdk_keys"].([]any)
	if !ok || len(initialKeys) != 1 {
		t.Fatalf("initial sdk_keys = %#v, want one key", initialDetail["sdk_keys"])
	}
	initialKey, ok := initialKeys[0].(map[string]any)
	if !ok {
		t.Fatalf("initial sdk key has unexpected type: %#v", initialKeys[0])
	}
	initialPrefix, _ := initialKey["key_prefix"].(string)
	if initialPrefix == "" {
		t.Fatalf("initial sdk key missing prefix: %#v", initialKey)
	}
	if _, leaked := initialKey["secret_hash"]; leaked {
		t.Fatalf("initial sdk key leaked secret_hash: %#v", initialKey)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/apps/"+DemoAppID+"/sdk-keys/rotate", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var rotateResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rotateResp); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	secret, _ := rotateResp["sdk_secret"].(string)
	if !strings.HasPrefix(secret, "lgsk_") {
		t.Fatalf("sdk_secret = %q, want lgsk_ prefix", secret)
	}
	rotatedKey, ok := rotateResp["sdk_key"].(map[string]any)
	if !ok {
		t.Fatalf("sdk_key response has unexpected type: %#v", rotateResp["sdk_key"])
	}
	if _, leaked := rotatedKey["secret_hash"]; leaked {
		t.Fatalf("rotated sdk key leaked secret_hash: %#v", rotatedKey)
	}
	newPrefix, _ := rotatedKey["key_prefix"].(string)
	if newPrefix == "" || newPrefix == initialPrefix {
		t.Fatalf("new key prefix = %q, initial = %q", newPrefix, initialPrefix)
	}
	if rotatedKey["status"] != "active" {
		t.Fatalf("rotated key status = %#v, want active", rotatedKey["status"])
	}

	detail := getAppDetailMap(t, server, token)
	keys, ok := detail["sdk_keys"].([]any)
	if !ok || len(keys) != 2 {
		t.Fatalf("sdk_keys after rotate = %#v, want two keys", detail["sdk_keys"])
	}
	seenActive := false
	seenRotated := false
	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			t.Fatalf("sdk key has unexpected type: %#v", rawKey)
		}
		if _, leaked := key["secret_hash"]; leaked {
			t.Fatalf("sdk key leaked secret_hash: %#v", key)
		}
		switch key["status"] {
		case "active":
			seenActive = key["key_prefix"] == newPrefix
		case "rotated":
			seenRotated = key["key_prefix"] == initialPrefix
		}
	}
	if !seenActive || !seenRotated {
		t.Fatalf("sdk key states not updated correctly: %#v", keys)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit log status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Items []AuditLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	found := false
	for _, item := range auditResp.Items {
		if item.Action == "sdk_key.rotate" && item.TargetType == "app" && item.TargetID == DemoAppID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("sdk_key.rotate audit log not found in %#v", auditResp.Items)
	}
}

func TestAppOnboardingAggregatesServerEvidence(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	req := httptest.NewRequest(http.MethodGet, "/admin/apps/"+DemoAppID+"/onboarding", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("onboarding status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var initial OnboardingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &initial); err != nil {
		t.Fatalf("decode onboarding response: %v", err)
	}
	if initial.AppID != DemoAppID || !initial.HasActiveSDKKey || !initial.HasRelease || !initial.HasLicense {
		t.Fatalf("unexpected initial onboarding response: %#v", initial)
	}
	if stepStatus(initial.Steps, "sdk_key_active") != "passed" {
		t.Fatalf("sdk_key_active status = %q, want passed", stepStatus(initial.Steps, "sdk_key_active"))
	}
	if stepStatus(initial.Steps, "first_activation") != "current" {
		t.Fatalf("first_activation status = %q, want current", stepStatus(initial.Steps, "first_activation"))
	}

	now := time.Now()
	server.mu.Lock()
	server.data.Devices = append(server.data.Devices, Device{
		ID:                    "dev_onboarding",
		DeviceFingerprintHash: "fp",
		InstallIDHash:         "install",
		Platform:              "windows",
		RiskScore:             10,
		Status:                "active",
		FirstSeenAt:           now.Add(-time.Minute),
		LastSeenAt:            now,
	})
	server.data.Activations = append(server.data.Activations, Activation{
		ID:               "act_onboarding",
		LicenseID:        "lic_demo_windows",
		DeviceID:         "dev_onboarding",
		AppID:            DemoAppID,
		ActivationStatus: "active",
		ActivatedAt:      now.Add(-time.Minute),
		LastVerifiedAt:   now,
	})
	server.data.IntegrityReports = append(server.data.IntegrityReports, IntegrityReport{
		ID:               "ir_onboarding",
		AppID:            DemoAppID,
		DeviceID:         "dev_onboarding",
		ReleaseID:        "rel_demo_nax_142",
		Platform:         "windows",
		AppVersion:       "1.4.2",
		MainBinaryHash:   DemoBinaryHash,
		SignerThumbprint: DemoSigner,
		CreatedAt:        now,
	})
	server.addRiskEventLocked(DemoAppID, "dev_onboarding", "lic_demo_windows", "binary_hash_mismatch", "high", "deny", "test risk", nil)
	if err := server.saveLocked(); err != nil {
		server.mu.Unlock()
		t.Fatalf("saveLocked() error = %v", err)
	}
	server.mu.Unlock()

	req = httptest.NewRequest(http.MethodGet, "/admin/apps/"+DemoAppID+"/onboarding", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("onboarding after evidence status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var withEvidence OnboardingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &withEvidence); err != nil {
		t.Fatalf("decode onboarding response with evidence: %v", err)
	}
	for _, id := range []string{"first_activation", "online_verify", "heartbeat", "integrity_report", "risk_drill"} {
		if got := stepStatus(withEvidence.Steps, id); got != "passed" {
			t.Fatalf("%s status = %q, want passed", id, got)
		}
	}
	if withEvidence.LatestDevice == nil || withEvidence.LatestDevice.ID != "dev_onboarding" {
		t.Fatalf("latest device = %#v, want dev_onboarding", withEvidence.LatestDevice)
	}
	if withEvidence.LatestRiskEvent == nil || withEvidence.LatestRiskEvent.EventType != "binary_hash_mismatch" {
		t.Fatalf("latest risk event = %#v", withEvidence.LatestRiskEvent)
	}
}

func TestIntegrationBundleOmitsSecretsAndContainsSkeleton(t *testing.T) {
	server, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	token := loginTestAdmin(t, server)

	body := []byte(`{"endpoint":"https://license.example/v1"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/apps/"+DemoAppID+"/integration-bundle", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("integration bundle status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/zip" {
		t.Fatalf("content type = %q, want application/zip", contentType)
	}

	files := readZipFiles(t, rec.Body.Bytes())
	for _, name := range []string{
		"README.md",
		".env.example",
		"licenseguard.config.json",
		"app_id.txt",
		"endpoint.txt",
		"public_key.txt",
		"integration-checklist.md",
		"internal/licenseguard/config.go",
		"internal/licenseguard/service.go",
		"internal/licenseguard/errors.go",
	} {
		if files[name] == "" {
			t.Fatalf("bundle missing %s; files = %#v", name, files)
		}
	}
	all := strings.Join(mapValues(files), "\n")
	if strings.Contains(all, "secret_hash") || strings.Contains(all, "lgsk_") || strings.Contains(all, DemoLicenseKey) {
		t.Fatalf("bundle leaked secret material or default license: %s", all)
	}
	if !strings.Contains(files[".env.example"], "LICENSE_GUARD_PUBLIC_KEY=") || !strings.Contains(files[".env.example"], "LICENSE_GUARD_APP_ID="+DemoAppID) {
		t.Fatalf("env example missing public config: %s", files[".env.example"])
	}
	var config map[string]string
	if err := json.Unmarshal([]byte(files["licenseguard.config.json"]), &config); err != nil {
		t.Fatalf("decode licenseguard.config.json: %v", err)
	}
	if config["app_id"] != DemoAppID || config["endpoint"] != "https://license.example/v1" || config["license_key_strategy"] != "activation_time" {
		t.Fatalf("unexpected config json: %#v", config)
	}
	if strings.TrimSpace(files["app_id.txt"]) != DemoAppID || strings.TrimSpace(files["endpoint.txt"]) != "https://license.example/v1" {
		t.Fatalf("single-value files mismatch: app=%q endpoint=%q", files["app_id.txt"], files["endpoint.txt"])
	}
	if strings.TrimSpace(files["public_key.txt"]) == "" || strings.TrimSpace(files["public_key.txt"]) != config["public_key"] {
		t.Fatalf("public key file mismatch")
	}
	if !strings.Contains(files["internal/licenseguard/errors.go"], "INTEGRITY_FAILED") {
		t.Fatalf("errors skeleton missing code mapping: %s", files["internal/licenseguard/errors.go"])
	}
}

func activateDemoLicense(t *testing.T, server *Server, installID string, integrityOverrides map[string]any) VerifyResponse {
	t.Helper()
	return activateLicenseForApp(t, server, DemoAppID, DemoLicenseKey, installID, "1.4.2", integrityOverrides)
}

func postJSONRecorder(t *testing.T, server *Server, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func challengeForInstall(t *testing.T, server *Server, installID string) struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
} {
	t.Helper()
	rec := postJSONRecorder(t, server, "/v1/challenge", map[string]any{
		"app_id":      DemoAppID,
		"platform":    "windows",
		"install_id":  installID,
		"app_version": "1.4.2",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var challengeResp struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	return challengeResp
}

func activateInvalidLicenseRecorder(t *testing.T, server *Server, installID string) *httptest.ResponseRecorder {
	t.Helper()
	challenge := challengeForInstall(t, server, installID)
	return postJSONRecorder(t, server, "/v1/activate", map[string]any{
		"app_id":       DemoAppID,
		"platform":     "windows",
		"license_key":  "LG-INVALID-RATE-LIMIT",
		"challenge_id": challenge.ChallengeID,
		"nonce":        challenge.Nonce,
		"device": map[string]any{
			"install_id":        installID,
			"fingerprint":       installID + "-fingerprint",
			"os":                "windows",
			"os_version":        "Windows 11",
			"machine_name_hash": installID + "-machine",
		},
		"integrity": map[string]any{
			"app_version":       "1.4.2",
			"main_binary_hash":  DemoBinaryHash,
			"signer_thumbprint": DemoSigner,
		},
	})
}

func verifyInvalidTokenRecorder(t *testing.T, server *Server, installID string) *httptest.ResponseRecorder {
	t.Helper()
	challenge := challengeForInstall(t, server, installID)
	return postJSONRecorder(t, server, "/v1/verify", map[string]any{
		"app_id":        DemoAppID,
		"platform":      "windows",
		"license_token": "invalid-token",
		"challenge_id":  challenge.ChallengeID,
		"nonce":         challenge.Nonce,
		"device": map[string]any{
			"install_id":        installID,
			"fingerprint":       installID + "-fingerprint",
			"os":                "windows",
			"os_version":        "Windows 11",
			"machine_name_hash": installID + "-machine",
		},
		"integrity": map[string]any{
			"app_version":       "1.4.2",
			"main_binary_hash":  DemoBinaryHash,
			"signer_thumbprint": DemoSigner,
		},
	})
}

func activateLicenseForApp(t *testing.T, server *Server, appID string, licenseKey string, installID string, appVersion string, integrityOverrides map[string]any) VerifyResponse {
	t.Helper()
	challengeBody, err := json.Marshal(map[string]any{
		"app_id":      appID,
		"platform":    "windows",
		"install_id":  installID,
		"app_version": appVersion,
	})
	if err != nil {
		t.Fatalf("marshal challenge body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(challengeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var challengeResp struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}

	integrity := map[string]any{
		"app_version": appVersion,
	}
	if appID == DemoAppID {
		integrity["main_binary_hash"] = DemoBinaryHash
		integrity["signer_thumbprint"] = DemoSigner
	}
	for key, value := range integrityOverrides {
		integrity[key] = value
	}
	activateBody, err := json.Marshal(map[string]any{
		"app_id":       appID,
		"platform":     "windows",
		"license_key":  licenseKey,
		"challenge_id": challengeResp.ChallengeID,
		"nonce":        challengeResp.Nonce,
		"device": map[string]any{
			"install_id":        installID,
			"fingerprint":       installID + "-fingerprint",
			"os":                "windows",
			"os_version":        "Windows 11",
			"machine_name_hash": installID + "-machine",
		},
		"integrity": integrity,
	})
	if err != nil {
		t.Fatalf("marshal activate body: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/activate", bytes.NewReader(activateBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var verifyResp VerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode activate response: %v", err)
	}
	return verifyResp
}

func verifyLicenseTokenForApp(t *testing.T, server *Server, appID string, licenseToken string, installID string, appVersion string, integrityOverrides map[string]any) VerifyResponse {
	t.Helper()
	challengeBody, err := json.Marshal(map[string]any{
		"app_id":      appID,
		"platform":    "windows",
		"install_id":  installID,
		"app_version": appVersion,
	})
	if err != nil {
		t.Fatalf("marshal challenge body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(challengeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var challengeResp struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}

	integrity := map[string]any{
		"app_version": appVersion,
	}
	if appID == DemoAppID {
		integrity["main_binary_hash"] = DemoBinaryHash
		integrity["signer_thumbprint"] = DemoSigner
	}
	for key, value := range integrityOverrides {
		integrity[key] = value
	}
	verifyBody, err := json.Marshal(map[string]any{
		"app_id":        appID,
		"platform":      "windows",
		"license_token": licenseToken,
		"challenge_id":  challengeResp.ChallengeID,
		"nonce":         challengeResp.Nonce,
		"device": map[string]any{
			"install_id":        installID,
			"fingerprint":       installID + "-fingerprint",
			"os":                "windows",
			"os_version":        "Windows 11",
			"machine_name_hash": installID + "-machine",
		},
		"integrity": integrity,
	})
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", bytes.NewReader(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var verifyResp VerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	return verifyResp
}

func addDemoUpdateRelease(t *testing.T, server *Server, release AppRelease) {
	t.Helper()
	now := time.Now()
	if release.ID == "" {
		release.ID = newID("rel")
	}
	release.AppID = DemoAppID
	release.Platform = "windows"
	if release.Channel == "" {
		release.Channel = "production"
	}
	if release.Status == "" {
		release.Status = "active"
	}
	if release.CreatedAt.IsZero() {
		release.CreatedAt = now
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	server.data.Releases = append(server.data.Releases, release)
}

func hasRiskEvent(events []RiskEvent, eventType string) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

func hasCapabilityPolicy(items []CapabilityPolicy, capability string, entitlement string, mode string) bool {
	for _, item := range items {
		if item.Capability == capability && item.RequiredEntitlement == entitlement && item.Mode == mode {
			return true
		}
	}
	return false
}

func hasDecision(items []CapabilityDecision, capability string, allowed bool, effectiveMode string, reason string) bool {
	for _, item := range items {
		if item.Capability == capability && item.Allowed == allowed && item.EffectiveMode == effectiveMode && item.Reason == reason {
			return true
		}
	}
	return false
}

func hasFinding(items []DiagnosticFinding, scope string, code string) bool {
	for _, item := range items {
		if item.Scope == scope && item.Code == code {
			return true
		}
	}
	return false
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func assertCapabilityPolicySignature(t *testing.T, publicKey ed25519.PublicKey, bundle SignedCapabilityPolicyBundle) {
	t.Helper()
	payload, err := json.Marshal(bundle.Bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Signature)
	if err != nil {
		t.Fatalf("decode policy signature: %v", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatalf("policy signature did not verify")
	}
}

func capabilityCheck(t *testing.T, server *Server, token string, capability string) CapabilityDecision {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"app_id":        DemoAppID,
		"license_token": token,
		"capability":    capability,
	})
	if err != nil {
		t.Fatalf("marshal capability check body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/capability/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("capability check status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Decision CapabilityDecision `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode capability check response: %v", err)
	}
	return resp.Decision
}

func getAppDetailMap(t *testing.T, server *Server, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/apps/"+DemoAppID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("app detail status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var detail map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode app detail: %v", err)
	}
	return detail
}

func stepStatus(steps []OnboardingStep, id string) string {
	for _, step := range steps {
		if step.ID == id {
			return step.Status
		}
	}
	return ""
}

func readZipFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	files := map[string]string{}
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open zip file %s: %v", file.Name, err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read zip file %s: %v", file.Name, err)
		}
		files[file.Name] = string(content)
	}
	return files
}

func mapValues(items map[string]string) []string {
	values := make([]string, 0, len(items))
	for _, value := range items {
		values = append(values, value)
	}
	return values
}

func loginTestAdmin(t *testing.T, server *Server) string {
	t.Helper()
	return loginTestAdminWithPassword(t, server, "ChangeMe123!")
}

func loginTestAdminWithPassword(t *testing.T, server *Server, password string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"account": "admin@example.com", "password": password})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AdminToken string `json:"admin_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if resp.AdminToken == "" {
		t.Fatal("login response did not include admin_token")
	}
	return resp.AdminToken
}
