package licensecore

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	DemoAdminAccount = "admin@example.com"
	DemoAdminPass    = "ChangeMe123!"
	DemoAppID        = "app_nax_desktop_prod"
	DemoLicenseKey   = "LG-DEMO-2026-WINDOWS"
	DemoBinaryHash   = "demo-main-binary-sha256"
	DemoSigner       = "demo-signer-thumbprint"
)

type Server struct {
	mu            sync.Mutex
	data          Data
	store         Store
	publicKey     ed25519.PublicKey
	privateKey    ed25519.PrivateKey
	challenges    map[string]Challenge
	adminSessions map[string]AdminSession
}

type AdminSession struct {
	AdminID   string
	ExpiresAt time.Time
}

func NewServer(dataDir string) (*Server, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	store, err := NewJSONStore(dataDir)
	if err != nil {
		return nil, err
	}
	return NewServerWithStore(dataDir, store)
}

func NewServerWithStore(keyDir string, store Store) (*Server, error) {
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		return nil, err
	}
	pub, priv, err := LoadOrCreateSigningKey(keyDir)
	if err != nil {
		return nil, err
	}

	s := &Server{
		store:         store,
		publicKey:     pub,
		privateKey:    priv,
		challenges:    map[string]Challenge{},
		adminSessions: map[string]AdminSession{},
	}
	if err := s.loadOrSeed(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimRight(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/health" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "license-guard"})
	case path == "/v1/public-key" && r.Method == http.MethodGet:
		s.handlePublicKey(w, r)
	case path == "/admin/login" && r.Method == http.MethodPost:
		s.handleAdminLogin(w, r)
	case strings.HasPrefix(path, "/admin/"):
		adminID, ok := s.requireAdmin(w, r)
		if !ok {
			return
		}
		s.handleAdmin(w, r, path, adminID)
	case path == "/v1/challenge" && r.Method == http.MethodPost:
		s.handleChallenge(w, r)
	case path == "/v1/activate" && r.Method == http.MethodPost:
		s.handleActivate(w, r)
	case path == "/v1/verify" && r.Method == http.MethodPost:
		s.handleVerify(w, r)
	case path == "/v1/heartbeat" && r.Method == http.MethodPost:
		s.handleHeartbeat(w, r)
	case path == "/v1/deactivate" && r.Method == http.MethodPost:
		s.handleDeactivate(w, r)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "route not found")
	}
}

func (s *Server) handlePublicKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"alg":        "EdDSA",
		"key_type":   "Ed25519",
		"public_key": s.publicKeyString(),
	})
}

func (s *Server) publicKeyString() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request, path string, adminID string) {
	switch {
	case path == "/admin/logout" && r.Method == http.MethodPost:
		s.handleAdminLogout(w, r, adminID)
	case path == "/admin/me/password" && r.Method == http.MethodPost:
		s.handleAdminPasswordChange(w, r, adminID)
	case path == "/admin/me" && r.Method == http.MethodGet:
		s.mu.Lock()
		admin := s.findAdminByIDLocked(adminID)
		s.mu.Unlock()
		if admin == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "admin not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": admin.ID, "account": admin.Account, "name": admin.Name})
	case path == "/admin/dashboard" && r.Method == http.MethodGet:
		s.handleDashboard(w, r)
	case path == "/admin/apps":
		s.handleApps(w, r, adminID)
	case strings.HasPrefix(path, "/admin/apps/"):
		s.handleAppDetail(w, r, strings.TrimPrefix(path, "/admin/apps/"), adminID)
	case path == "/admin/licenses":
		s.handleLicenses(w, r, adminID)
	case strings.HasPrefix(path, "/admin/licenses/"):
		s.handleLicenseAction(w, r, strings.TrimPrefix(path, "/admin/licenses/"), adminID)
	case path == "/admin/devices" && r.Method == http.MethodGet:
		s.handleDevices(w, r)
	case strings.HasPrefix(path, "/admin/devices/"):
		s.handleDeviceAction(w, r, strings.TrimPrefix(path, "/admin/devices/"), adminID)
	case path == "/admin/risk-events" && r.Method == http.MethodGet:
		s.handleRiskEvents(w, r)
	case strings.HasPrefix(path, "/admin/risk-events/"):
		s.handleRiskEventAction(w, r, strings.TrimPrefix(path, "/admin/risk-events/"), adminID)
	case path == "/admin/audit-logs" && r.Method == http.MethodGet:
		s.handleAuditLogs(w, r)
	case path == "/admin/settings":
		s.handleSettings(w, r, adminID)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "admin route not found")
	}
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request, adminID string) {
	token := bearerToken(r)
	s.mu.Lock()
	delete(s.adminSessions, token)
	s.auditLocked(adminID, "admin.logout", "admin", adminID, r, nil)
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminPasswordChange(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "新密码至少需要 8 个字符")
		return
	}

	currentToken := bearerToken(r)
	s.mu.Lock()
	admin := s.findAdminByIDLocked(adminID)
	if admin == nil || admin.Status != "active" {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "admin not found")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.CurrentPassword)) != nil {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "INVALID_CURRENT_PASSWORD", "当前密码错误")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "PASSWORD_HASH_FAILED", err.Error())
		return
	}
	admin.PasswordHash = string(hash)
	admin.UpdatedAt = time.Now()
	s.invalidateAdminSessionsExceptLocked(adminID, currentToken)
	s.auditLocked(adminID, "admin.password.update", "admin", adminID, r, nil)
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	account := strings.ToLower(strings.TrimSpace(req.Account))
	s.mu.Lock()
	admin := s.findAdminByAccountLocked(account)
	var adminCopy Admin
	if admin != nil {
		adminCopy = *admin
	}
	s.mu.Unlock()

	if admin == nil || adminCopy.Status != "active" || bcrypt.CompareHashAndPassword([]byte(adminCopy.PasswordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "账号或密码错误")
		return
	}

	token := "adm_" + randomString(32)
	expiresAt := time.Now().Add(12 * time.Hour)
	s.mu.Lock()
	s.adminSessions[token] = AdminSession{AdminID: adminCopy.ID, ExpiresAt: expiresAt}
	s.auditLocked(adminCopy.ID, "admin.login", "admin", adminCopy.ID, r, nil)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"admin_token": token,
		"expires_at":  expiresAt,
		"admin":       map[string]any{"id": adminCopy.ID, "account": adminCopy.Account, "name": adminCopy.Name},
	})
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing admin token")
		return "", false
	}
	s.mu.Lock()
	session, ok := s.adminSessions[token]
	if ok && time.Now().After(session.ExpiresAt) {
		delete(s.adminSessions, token)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid admin token")
		return "", false
	}
	return session.AdminID, true
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" || token == auth {
		return ""
	}
	return token
}

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	activeLicenses := 0
	todayVerifications := 0
	highRiskDevices := 0
	for _, lic := range s.data.Licenses {
		if lic.Status == "active" && lic.ExpiresAt.After(now) {
			activeLicenses++
		}
	}
	for _, report := range s.data.IntegrityReports {
		if report.CreatedAt.After(dayStart) {
			todayVerifications++
		}
	}
	for _, device := range s.data.Devices {
		if device.RiskScore >= 80 || device.Status == "blocked" {
			highRiskDevices++
		}
	}

	events := append([]RiskEvent(nil), s.data.RiskEvents...)
	sort.Slice(events, func(i, j int) bool { return events[i].CreatedAt.After(events[j].CreatedAt) })
	if len(events) > 8 {
		events = events[:8]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"app_count":            len(s.data.Apps),
		"active_license_count": activeLicenses,
		"today_verify_count":   todayVerifications,
		"high_risk_devices":    highRiskDevices,
		"recent_risk_events":   events,
		"generated_at":         now,
	})
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request, adminID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		apps := append([]App(nil), s.data.Apps...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"items": apps})
	case http.MethodPost:
		var req struct {
			AppKey      string `json:"app_key"`
			Name        string `json:"name"`
			Description string `json:"description"`
			OwnerTeam   string `json:"owner_team"`
			Platform    string `json:"platform"`
			Version     string `json:"version"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.AppKey == "" || req.Name == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "app_key and name are required")
			return
		}
		if req.Platform == "" {
			req.Platform = "windows"
		}
		if req.Version == "" {
			req.Version = "1.0.0"
		}

		now := time.Now()
		app := App{
			ID:          newID("app"),
			AppKey:      req.AppKey,
			Name:        req.Name,
			Description: req.Description,
			OwnerTeam:   req.OwnerTeam,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		release := AppRelease{
			ID:             newID("rel"),
			AppID:          app.AppKey,
			Platform:       req.Platform,
			Version:        req.Version,
			BuildNumber:    1,
			Channel:        "production",
			Status:         "active",
			RolloutPercent: 100,
			CreatedAt:      now,
		}

		s.mu.Lock()
		if s.findAppLocked(req.AppKey) != nil {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "APP_EXISTS", "app_key already exists")
			return
		}
		s.data.Apps = append(s.data.Apps, app)
		s.data.Releases = append(s.data.Releases, release)
		sdkKey, sdkSecret := newSDKKey(app.AppKey, s.publicKeyString(), now, false)
		s.data.SDKKeys = append(s.data.SDKKeys, sdkKey)
		s.auditLocked(adminID, "app.create", "app", app.AppKey, r, map[string]any{"name": app.Name})
		err := s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"app": app, "release": release, "sdk_key": sdkKeyView(sdkKey), "sdk_secret": sdkSecret})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (s *Server) handleAppDetail(w http.ResponseWriter, r *http.Request, tail string, adminID string) {
	parts := strings.Split(tail, "/")
	appID := parts[0]
	if appID == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "app not found")
		return
	}

	if len(parts) == 3 && parts[1] == "sdk-keys" && parts[2] == "rotate" && r.Method == http.MethodPost {
		s.handleSDKKeyRotate(w, r, appID, adminID)
		return
	}

	if len(parts) == 2 && parts[1] == "onboarding" && r.Method == http.MethodGet {
		s.handleAppOnboarding(w, r, appID)
		return
	}

	if len(parts) == 2 && parts[1] == "integration-bundle" && r.Method == http.MethodPost {
		s.handleIntegrationBundle(w, r, appID)
		return
	}

	if len(parts) == 2 && parts[1] == "releases" && r.Method == http.MethodPost {
		var req AppRelease
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Version == "" || req.Platform == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "version and platform are required")
			return
		}
		req.ID = newID("rel")
		req.AppID = appID
		if req.Channel == "" {
			req.Channel = "production"
		}
		if req.Status == "" {
			req.Status = "active"
		}
		if req.RolloutPercent == 0 {
			req.RolloutPercent = 100
		}
		req.RolloutPercent = clampPercent(req.RolloutPercent)
		req.CreatedAt = time.Now()

		s.mu.Lock()
		if s.findAppLocked(appID) == nil {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
			return
		}
		s.data.Releases = append(s.data.Releases, req)
		s.auditLocked(adminID, "release.create", "app", appID, r, map[string]any{"version": req.Version})
		err := s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"release": req})
		return
	}

	if len(parts) == 3 && parts[1] == "releases" && r.Method == http.MethodPatch {
		var req struct {
			Status               *string `json:"status"`
			Mandatory            *bool   `json:"mandatory"`
			RolloutPercent       *int    `json:"rollout_percent"`
			DownloadURL          *string `json:"download_url"`
			PackageSHA256        *string `json:"package_sha256"`
			ReleaseNotes         *string `json:"release_notes"`
			SignerThumbprint     *string `json:"signer_thumbprint"`
			MainBinaryHash       *string `json:"main_binary_hash"`
			MinSupportedVersion  *string `json:"min_supported_version"`
			ResourceManifestHash *string `json:"resource_manifest_hash"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		releaseID := parts[2]

		s.mu.Lock()
		release := s.findReleaseByIDLocked(appID, releaseID)
		if release == nil {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, "RELEASE_NOT_FOUND", "release not found")
			return
		}
		if req.Status != nil {
			release.Status = *req.Status
		}
		if req.Mandatory != nil {
			release.Mandatory = *req.Mandatory
		}
		if req.RolloutPercent != nil {
			release.RolloutPercent = clampPercent(*req.RolloutPercent)
		}
		if req.DownloadURL != nil {
			release.DownloadURL = *req.DownloadURL
		}
		if req.PackageSHA256 != nil {
			release.PackageSHA256 = *req.PackageSHA256
		}
		if req.ReleaseNotes != nil {
			release.ReleaseNotes = *req.ReleaseNotes
		}
		if req.SignerThumbprint != nil {
			release.SignerThumbprint = *req.SignerThumbprint
		}
		if req.MainBinaryHash != nil {
			release.MainBinaryHash = *req.MainBinaryHash
		}
		if req.MinSupportedVersion != nil {
			release.MinSupportedVersion = *req.MinSupportedVersion
		}
		if req.ResourceManifestHash != nil {
			release.ResourceManifestHash = *req.ResourceManifestHash
		}
		s.auditLocked(adminID, "release.update", "release", releaseID, r, map[string]any{"app_id": appID})
		err := s.saveLocked()
		updated := *release
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"release": updated})
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	s.mu.Lock()
	app := s.findAppLocked(appID)
	if app == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
		return
	}
	releases := s.releasesForAppLocked(appID)
	sdkKeys := s.sdkKeyViewsForAppLocked(appID)
	licenses := s.licensesForAppLocked(appID)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"app": app, "releases": releases, "licenses": licenses, "sdk_keys": sdkKeys})
}

func (s *Server) handleAppOnboarding(w http.ResponseWriter, _ *http.Request, appID string) {
	s.mu.Lock()
	app := s.findAppLocked(appID)
	if app == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
		return
	}
	response := s.onboardingResponseLocked(*app)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleIntegrationBundle(w http.ResponseWriter, r *http.Request, appID string) {
	var req struct {
		Endpoint   string `json:"endpoint"`
		LicenseKey string `json:"license_key"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Endpoint == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded == "https" || forwarded == "http" {
			scheme = forwarded
		}
		req.Endpoint = scheme + "://" + r.Host + "/v1"
	}

	s.mu.Lock()
	app := s.findAppLocked(appID)
	if app == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
		return
	}
	response := s.onboardingResponseLocked(*app)
	s.mu.Unlock()

	body, err := buildIntegrationBundle(response, strings.TrimRight(req.Endpoint, "/"), req.LicenseKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BUNDLE_FAILED", err.Error())
		return
	}

	filename := "licenseguard-integration-" + sanitizeFilename(app.AppKey) + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleSDKKeyRotate(w http.ResponseWriter, r *http.Request, appID string, adminID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	now := time.Now()
	s.mu.Lock()
	if s.findAppLocked(appID) == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
		return
	}
	for i := range s.data.SDKKeys {
		if s.data.SDKKeys[i].AppID == appID && s.data.SDKKeys[i].Status == "active" {
			s.data.SDKKeys[i].Status = "rotated"
			s.data.SDKKeys[i].RotatedAt = &now
		}
	}
	sdkKey, sdkSecret := newSDKKey(appID, s.publicKeyString(), now, true)
	s.data.SDKKeys = append(s.data.SDKKeys, sdkKey)
	s.auditLocked(adminID, "sdk_key.rotate", "app", appID, r, map[string]any{"key_prefix": sdkKey.KeyPrefix})
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sdk_key": sdkKeyView(sdkKey), "sdk_secret": sdkSecret})
}

func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request, adminID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		licenses := append([]License(nil), s.data.Licenses...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"items": licenses})
	case http.MethodPost:
		var req struct {
			AppID        string   `json:"app_id"`
			PlanName     string   `json:"plan_name"`
			OwnerRef     string   `json:"owner_ref"`
			MaxDevices   int      `json:"max_devices"`
			ExpiresAt    string   `json:"expires_at"`
			Entitlements []string `json:"entitlements"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.AppID == "" {
			req.AppID = DemoAppID
		}
		if req.PlanName == "" {
			req.PlanName = "Pro"
		}
		s.mu.Lock()
		settings := s.settingsLocked()
		s.mu.Unlock()
		if req.MaxDevices <= 0 {
			req.MaxDevices = settings.DefaultMaxDevices
		}
		if len(req.Entitlements) == 0 {
			req.Entitlements = []string{"feature.pro", "export.enabled"}
		}
		expiresAt := time.Now().Add(time.Duration(settings.DefaultLicenseDays) * 24 * time.Hour)
		if req.ExpiresAt != "" {
			parsed, err := time.Parse("2006-01-02", req.ExpiresAt)
			if err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_EXPIRES_AT", "expires_at must be YYYY-MM-DD")
				return
			}
			expiresAt = parsed
		}
		key := generateLicenseKey()
		now := time.Now()
		lic := License{
			ID:               newID("lic"),
			LicenseKeyHash:   hashString(key),
			LicenseKeyPrefix: licensePrefix(key),
			AppID:            req.AppID,
			PlanName:         req.PlanName,
			OwnerType:        "user",
			OwnerRef:         req.OwnerRef,
			MaxDevices:       req.MaxDevices,
			Entitlements:     req.Entitlements,
			ExpiresAt:        expiresAt,
			Status:           "active",
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		s.mu.Lock()
		if s.findAppLocked(req.AppID) == nil {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
			return
		}
		s.data.Licenses = append(s.data.Licenses, lic)
		s.auditLocked(adminID, "license.create", "license", lic.ID, r, map[string]any{"app_id": req.AppID})
		err := s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"license": lic, "license_key": key})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (s *Server) handleLicenseAction(w http.ResponseWriter, r *http.Request, tail string, adminID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "license action not found")
		return
	}
	licenseID, action := parts[0], parts[1]
	if action != "revoke" && action != "suspend" && action != "resume" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "license action not found")
		return
	}

	s.mu.Lock()
	lic := s.findLicenseByIDLocked(licenseID)
	if lic == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "LICENSE_NOT_FOUND", "license not found")
		return
	}
	switch action {
	case "revoke":
		lic.Status = "revoked"
	case "suspend":
		lic.Status = "suspended"
	case "resume":
		lic.Status = "active"
	}
	lic.UpdatedAt = time.Now()
	for i := range s.data.Activations {
		if s.data.Activations[i].LicenseID == lic.ID && action == "revoke" {
			s.data.Activations[i].ActivationStatus = "blocked"
		}
	}
	s.auditLocked(adminID, "license."+action, "license", licenseID, r, nil)
	err := s.saveLocked()
	updated := *lic
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": updated})
}

func (s *Server) handleDevices(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"items": s.data.Devices})
}

func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request, tail string, adminID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "device action not found")
		return
	}
	deviceID, action := parts[0], parts[1]
	if action != "block" && action != "unblock" && action != "unbind" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "device action not found")
		return
	}

	s.mu.Lock()
	device := s.findDeviceByIDLocked(deviceID)
	if device == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
		return
	}
	now := time.Now()
	if action == "block" {
		device.Status = "blocked"
	} else if action == "unblock" {
		device.Status = "active"
	} else {
		for i := range s.data.Activations {
			if s.data.Activations[i].DeviceID == device.ID && s.data.Activations[i].ActivationStatus == "active" {
				s.data.Activations[i].ActivationStatus = "deactivated"
				s.data.Activations[i].DeactivatedAt = &now
				s.data.Activations[i].LastVerifiedAt = now
			}
		}
	}
	device.LastSeenAt = now
	s.auditLocked(adminID, "device."+action, "device", deviceID, r, nil)
	err := s.saveLocked()
	copy := *device
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": copy})
}

func (s *Server) handleRiskEvents(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	events := append([]RiskEvent(nil), s.data.RiskEvents...)
	s.mu.Unlock()
	sort.Slice(events, func(i, j int) bool { return events[i].CreatedAt.After(events[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) handleRiskEventAction(w http.ResponseWriter, r *http.Request, tail string, adminID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 2 || parts[1] != "resolve" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "risk event action not found")
		return
	}

	eventID := parts[0]
	s.mu.Lock()
	event := s.findRiskEventByIDLocked(eventID)
	if event == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "RISK_EVENT_NOT_FOUND", "risk event not found")
		return
	}
	if event.ResolvedAt == nil {
		now := time.Now()
		event.ResolvedAt = &now
		s.auditLocked(adminID, "risk.resolve", "risk_event", eventID, r, map[string]any{"event_type": event.EventType})
	}
	err := s.saveLocked()
	copy := *event
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"risk_event": copy})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	logs := append([]AuditLog(nil), s.data.AuditLogs...)
	s.mu.Unlock()
	sort.Slice(logs, func(i, j int) bool { return logs[i].CreatedAt.After(logs[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"items": logs})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, adminID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		settings := s.settingsLocked()
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"settings": settings})
	case http.MethodPatch:
		var req struct {
			DefaultTokenTTLMinutes    *int  `json:"default_token_ttl_minutes"`
			MediumRiskTokenTTLMinutes *int  `json:"medium_risk_token_ttl_minutes"`
			OfflineGraceDays          *int  `json:"offline_grace_days"`
			DefaultMaxDevices         *int  `json:"default_max_devices"`
			DefaultLicenseDays        *int  `json:"default_license_days"`
			AuditLogRetentionDays     *int  `json:"audit_log_retention_days"`
			MFARequired               *bool `json:"mfa_required"`
			SensitiveActionConfirm    *bool `json:"sensitive_action_confirm"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}

		s.mu.Lock()
		settings := s.settingsLocked()
		if req.DefaultTokenTTLMinutes != nil {
			settings.DefaultTokenTTLMinutes = *req.DefaultTokenTTLMinutes
		}
		if req.MediumRiskTokenTTLMinutes != nil {
			settings.MediumRiskTokenTTLMinutes = *req.MediumRiskTokenTTLMinutes
		}
		if req.OfflineGraceDays != nil {
			settings.OfflineGraceDays = *req.OfflineGraceDays
		}
		if req.DefaultMaxDevices != nil {
			settings.DefaultMaxDevices = *req.DefaultMaxDevices
		}
		if req.DefaultLicenseDays != nil {
			settings.DefaultLicenseDays = *req.DefaultLicenseDays
		}
		if req.AuditLogRetentionDays != nil {
			settings.AuditLogRetentionDays = *req.AuditLogRetentionDays
		}
		if req.MFARequired != nil {
			settings.MFARequired = *req.MFARequired
		}
		if req.SensitiveActionConfirm != nil {
			settings.SensitiveActionConfirm = *req.SensitiveActionConfirm
		}
		settings.UpdatedAt = time.Now()
		settings = normalizeSystemSettings(settings, settings.UpdatedAt)
		s.data.Settings = settings
		s.auditLocked(adminID, "settings.update", "settings", "system", r, nil)
		err := s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"settings": settings})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID      string `json:"app_id"`
		Platform   string `json:"platform"`
		InstallID  string `json:"install_id"`
		AppVersion string `json:"app_version"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.AppID == "" || req.InstallID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "app_id and install_id are required")
		return
	}

	now := time.Now()
	challenge := Challenge{
		ID:        newID("chg"),
		Nonce:     randomString(32),
		AppID:     req.AppID,
		InstallID: req.InstallID,
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}

	s.mu.Lock()
	if s.findAppLocked(req.AppID) == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "APP_NOT_FOUND", "app not found")
		return
	}
	s.challenges[challenge.ID] = challenge
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challenge.ID,
		"nonce":        challenge.Nonce,
		"expires_at":   challenge.ExpiresAt,
		"server_time":  now,
	})
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID       string           `json:"app_id"`
		Platform    string           `json:"platform"`
		LicenseKey  string           `json:"license_key"`
		ChallengeID string           `json:"challenge_id"`
		Nonce       string           `json:"nonce"`
		Device      DeviceInfo       `json:"device"`
		Integrity   IntegrityRequest `json:"integrity"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Platform == "" {
		req.Platform = "windows"
	}
	s.processClientVerification(w, r, clientVerificationInput{
		AppID:        req.AppID,
		Platform:     req.Platform,
		LicenseKey:   req.LicenseKey,
		ChallengeID:  req.ChallengeID,
		Nonce:        req.Nonce,
		Device:       req.Device,
		Integrity:    req.Integrity,
		IsActivation: true,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID        string           `json:"app_id"`
		Platform     string           `json:"platform"`
		LicenseKey   string           `json:"license_key"`
		LicenseToken string           `json:"license_token"`
		ChallengeID  string           `json:"challenge_id"`
		Nonce        string           `json:"nonce"`
		Device       DeviceInfo       `json:"device"`
		Integrity    IntegrityRequest `json:"integrity"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Platform == "" {
		req.Platform = "windows"
	}
	s.processClientVerification(w, r, clientVerificationInput{
		AppID:        req.AppID,
		Platform:     req.Platform,
		LicenseKey:   req.LicenseKey,
		LicenseToken: req.LicenseToken,
		ChallengeID:  req.ChallengeID,
		Nonce:        req.Nonce,
		Device:       req.Device,
		Integrity:    req.Integrity,
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID        string `json:"app_id"`
		LicenseToken string `json:"license_token"`
		InstallID    string `json:"install_id"`
		AppVersion   string `json:"app_version"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	claims, err := VerifyLicenseToken(s.publicKey, req.LicenseToken, false)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", err.Error())
		return
	}
	if req.AppID != "" && claims.AppID != req.AppID {
		writeError(w, http.StatusForbidden, "APP_MISMATCH", "token app does not match request app")
		return
	}

	s.mu.Lock()
	activation := s.findActivationLocked(claims.LicenseID, claims.DeviceID)
	if activation != nil {
		activation.LastVerifiedAt = time.Now()
	}
	device := s.findDeviceByIDLocked(claims.DeviceID)
	if device != nil {
		if req.InstallID != "" && device.InstallIDHash != hashString(req.InstallID) {
			s.addRiskEventLocked(claims.AppID, device.ID, claims.LicenseID, "token_device_mismatch", "high", "deny", "心跳 token 与 install_id 不匹配", nil)
			err = s.saveLocked()
			s.mu.Unlock()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
				return
			}
			writeError(w, http.StatusForbidden, "TOKEN_DEVICE_MISMATCH", "授权 token 与当前设备不匹配")
			return
		}
		device.LastSeenAt = time.Now()
	}
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "server_time": time.Now()})
}

func (s *Server) handleDeactivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID        string `json:"app_id"`
		LicenseToken string `json:"license_token"`
		InstallID    string `json:"install_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	claims, err := VerifyLicenseToken(s.publicKey, req.LicenseToken, false)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", err.Error())
		return
	}
	if req.AppID != "" && claims.AppID != req.AppID {
		writeError(w, http.StatusForbidden, "APP_MISMATCH", "token app does not match request app")
		return
	}

	now := time.Now()
	s.mu.Lock()
	device := s.findDeviceByIDLocked(claims.DeviceID)
	if device != nil && req.InstallID != "" && device.InstallIDHash != hashString(req.InstallID) {
		s.addRiskEventLocked(claims.AppID, device.ID, claims.LicenseID, "token_device_mismatch", "high", "deny", "deactivate token 与 install_id 不匹配", nil)
		err = s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
			return
		}
		writeError(w, http.StatusForbidden, "TOKEN_DEVICE_MISMATCH", "授权 token 与当前设备不匹配")
		return
	}

	deactivated := false
	activation := s.findActivationLocked(claims.LicenseID, claims.DeviceID)
	if activation != nil && activation.ActivationStatus != "deactivated" {
		activation.ActivationStatus = "deactivated"
		activation.LastVerifiedAt = now
		activation.DeactivatedAt = &now
		deactivated = true
	}
	if device != nil {
		device.LastSeenAt = now
	}
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deactivated": deactivated, "server_time": now})
}

type clientVerificationInput struct {
	AppID        string
	Platform     string
	LicenseKey   string
	LicenseToken string
	ChallengeID  string
	Nonce        string
	Device       DeviceInfo
	Integrity    IntegrityRequest
	IsActivation bool
}

func (s *Server) processClientVerification(w http.ResponseWriter, r *http.Request, input clientVerificationInput) {
	if input.AppID == "" || input.ChallengeID == "" || input.Nonce == "" || input.Device.InstallID == "" || input.Device.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "app_id, challenge, nonce and device identifiers are required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateChallengeLocked(input.AppID, input.Device.InstallID, input.ChallengeID, input.Nonce); err != nil {
		writeDenied(w, "CHALLENGE_INVALID", err.Error(), RiskResult{Level: "medium", Score: 50, Actions: []string{"deny"}})
		return
	}
	app := s.findAppLocked(input.AppID)
	if app == nil || app.Status != "active" {
		writeDenied(w, "APP_NOT_ACTIVE", "应用不存在或已停用", RiskResult{Level: "high", Score: 90, Actions: []string{"deny"}})
		return
	}

	var lic *License
	var tokenClaims *LicenseTokenClaims
	if input.LicenseKey != "" {
		lic = s.findLicenseByKeyLocked(input.LicenseKey)
	} else if input.LicenseToken != "" {
		claims, err := VerifyLicenseToken(s.publicKey, input.LicenseToken, true)
		if err != nil {
			writeDenied(w, "INVALID_TOKEN", "授权 token 无效", RiskResult{Level: "medium", Score: 55, Actions: []string{"deny"}})
			return
		}
		tokenClaims = claims
		lic = s.findLicenseByIDLocked(claims.LicenseID)
	} else {
		writeDenied(w, "LICENSE_REQUIRED", "需要 license_key 或 license_token", RiskResult{Level: "medium", Score: 55, Actions: []string{"deny"}})
		return
	}

	if lic == nil || lic.AppID != app.AppKey {
		writeDenied(w, "INVALID_LICENSE", "授权不存在或不属于当前应用", RiskResult{Level: "high", Score: 82, Actions: []string{"deny"}})
		return
	}
	if lic.Status != "active" {
		writeDenied(w, "LICENSE_"+strings.ToUpper(lic.Status), "授权不可用", RiskResult{Level: "high", Score: 85, Actions: []string{"deny"}})
		return
	}
	if time.Now().After(lic.ExpiresAt) {
		lic.Status = "expired"
		_ = s.saveLocked()
		writeDenied(w, "LICENSE_EXPIRED", "授权已过期", RiskResult{Level: "medium", Score: 65, Actions: []string{"deny"}})
		return
	}
	if tokenClaims != nil && tokenClaims.AppID != app.AppKey {
		s.addRiskEventLocked(app.AppKey, "", lic.ID, "token_app_mismatch", "high", "deny", "授权 token 不属于当前应用", map[string]any{"token_app_id": tokenClaims.AppID})
		_ = s.saveLocked()
		writeDenied(w, "TOKEN_APP_MISMATCH", "授权 token 不属于当前应用", RiskResult{Level: "high", Score: 92, Actions: []string{"deny"}})
		return
	}

	device := s.findOrCreateDeviceLocked(input)
	if device.Status == "blocked" {
		s.addRiskEventLocked(app.AppKey, device.ID, lic.ID, "device_blocked", "high", "deny", "设备已被后台封禁", nil)
		_ = s.saveLocked()
		writeDenied(w, "DEVICE_BLOCKED", "设备已封禁", RiskResult{Level: "high", Score: 90, Actions: []string{"deny"}})
		return
	}
	if tokenClaims != nil && tokenClaims.DeviceID != device.ID {
		s.addRiskEventLocked(app.AppKey, device.ID, lic.ID, "token_device_mismatch", "high", "deny", "授权 token 与当前设备不匹配", map[string]any{"token_device_id": tokenClaims.DeviceID})
		_ = s.saveLocked()
		writeDenied(w, "TOKEN_DEVICE_MISMATCH", "授权 token 与当前设备不匹配", RiskResult{Level: "high", Score: 92, Actions: []string{"deny"}})
		return
	}

	activation := s.findActivationLocked(lic.ID, device.ID)
	if tokenClaims != nil && (activation == nil || activation.ActivationStatus != "active") {
		s.addRiskEventLocked(app.AppKey, device.ID, lic.ID, "token_activation_inactive", "medium", "deny", "授权 token 对应的激活已停用", nil)
		_ = s.saveLocked()
		writeDenied(w, "TOKEN_DEACTIVATED", "授权 token 已停用，请重新激活", RiskResult{Level: "medium", Score: 60, Actions: []string{"deny"}})
		return
	}
	if activation == nil {
		activeCount := s.activeDeviceCountLocked(lic.ID)
		if activeCount >= lic.MaxDevices {
			s.addRiskEventLocked(app.AppKey, device.ID, lic.ID, "device_limit_exceeded", "medium", "deny", "授权绑定设备数已达到上限", map[string]any{"max_devices": lic.MaxDevices})
			_ = s.saveLocked()
			writeDenied(w, "DEVICE_LIMIT_EXCEEDED", "授权绑定设备数已达到上限", RiskResult{Level: "medium", Score: 58, Actions: []string{"review"}})
			return
		}
		now := time.Now()
		s.data.Activations = append(s.data.Activations, Activation{
			ID:               newID("act"),
			LicenseID:        lic.ID,
			DeviceID:         device.ID,
			AppID:            app.AppKey,
			ActivationStatus: "active",
			ActivatedAt:      now,
			LastVerifiedAt:   now,
		})
	} else {
		activation.ActivationStatus = "active"
		activation.LastVerifiedAt = time.Now()
	}

	risk, release, deny := s.evaluateIntegrityLocked(app.AppKey, device.ID, lic.ID, input)
	device.RiskScore = risk.Score
	device.LastSeenAt = time.Now()

	report := IntegrityReport{
		ID:                newID("ir"),
		AppID:             app.AppKey,
		DeviceID:          device.ID,
		Platform:          input.Platform,
		AppVersion:        input.Integrity.AppVersion,
		MainBinaryHash:    input.Integrity.MainBinaryHash,
		SignerThumbprint:  input.Integrity.SignerThumbprint,
		DebuggerDetected:  input.Integrity.DebuggerDetected,
		SuspiciousModules: input.Integrity.SuspiciousModules,
		VMIndicators:      input.Integrity.VMIndicators,
		CreatedAt:         time.Now(),
	}
	if release != nil {
		report.ReleaseID = release.ID
	}
	s.data.IntegrityReports = append(s.data.IntegrityReports, report)

	if deny {
		_ = s.saveLocked()
		writeDenied(w, "INTEGRITY_FAILED", "完整性验证失败", risk)
		return
	}

	settings := s.settingsLocked()
	tokenTTL := time.Duration(settings.DefaultTokenTTLMinutes) * time.Minute
	if risk.Level == "medium" {
		tokenTTL = time.Duration(settings.MediumRiskTokenTTLMinutes) * time.Minute
	}
	expiresAt := time.Now().Add(tokenTTL)
	graceUntil := time.Now().Add(time.Duration(settings.OfflineGraceDays) * 24 * time.Hour)
	token, err := SignLicenseToken(s.privateKey, LicenseTokenClaims{
		Iss:               "license-guard",
		AppID:             app.AppKey,
		LicenseID:         lic.ID,
		DeviceID:          device.ID,
		Entitlements:      lic.Entitlements,
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         expiresAt.Unix(),
		OfflineGraceUntil: graceUntil.Unix(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_SIGN_FAILED", err.Error())
		return
	}

	err = s.saveLocked()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, VerifyResponse{
		Allowed:           true,
		LicenseToken:      token,
		ExpiresAt:         &expiresAt,
		OfflineGraceUntil: &graceUntil,
		Entitlements:      lic.Entitlements,
		DeviceStatus:      device.Status,
		Risk:              risk,
		Update:            s.updateInfoLocked(app.AppKey, input.Platform, input.Integrity.AppVersion, device.ID),
	})
}

func (s *Server) evaluateIntegrityLocked(appID string, deviceID string, licenseID string, input clientVerificationInput) (RiskResult, *AppRelease, bool) {
	score := 10
	deny := false
	actions := []string{}
	var exactRelease *AppRelease

	if input.Integrity.AppVersion != "" {
		exactRelease = s.findReleaseLocked(appID, input.Platform, input.Integrity.AppVersion)
		if exactRelease == nil {
			score += 20
			actions = append(actions, "review")
			s.addRiskEventLocked(appID, deviceID, licenseID, "unknown_app_version", "medium", "review", "客户端版本未在后台登记", map[string]any{"version": input.Integrity.AppVersion})
		} else {
			if exactRelease.Status == "blocked" {
				score += 85
				deny = true
				actions = append(actions, "deny")
				s.addRiskEventLocked(appID, deviceID, licenseID, "app_version_blocked", "high", "deny", "当前版本已被后台阻止", map[string]any{"version": input.Integrity.AppVersion})
			}
			if exactRelease.Status == "deprecated" {
				score += 35
				actions = append(actions, "shorten_token_ttl", "update_recommended")
				s.addRiskEventLocked(appID, deviceID, licenseID, "app_version_deprecated", "medium", "challenge", "当前版本已标记为过时", map[string]any{"version": input.Integrity.AppVersion})
			}
			if exactRelease.MainBinaryHash != "" && input.Integrity.MainBinaryHash != "" && !strings.EqualFold(exactRelease.MainBinaryHash, input.Integrity.MainBinaryHash) {
				score += 90
				deny = true
				actions = append(actions, "deny")
				s.addRiskEventLocked(appID, deviceID, licenseID, "binary_hash_mismatch", "high", "deny", "主程序 hash 与发布版本不匹配", map[string]any{"expected": exactRelease.MainBinaryHash, "actual": input.Integrity.MainBinaryHash})
			}
			if exactRelease.SignerThumbprint != "" && input.Integrity.SignerThumbprint != "" && !strings.EqualFold(exactRelease.SignerThumbprint, input.Integrity.SignerThumbprint) {
				score += 80
				deny = true
				actions = append(actions, "deny")
				s.addRiskEventLocked(appID, deviceID, licenseID, "signature_mismatch", "high", "deny", "签名证书指纹不匹配", map[string]any{"expected": exactRelease.SignerThumbprint, "actual": input.Integrity.SignerThumbprint})
			}
		}
	}
	if input.Integrity.DebuggerDetected {
		score += 40
		actions = append(actions, "shorten_token_ttl")
		s.addRiskEventLocked(appID, deviceID, licenseID, "debugger_detected", "medium", "challenge", "检测到调试器", nil)
	}
	if len(input.Integrity.SuspiciousModules) > 0 {
		score += 20 + len(input.Integrity.SuspiciousModules)*8
		actions = append(actions, "review")
		s.addRiskEventLocked(appID, deviceID, licenseID, "suspicious_module_loaded", "medium", "review", "检测到可疑模块", map[string]any{"modules": input.Integrity.SuspiciousModules})
	}
	if len(input.Integrity.VMIndicators) > 0 {
		score += 12
		actions = append(actions, "log")
		s.addRiskEventLocked(appID, deviceID, licenseID, "vm_indicator", "low", "allow", "检测到虚拟化环境信号", map[string]any{"indicators": input.Integrity.VMIndicators})
	}
	if score > 100 {
		score = 100
	}

	level := "low"
	if score >= 80 {
		level = "high"
	} else if score >= 45 {
		level = "medium"
	}
	if len(actions) == 0 {
		actions = []string{"allow"}
	}

	return RiskResult{Level: level, Score: score, Actions: uniqueStrings(actions)}, exactRelease, deny
}

func (s *Server) updateInfoLocked(appID string, platform string, currentVersion string, deviceID string) *UpdateInfo {
	if currentVersion == "" {
		return nil
	}
	latest := s.latestReleaseLocked(appID, platform)
	if latest == nil || latest.Version == "" || latest.Version == currentVersion {
		return nil
	}
	required := latest.Mandatory || s.isBelowMinSupportedLocked(appID, platform, currentVersion, latest.MinSupportedVersion)
	if !required && !releaseInRollout(appID, platform, latest.ID, deviceID, latest.RolloutPercent) {
		return nil
	}
	return &UpdateInfo{
		Available:     true,
		Required:      required,
		LatestVersion: latest.Version,
		DownloadURL:   latest.DownloadURL,
		PackageSHA256: latest.PackageSHA256,
		ReleaseNotes:  latest.ReleaseNotes,
	}
}

func (s *Server) isBelowMinSupportedLocked(appID string, platform string, currentVersion string, minSupportedVersion string) bool {
	if minSupportedVersion == "" {
		return false
	}
	current := s.findReleaseLocked(appID, platform, currentVersion)
	minimum := s.findReleaseLocked(appID, platform, minSupportedVersion)
	if current != nil && minimum != nil && current.BuildNumber != 0 && minimum.BuildNumber != 0 {
		return current.BuildNumber < minimum.BuildNumber
	}
	return compareVersionStrings(currentVersion, minSupportedVersion) < 0
}

func (s *Server) validateChallengeLocked(appID string, installID string, challengeID string, nonce string) error {
	challenge, ok := s.challenges[challengeID]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	delete(s.challenges, challengeID)
	if time.Now().After(challenge.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if challenge.AppID != appID || challenge.InstallID != installID || challenge.Nonce != nonce {
		return fmt.Errorf("challenge fields do not match request")
	}
	return nil
}

func (s *Server) findOrCreateDeviceLocked(input clientVerificationInput) *Device {
	fingerprintHash := hashString(input.Device.Fingerprint)
	if existing := s.findDeviceByFingerprintLocked(fingerprintHash); existing != nil {
		existing.OSVersion = input.Device.OSVersion
		existing.MachineNameHash = hashString(input.Device.MachineNameHash)
		existing.LastSeenAt = time.Now()
		return existing
	}
	now := time.Now()
	device := Device{
		ID:                    newID("dev"),
		DeviceFingerprintHash: fingerprintHash,
		InstallIDHash:         hashString(input.Device.InstallID),
		Platform:              input.Platform,
		OSVersion:             input.Device.OSVersion,
		MachineNameHash:       hashString(input.Device.MachineNameHash),
		RiskScore:             10,
		Status:                "active",
		FirstSeenAt:           now,
		LastSeenAt:            now,
	}
	s.data.Devices = append(s.data.Devices, device)
	return &s.data.Devices[len(s.data.Devices)-1]
}

func (s *Server) loadOrSeed() error {
	data, err := s.store.Load()
	if err == nil {
		s.data = data
		return s.ensureLoadedDefaults()
	}
	if !errors.Is(err, ErrStoreNotFound) {
		return err
	}

	now := time.Now()
	demoAdmin, err := newPasswordAdmin("admin_demo", DemoAdminAccount, "Demo Admin", DemoAdminPass, now)
	if err != nil {
		return err
	}
	sdkKey, _ := newSDKKey(DemoAppID, s.publicKeyString(), now, false)
	s.data = Data{
		Settings: defaultSystemSettings(now),
		Admins:   []Admin{demoAdmin},
		Apps: []App{{
			ID:          "app_demo_nax",
			AppKey:      DemoAppID,
			Name:        "Nax Desktop",
			Description: "Windows Go demo application",
			OwnerTeam:   "Core",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}},
		Releases: []AppRelease{{
			ID:               "rel_demo_nax_142",
			AppID:            DemoAppID,
			Platform:         "windows",
			Version:          "1.4.2",
			BuildNumber:      10402,
			Channel:          "production",
			Status:           "active",
			SignerThumbprint: DemoSigner,
			MainBinaryHash:   DemoBinaryHash,
			DownloadURL:      "https://download.example.com/nax-desktop/1.4.2/setup.exe",
			PackageSHA256:    "demo-package-sha256",
			RolloutPercent:   100,
			ReleaseNotes:     "Seed release for local Windows Go integration.",
			CreatedAt:        now,
		}},
		SDKKeys: []SDKKey{sdkKey},
		Licenses: []License{{
			ID:               "lic_demo_windows",
			LicenseKeyHash:   hashString(DemoLicenseKey),
			LicenseKeyPrefix: licensePrefix(DemoLicenseKey),
			AppID:            DemoAppID,
			PlanName:         "Pro",
			OwnerType:        "user",
			OwnerRef:         "demo-customer",
			MaxDevices:       3,
			Entitlements:     []string{"feature.pro", "export.enabled"},
			ExpiresAt:        now.Add(365 * 24 * time.Hour),
			Status:           "active",
			CreatedAt:        now,
			UpdatedAt:        now,
		}},
	}
	return s.saveLocked()
}

func (s *Server) ensureLoadedDefaults() error {
	now := time.Now()
	changed := false
	settings := normalizeSystemSettings(s.data.Settings, now)
	if s.data.Settings != settings {
		s.data.Settings = settings
		changed = true
	}
	for _, app := range s.data.Apps {
		activeKey := s.activeSDKKeyForAppLocked(app.AppKey)
		if activeKey == nil {
			sdkKey, _ := newSDKKey(app.AppKey, s.publicKeyString(), now, false)
			s.data.SDKKeys = append(s.data.SDKKeys, sdkKey)
			changed = true
			continue
		}
		if activeKey.PublicKey != s.publicKeyString() {
			activeKey.PublicKey = s.publicKeyString()
			changed = true
		}
	}
	if len(s.data.Admins) > 0 {
		if changed {
			return s.saveLocked()
		}
		return nil
	}
	admin, err := newPasswordAdmin("admin_demo", DemoAdminAccount, "Demo Admin", DemoAdminPass, now)
	if err != nil {
		return err
	}
	s.data.Admins = append(s.data.Admins, admin)
	changed = true
	if !changed {
		return nil
	}
	return s.saveLocked()
}

func newPasswordAdmin(id string, account string, name string, password string, now time.Time) (Admin, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return Admin{}, err
	}
	return Admin{
		ID:           id,
		Account:      strings.ToLower(strings.TrimSpace(account)),
		Name:         name,
		PasswordHash: string(hash),
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func newSDKKey(appID string, publicKey string, now time.Time, rotated bool) (SDKKey, string) {
	secret := "lgsk_" + randomString(32)
	key := SDKKey{
		ID:         newID("sdk"),
		AppID:      appID,
		PublicKey:  publicKey,
		SecretHash: hashString(secret),
		KeyPrefix:  sdkKeyPrefix(secret),
		Status:     "active",
		CreatedAt:  now,
	}
	if rotated {
		key.RotatedAt = &now
	}
	return key, secret
}

func sdkKeyView(key SDKKey) SDKKeyView {
	return SDKKeyView{
		ID:         key.ID,
		AppID:      key.AppID,
		PublicKey:  key.PublicKey,
		KeyPrefix:  key.KeyPrefix,
		Status:     key.Status,
		LastUsedAt: key.LastUsedAt,
		CreatedAt:  key.CreatedAt,
		RotatedAt:  key.RotatedAt,
	}
}

func sdkKeyPrefix(secret string) string {
	if len(secret) <= 16 {
		return secret
	}
	return secret[:16]
}

func (s *Server) saveLocked() error {
	return s.store.Save(s.data)
}

func (s *Server) settingsLocked() SystemSettings {
	return normalizeSystemSettings(s.data.Settings, time.Now())
}

func defaultSystemSettings(now time.Time) SystemSettings {
	return SystemSettings{
		DefaultTokenTTLMinutes:    12 * 60,
		MediumRiskTokenTTLMinutes: 30,
		OfflineGraceDays:          7,
		DefaultMaxDevices:         3,
		DefaultLicenseDays:        365,
		AuditLogRetentionDays:     365,
		MFARequired:               false,
		SensitiveActionConfirm:    false,
		UpdatedAt:                 now,
	}
}

func normalizeSystemSettings(settings SystemSettings, now time.Time) SystemSettings {
	defaults := defaultSystemSettings(now)
	if settings.DefaultTokenTTLMinutes <= 0 {
		settings.DefaultTokenTTLMinutes = defaults.DefaultTokenTTLMinutes
	}
	if settings.MediumRiskTokenTTLMinutes <= 0 {
		settings.MediumRiskTokenTTLMinutes = defaults.MediumRiskTokenTTLMinutes
	}
	if settings.OfflineGraceDays < 0 {
		settings.OfflineGraceDays = defaults.OfflineGraceDays
	}
	if settings.DefaultMaxDevices <= 0 {
		settings.DefaultMaxDevices = defaults.DefaultMaxDevices
	}
	if settings.DefaultLicenseDays <= 0 {
		settings.DefaultLicenseDays = defaults.DefaultLicenseDays
	}
	if settings.AuditLogRetentionDays <= 0 {
		settings.AuditLogRetentionDays = defaults.AuditLogRetentionDays
	}
	if settings.UpdatedAt.IsZero() {
		settings.UpdatedAt = now
	}

	settings.DefaultTokenTTLMinutes = clampInt(settings.DefaultTokenTTLMinutes, 5, 30*24*60)
	settings.MediumRiskTokenTTLMinutes = clampInt(settings.MediumRiskTokenTTLMinutes, 5, settings.DefaultTokenTTLMinutes)
	settings.OfflineGraceDays = clampInt(settings.OfflineGraceDays, 0, 30)
	settings.DefaultMaxDevices = clampInt(settings.DefaultMaxDevices, 1, 1000)
	settings.DefaultLicenseDays = clampInt(settings.DefaultLicenseDays, 1, 3650)
	settings.AuditLogRetentionDays = clampInt(settings.AuditLogRetentionDays, 7, 3650)
	return settings
}

func (s *Server) findAdminByAccountLocked(account string) *Admin {
	account = strings.ToLower(strings.TrimSpace(account))
	for i := range s.data.Admins {
		if strings.EqualFold(s.data.Admins[i].Account, account) {
			return &s.data.Admins[i]
		}
	}
	return nil
}

func (s *Server) findAdminByIDLocked(id string) *Admin {
	for i := range s.data.Admins {
		if s.data.Admins[i].ID == id {
			return &s.data.Admins[i]
		}
	}
	return nil
}

func (s *Server) invalidateAdminSessionsExceptLocked(adminID string, keepToken string) {
	for token, session := range s.adminSessions {
		if session.AdminID == adminID && token != keepToken {
			delete(s.adminSessions, token)
		}
	}
}

func (s *Server) findAppLocked(appID string) *App {
	for i := range s.data.Apps {
		if s.data.Apps[i].AppKey == appID || s.data.Apps[i].ID == appID {
			return &s.data.Apps[i]
		}
	}
	return nil
}

func (s *Server) releasesForAppLocked(appID string) []AppRelease {
	var releases []AppRelease
	for _, release := range s.data.Releases {
		if release.AppID == appID {
			releases = append(releases, release)
		}
	}
	return releases
}

func (s *Server) sdkKeyViewsForAppLocked(appID string) []SDKKeyView {
	var keys []SDKKeyView
	for _, key := range s.data.SDKKeys {
		if key.AppID == appID {
			keys = append(keys, sdkKeyView(key))
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].CreatedAt.After(keys[j].CreatedAt)
	})
	return keys
}

func (s *Server) onboardingResponseLocked(app App) OnboardingResponse {
	now := time.Now()
	releases := s.releasesForAppLocked(app.AppKey)
	licenses := s.licensesForAppLocked(app.AppKey)
	activeSDKKey := s.activeSDKKeyForAppLocked(app.AppKey)
	latestRelease := latestReleaseFromItems(releases)
	latestDevice := s.latestDeviceForAppLocked(app.AppKey)
	latestReport := s.latestIntegrityReportForAppLocked(app.AppKey)
	latestRisk := s.latestRiskEventForAppLocked(app.AppKey)
	settings := s.settingsLocked()

	hasRelease := len(releases) > 0
	hasLicense := len(licenses) > 0
	hasActiveSDKKey := activeSDKKey != nil
	hasActivation := s.hasActivationForAppLocked(app.AppKey)
	hasHeartbeat := latestDevice != nil && latestDevice.LastSeenAt.After(now.Add(-30*time.Minute))
	hasIntegrity := latestReport != nil
	hasRisk := latestRisk != nil

	steps := []OnboardingStep{
		{ID: "app_created", Label: "创建 App", Status: passedStatus(app.AppKey != ""), Source: "server", Evidence: map[string]any{"app_id": app.AppKey}},
		{ID: "release_created", Label: "发布版本", Status: passedStatus(hasRelease), Source: "server", Evidence: releaseEvidence(latestRelease)},
		{ID: "license_issued", Label: "签发 License", Status: passedStatus(hasLicense), Source: "server", Evidence: map[string]any{"license_count": len(licenses)}},
		{ID: "sdk_key_active", Label: "配置 SDK Key", Status: passedStatus(hasActiveSDKKey), Source: "server", Evidence: sdkKeyEvidence(activeSDKKey)},
		{ID: "app_config", Label: "改造 App 配置", Status: "manual", Source: "client"},
		{ID: "first_activation", Label: "接入首次激活", Status: currentOrPassedStatus(hasActivation), Source: "server", Evidence: map[string]any{"activation_count": s.activationCountForAppLocked(app.AppKey)}},
		{ID: "local_verify", Label: "接入本地验签", Status: "manual", Source: "client"},
		{ID: "online_verify", Label: "接入在线 verify", Status: currentOrPassedStatus(hasIntegrity), Source: "server", Evidence: integrityEvidence(latestReport)},
		{ID: "heartbeat", Label: "接入 heartbeat", Status: currentOrPassedStatus(hasHeartbeat), Source: "server", Evidence: deviceEvidence(latestDevice)},
		{ID: "entitlements", Label: "接入 entitlements", Status: "manual", Source: "client"},
		{ID: "integrity_report", Label: "接入完整性上报", Status: currentOrPassedStatus(hasIntegrity), Source: "server", Evidence: integrityEvidence(latestReport)},
		{ID: "risk_drill", Label: "演练错误场景", Status: currentOrPassedStatus(hasRisk), Source: "server", Evidence: riskEvidence(latestRisk)},
	}

	return OnboardingResponse{
		AppID:                 app.AppKey,
		App:                   app,
		HasActiveSDKKey:       hasActiveSDKKey,
		HasRelease:            hasRelease,
		HasLicense:            hasLicense,
		LatestRelease:         latestRelease,
		LatestDevice:          latestDevice,
		LatestIntegrityReport: latestReport,
		LatestRiskEvent:       latestRisk,
		OfflineGraceDays:      settings.OfflineGraceDays,
		Steps:                 steps,
		GeneratedAt:           now,
	}
}

func (s *Server) latestDeviceForAppLocked(appID string) *Device {
	knownDeviceIDs := map[string]bool{}
	for _, activation := range s.data.Activations {
		if activation.AppID == appID {
			knownDeviceIDs[activation.DeviceID] = true
		}
	}
	for _, report := range s.data.IntegrityReports {
		if report.AppID == appID {
			knownDeviceIDs[report.DeviceID] = true
		}
	}
	var latest *Device
	for i := range s.data.Devices {
		device := &s.data.Devices[i]
		if !knownDeviceIDs[device.ID] {
			continue
		}
		if latest == nil || device.LastSeenAt.After(latest.LastSeenAt) {
			latest = device
		}
	}
	if latest == nil {
		return nil
	}
	copy := *latest
	return &copy
}

func (s *Server) latestIntegrityReportForAppLocked(appID string) *IntegrityReport {
	var latest *IntegrityReport
	for i := range s.data.IntegrityReports {
		report := &s.data.IntegrityReports[i]
		if report.AppID != appID {
			continue
		}
		if latest == nil || report.CreatedAt.After(latest.CreatedAt) {
			latest = report
		}
	}
	if latest == nil {
		return nil
	}
	copy := *latest
	return &copy
}

func (s *Server) latestRiskEventForAppLocked(appID string) *RiskEvent {
	var latest *RiskEvent
	for i := range s.data.RiskEvents {
		event := &s.data.RiskEvents[i]
		if event.AppID != appID {
			continue
		}
		if latest == nil || event.CreatedAt.After(latest.CreatedAt) {
			latest = event
		}
	}
	if latest == nil {
		return nil
	}
	copy := *latest
	return &copy
}

func (s *Server) hasActivationForAppLocked(appID string) bool {
	return s.activationCountForAppLocked(appID) > 0
}

func (s *Server) activationCountForAppLocked(appID string) int {
	count := 0
	for _, activation := range s.data.Activations {
		if activation.AppID == appID {
			count++
		}
	}
	return count
}

func (s *Server) licensesForAppLocked(appID string) []License {
	var licenses []License
	for _, lic := range s.data.Licenses {
		if lic.AppID == appID {
			licenses = append(licenses, lic)
		}
	}
	return licenses
}

func (s *Server) findLicenseByKeyLocked(key string) *License {
	hash := hashString(key)
	for i := range s.data.Licenses {
		if s.data.Licenses[i].LicenseKeyHash == hash {
			return &s.data.Licenses[i]
		}
	}
	return nil
}

func (s *Server) findLicenseByIDLocked(id string) *License {
	for i := range s.data.Licenses {
		if s.data.Licenses[i].ID == id {
			return &s.data.Licenses[i]
		}
	}
	return nil
}

func (s *Server) activeSDKKeyForAppLocked(appID string) *SDKKey {
	for i := range s.data.SDKKeys {
		if s.data.SDKKeys[i].AppID == appID && s.data.SDKKeys[i].Status == "active" {
			return &s.data.SDKKeys[i]
		}
	}
	return nil
}

func (s *Server) findDeviceByFingerprintLocked(fingerprintHash string) *Device {
	for i := range s.data.Devices {
		if s.data.Devices[i].DeviceFingerprintHash == fingerprintHash {
			return &s.data.Devices[i]
		}
	}
	return nil
}

func (s *Server) findDeviceByIDLocked(id string) *Device {
	for i := range s.data.Devices {
		if s.data.Devices[i].ID == id {
			return &s.data.Devices[i]
		}
	}
	return nil
}

func (s *Server) findActivationLocked(licenseID string, deviceID string) *Activation {
	for i := range s.data.Activations {
		if s.data.Activations[i].LicenseID == licenseID && s.data.Activations[i].DeviceID == deviceID {
			return &s.data.Activations[i]
		}
	}
	return nil
}

func (s *Server) activeDeviceCountLocked(licenseID string) int {
	seen := map[string]bool{}
	for _, activation := range s.data.Activations {
		if activation.LicenseID == licenseID && activation.ActivationStatus == "active" {
			seen[activation.DeviceID] = true
		}
	}
	return len(seen)
}

func (s *Server) findReleaseLocked(appID string, platform string, version string) *AppRelease {
	var fallback *AppRelease
	for i := range s.data.Releases {
		release := &s.data.Releases[i]
		if release.AppID == appID && release.Platform == platform && release.Version == version {
			if release.Status == "blocked" {
				return release
			}
			if fallback == nil {
				fallback = release
			}
		}
	}
	return fallback
}

func (s *Server) findReleaseByIDLocked(appID string, releaseID string) *AppRelease {
	for i := range s.data.Releases {
		release := &s.data.Releases[i]
		if release.AppID == appID && release.ID == releaseID {
			return release
		}
	}
	return nil
}

func (s *Server) findRiskEventByIDLocked(id string) *RiskEvent {
	for i := range s.data.RiskEvents {
		if s.data.RiskEvents[i].ID == id {
			return &s.data.RiskEvents[i]
		}
	}
	return nil
}

func (s *Server) latestReleaseLocked(appID string, platform string) *AppRelease {
	var releases []*AppRelease
	for i := range s.data.Releases {
		release := &s.data.Releases[i]
		if release.AppID == appID && release.Platform == platform && release.Status == "active" {
			releases = append(releases, release)
		}
	}
	if len(releases) == 0 {
		return nil
	}
	sort.Slice(releases, func(i, j int) bool {
		if releases[i].BuildNumber == releases[j].BuildNumber {
			return releases[i].CreatedAt.After(releases[j].CreatedAt)
		}
		return releases[i].BuildNumber > releases[j].BuildNumber
	})
	return releases[0]
}

func releaseInRollout(appID string, platform string, releaseID string, deviceID string, rolloutPercent int) bool {
	rolloutPercent = clampPercent(rolloutPercent)
	if rolloutPercent >= 100 {
		return true
	}
	if rolloutPercent <= 0 || deviceID == "" {
		return false
	}
	key := appID + "|" + platform + "|" + releaseID + "|" + deviceID
	bucket := int(crc32.ChecksumIEEE([]byte(key)) % 100)
	return bucket < rolloutPercent
}

func latestReleaseFromItems(releases []AppRelease) *AppRelease {
	if len(releases) == 0 {
		return nil
	}
	items := append([]AppRelease(nil), releases...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].BuildNumber == items[j].BuildNumber {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].BuildNumber > items[j].BuildNumber
	})
	return &items[0]
}

func passedStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func currentOrPassedStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "current"
}

func releaseEvidence(release *AppRelease) map[string]any {
	if release == nil {
		return nil
	}
	return map[string]any{
		"version":              release.Version,
		"main_binary_hash":     release.MainBinaryHash,
		"signer_thumbprint":    release.SignerThumbprint,
		"resource_manifest":    release.ResourceManifestHash,
		"release_id":           release.ID,
		"min_supported":        release.MinSupportedVersion,
		"rollout_percent":      release.RolloutPercent,
		"mandatory":            release.Mandatory,
		"package_sha256":       release.PackageSHA256,
		"download_url":         release.DownloadURL,
		"resource_manifest_id": release.ResourceManifestHash,
	}
}

func sdkKeyEvidence(key *SDKKey) map[string]any {
	if key == nil {
		return nil
	}
	return map[string]any{
		"key_prefix":   key.KeyPrefix,
		"public_key":   key.PublicKey,
		"status":       key.Status,
		"created_at":   key.CreatedAt,
		"last_used_at": key.LastUsedAt,
	}
}

func deviceEvidence(device *Device) map[string]any {
	if device == nil {
		return nil
	}
	return map[string]any{
		"device_id":    device.ID,
		"status":       device.Status,
		"last_seen_at": device.LastSeenAt,
		"risk_score":   device.RiskScore,
	}
}

func integrityEvidence(report *IntegrityReport) map[string]any {
	if report == nil {
		return nil
	}
	return map[string]any{
		"report_id":          report.ID,
		"app_version":        report.AppVersion,
		"main_binary_hash":   report.MainBinaryHash,
		"signer_thumbprint":  report.SignerThumbprint,
		"debugger_detected":  report.DebuggerDetected,
		"suspicious_modules": report.SuspiciousModules,
		"vm_indicators":      report.VMIndicators,
		"created_at":         report.CreatedAt,
	}
}

func riskEvidence(event *RiskEvent) map[string]any {
	if event == nil {
		return nil
	}
	return map[string]any{
		"risk_id":     event.ID,
		"event_type":  event.EventType,
		"severity":    event.Severity,
		"action":      event.Action,
		"created_at":  event.CreatedAt,
		"resolved_at": event.ResolvedAt,
	}
}

func buildIntegrationBundle(onboarding OnboardingResponse, endpoint string, licenseKey string) ([]byte, error) {
	release := onboarding.LatestRelease
	version := "1.0.0"
	binaryHash := ""
	signer := ""
	if release != nil {
		version = release.Version
		binaryHash = release.MainBinaryHash
		signer = release.SignerThumbprint
	}
	envLines := []string{
		"LICENSE_GUARD_ENDPOINT=" + endpoint,
		"LICENSE_GUARD_APP_ID=" + onboarding.AppID,
		"LICENSE_GUARD_APP_VERSION=" + version,
		"LICENSE_GUARD_PUBLIC_KEY=" + publicKeyFromOnboarding(onboarding),
		"LICENSE_GUARD_BINARY_HASH=" + binaryHash,
		"LICENSE_GUARD_SIGNER_THUMBPRINT=" + signer,
		"LICENSE_GUARD_INSTALL_ID_PATH=%LOCALAPPDATA%\\LicenseGuard\\" + onboarding.AppID + "\\install_id",
		"LICENSE_GUARD_TOKEN_CACHE_PATH=%LOCALAPPDATA%\\LicenseGuard\\" + onboarding.AppID + "\\license_token.json",
	}
	if licenseKey != "" {
		envLines = append(envLines, "LICENSE_GUARD_DEMO_LICENSE="+licenseKey)
	}
	publicKey := publicKeyFromOnboarding(onboarding)
	installIDPath := "%LOCALAPPDATA%\\LicenseGuard\\" + onboarding.AppID + "\\install_id"
	tokenCachePath := "%LOCALAPPDATA%\\LicenseGuard\\" + onboarding.AppID + "\\license_token.json"

	files := map[string]string{
		"README.md":                        integrationReadme(onboarding, endpoint, licenseKey != ""),
		".env.example":                     strings.Join(envLines, "\n") + "\n",
		"licenseguard.config.json":         integrationConfigJSON(onboarding, endpoint, version, publicKey, binaryHash, signer, installIDPath, tokenCachePath),
		"app_id.txt":                       onboarding.AppID + "\n",
		"endpoint.txt":                     endpoint + "\n",
		"public_key.txt":                   publicKey + "\n",
		"integration-checklist.md":         integrationChecklist(onboarding),
		"internal/licenseguard/README.md":  licenseguardPackageReadme(),
		"internal/licenseguard/config.go":  integrationConfigGo(),
		"internal/licenseguard/service.go": integrationServiceGo(),
		"internal/licenseguard/errors.go":  integrationErrorsGo(),
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writer, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}
		if _, err := writer.Write([]byte(files[name])); err != nil {
			_ = zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func publicKeyFromOnboarding(onboarding OnboardingResponse) string {
	for _, step := range onboarding.Steps {
		if step.ID == "sdk_key_active" {
			if value, ok := step.Evidence["public_key"].(string); ok {
				return value
			}
		}
	}
	return ""
}

func integrationReadme(onboarding OnboardingResponse, endpoint string, includesLicense bool) string {
	release := onboarding.LatestRelease
	version := "1.0.0"
	if release != nil && release.Version != "" {
		version = release.Version
	}
	licenseLine := "License key is intentionally not included. Pass it at activation time."
	if includesLicense {
		licenseLine = "A demo license key was included because the bundle request supplied one explicitly."
	}
	return "# License Guard Integration Bundle\n\n" +
		"App: " + onboarding.App.Name + "\n" +
		"App ID: " + onboarding.AppID + "\n" +
		"Endpoint: " + endpoint + "\n" +
		"Version: " + version + "\n\n" +
		licenseLine + "\n\n" +
		"Files:\n" +
		"- .env.example: runtime configuration values safe for client code.\n" +
		"- licenseguard.config.json: importable client configuration without secrets.\n" +
		"- app_id.txt, endpoint.txt, public_key.txt: single-value files for deployment checks.\n" +
		"- internal/licenseguard/: minimal integration skeleton for Windows Go apps.\n" +
		"- integration-checklist.md: acceptance steps matching the Admin UI onboarding workbench.\n\n" +
		"Do not add SDK Secret, server private keys, admin tokens, or database credentials to the client app.\n"
}

func integrationConfigJSON(onboarding OnboardingResponse, endpoint string, version string, publicKey string, binaryHash string, signer string, installIDPath string, tokenCachePath string) string {
	payload := map[string]string{
		"endpoint":             endpoint,
		"app_id":               onboarding.AppID,
		"app_version":          version,
		"public_key":           publicKey,
		"binary_hash":          binaryHash,
		"signer_thumbprint":    signer,
		"install_id_path":      installIDPath,
		"token_cache_path":     tokenCachePath,
		"license_key_strategy": "activation_time",
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	return string(raw) + "\n"
}

func integrationChecklist(onboarding OnboardingResponse) string {
	var b strings.Builder
	b.WriteString("# Integration Checklist\n\n")
	for _, step := range onboarding.Steps {
		b.WriteString("- [ ] ")
		b.WriteString(step.Label)
		b.WriteString(" (")
		b.WriteString(step.Status)
		b.WriteString(", ")
		b.WriteString(step.Source)
		b.WriteString(")\n")
	}
	b.WriteString("\nAcceptance:\n")
	b.WriteString("- Activation returns allowed=true and the Admin UI shows a device.\n")
	b.WriteString("- Local token verification works while offline until offline grace expires.\n")
	b.WriteString("- Verify and heartbeat update last_seen_at.\n")
	b.WriteString("- Tampered binary hash returns INTEGRITY_FAILED and creates a risk event.\n")
	return b.String()
}

func licenseguardPackageReadme() string {
	return "# internal/licenseguard\n\n" +
		"Place the generated skeleton in your app and replace TODO blocks with calls to the checked-in License Guard Go SDK or equivalent HTTP client code.\n\n" +
		"Keep business code behind Service or a similar interface so entitlement checks do not scatter raw API calls through the app.\n"
}

func integrationConfigGo() string {
	return `package licenseguard

import "os"

type Config struct {
	Endpoint         string
	AppID            string
	AppVersion       string
	PublicKey        string
	BinaryHash       string
	SignerThumbprint string
	InstallIDPath    string
	TokenCachePath   string
}

func LoadConfig() Config {
	return Config{
		Endpoint:         os.Getenv("LICENSE_GUARD_ENDPOINT"),
		AppID:            os.Getenv("LICENSE_GUARD_APP_ID"),
		AppVersion:       os.Getenv("LICENSE_GUARD_APP_VERSION"),
		PublicKey:        os.Getenv("LICENSE_GUARD_PUBLIC_KEY"),
		BinaryHash:       os.Getenv("LICENSE_GUARD_BINARY_HASH"),
		SignerThumbprint: os.Getenv("LICENSE_GUARD_SIGNER_THUMBPRINT"),
		InstallIDPath:    os.Getenv("LICENSE_GUARD_INSTALL_ID_PATH"),
		TokenCachePath:   os.Getenv("LICENSE_GUARD_TOKEN_CACHE_PATH"),
	}
}
`
}

func integrationServiceGo() string {
	return `package licenseguard

import "context"

type Result struct {
	Allowed      bool
	Code         string
	Entitlements []string
}

type Service struct {
	config Config
}

func NewService(config Config) *Service {
	return &Service{config: config}
}

func (s *Service) Activate(ctx context.Context, licenseKey string) (*Result, error) {
	// TODO: call /v1/challenge, collect device and integrity data, then call /v1/activate.
	return nil, nil
}

func (s *Service) VerifyLocalOnStartup(ctx context.Context) (*Result, error) {
	// TODO: read token cache, verify Ed25519 signature with PublicKey, then check app_id, device_id, exp, and entitlements.
	return nil, nil
}

func (s *Service) VerifyOnline(ctx context.Context) (*Result, error) {
	// TODO: call /v1/challenge and /v1/verify with cached token and current integrity report.
	return nil, nil
}

func (s *Service) Heartbeat(ctx context.Context) error {
	// TODO: call /v1/heartbeat with cached token and install_id.
	return nil
}

func (s *Service) HasEntitlement(result *Result, name string) bool {
	if result == nil {
		return false
	}
	for _, item := range result.Entitlements {
		if item == name {
			return true
		}
	}
	return false
}
`
}

func integrationErrorsGo() string {
	return `package licenseguard

var UserMessages = map[string]string{
	"LICENSE_REVOKED":        "授权已吊销，请联系管理员。",
	"LICENSE_SUSPENDED":      "授权已暂停，请联系管理员恢复。",
	"DEVICE_BLOCKED":         "当前设备已被封禁。",
	"DEVICE_LIMIT_EXCEEDED":  "授权设备数已达上限，请解绑旧设备。",
	"INTEGRITY_FAILED":       "应用完整性校验失败，请重新安装官方版本。",
	"TOKEN_EXPIRED":          "授权状态需要联网刷新。",
	"APP_VERSION_BLOCKED":    "当前版本已停用，请升级。",
	"TOKEN_DEVICE_MISMATCH":  "授权 token 与当前设备不匹配，请重新激活。",
	"TOKEN_DEACTIVATED":      "当前设备授权已停用，请重新激活。",
}
`
}

func sanitizeFilename(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	name := strings.Trim(b.String(), "._-")
	if name == "" {
		return "app"
	}
	return name
}

func clampPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func clampInt(value int, min int, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func compareVersionStrings(left string, right string) int {
	leftParts := splitVersionParts(left)
	rightParts := splitVersionParts(right)
	maxLen := len(leftParts)
	if len(rightParts) > maxLen {
		maxLen = len(rightParts)
	}
	for i := 0; i < maxLen; i++ {
		leftValue := 0
		rightValue := 0
		if i < len(leftParts) {
			leftValue = leftParts[i]
		}
		if i < len(rightParts) {
			rightValue = rightParts[i]
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}

func splitVersionParts(value string) []int {
	separators := func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	}
	rawParts := strings.FieldsFunc(value, separators)
	parts := make([]int, 0, len(rawParts))
	for _, part := range rawParts {
		number := 0
		found := false
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			found = true
			number = number*10 + int(r-'0')
		}
		if found {
			parts = append(parts, number)
		}
	}
	return parts
}

func (s *Server) addRiskEventLocked(appID string, deviceID string, licenseID string, eventType string, severity string, action string, summary string, metadata map[string]any) {
	s.data.RiskEvents = append(s.data.RiskEvents, RiskEvent{
		ID:        newID("risk"),
		AppID:     appID,
		DeviceID:  deviceID,
		LicenseID: licenseID,
		EventType: eventType,
		Severity:  severity,
		Action:    action,
		Summary:   summary,
		Metadata:  metadata,
		CreatedAt: time.Now(),
	})
}

func (s *Server) auditLocked(adminID string, action string, targetType string, targetID string, r *http.Request, metadata map[string]any) {
	s.data.AuditLogs = append(s.data.AuditLogs, AuditLog{
		ID:         newID("audit"),
		AdminID:    adminID,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		IP:         clientIP(r),
		UserAgent:  r.UserAgent(),
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return false
	}
	return true
}

func writeDenied(w http.ResponseWriter, code string, message string, risk RiskResult) {
	writeJSON(w, http.StatusOK, VerifyResponse{Allowed: false, Code: code, Message: message, Risk: risk})
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-LG-App-Id, X-LG-SDK-Version, X-LG-Request-Id")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newID(prefix string) string {
	return prefix + "_" + time.Now().UTC().Format("20060102150405") + "_" + randomString(8)
}

func randomString(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func generateLicenseKey() string {
	return "LG-" + strings.ToUpper(randomString(4)[:4]) + "-" + strings.ToUpper(randomString(4)[:4]) + "-" + strings.ToUpper(randomString(4)[:4])
}

func licensePrefix(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
