package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSHA256Hex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("visionflow"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := fileSHA256Hex(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "a58880191470ecebc196979fa67099f19689b549bd09530e0d08185013ab9226"
	if got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

func TestBuildReleasePayloadComputesHashes(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "VisionFlow.exe")
	packagePath := filepath.Join(dir, "VisionFlowSetup.exe")
	notesPath := filepath.Join(dir, "notes.md")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, []byte("package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notesPath, []byte("release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, err := buildReleasePayload(releaseInput{
		appID:               "app_visionflow_windows_prod",
		version:             "0.2.0",
		buildNumber:         42,
		mainBinary:          binaryPath,
		packageFile:         packagePath,
		signerThumbprint:    "ABCDEF",
		downloadURL:         "https://download.example/visionflow.exe",
		releaseNotesFile:    notesPath,
		rolloutPercent:      150,
		minSupportedVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload.AppID != "app_visionflow_windows_prod" || payload.Platform != "windows" || payload.Channel != "production" || payload.Status != "active" {
		t.Fatalf("unexpected payload defaults: %#v", payload)
	}
	if payload.RolloutPercent != 100 {
		t.Fatalf("rollout = %d, want clamped 100", payload.RolloutPercent)
	}
	if payload.MainBinaryHash == "" || payload.PackageSHA256 == "" || payload.ReleaseNotes != "release notes" {
		t.Fatalf("payload did not compute derived fields: %#v", payload)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	for input, want := range map[string]string{
		"https://license.example/":    "https://license.example",
		"https://license.example/v1":  "https://license.example",
		"https://license.example/api": "https://license.example/api",
	} {
		if got := normalizeServerURL(input); got != want {
			t.Fatalf("normalizeServerURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVisionFlowBootstrapCreatesUsableEnv(t *testing.T) {
	var appCreated bool
	var releasePatched bool
	var licenseCreated bool
	var policiesSeeded bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/apps":
			writeTestJSON(t, w, map[string]any{"items": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/apps":
			appCreated = true
			var req map[string]any
			decodeTestJSON(t, r, &req)
			if req["app_key"] != "app_visionflow_windows_prod" || req["version"] != "0.1.0" {
				t.Fatalf("unexpected app create payload: %#v", req)
			}
			writeTestJSON(t, w, map[string]any{
				"app": map[string]any{"app_key": "app_visionflow_windows_prod"},
				"release": map[string]any{
					"id":       "rel_1",
					"app_id":   "app_visionflow_windows_prod",
					"platform": "windows",
					"version":  "0.1.0",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/apps/app_visionflow_windows_prod/capability-policies/visionflow-defaults":
			policiesSeeded = true
			writeTestJSON(t, w, map[string]any{
				"added": 7,
				"items": []map[string]any{{
					"capability":           "automation.run",
					"required_entitlement": "visionflow.automation",
					"mode":                 "block",
				}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/apps/app_visionflow_windows_prod":
			writeTestJSON(t, w, map[string]any{
				"app": map[string]any{"app_key": "app_visionflow_windows_prod"},
				"releases": []map[string]any{{
					"id":       "rel_1",
					"app_id":   "app_visionflow_windows_prod",
					"platform": "windows",
					"version":  "0.1.0",
				}},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/admin/apps/app_visionflow_windows_prod/releases/rel_1":
			releasePatched = true
			var req map[string]any
			decodeTestJSON(t, r, &req)
			if req["main_binary_hash"] != "dev-visionflow-main-binary-sha256" || req["signer_thumbprint"] != "dev-visionflow-signer-thumbprint" {
				t.Fatalf("unexpected release patch payload: %#v", req)
			}
			writeTestJSON(t, w, map[string]any{"release": map[string]any{"id": "rel_1"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/public-key":
			writeTestJSON(t, w, map[string]any{"alg": "Ed25519", "key_type": "public", "public_key": "test-public-key"})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/licenses":
			licenseCreated = true
			var req map[string]any
			decodeTestJSON(t, r, &req)
			entitlements, ok := req["entitlements"].([]any)
			if !ok || len(entitlements) == 0 || entitlements[0] != "visionflow.automation" {
				t.Fatalf("unexpected license entitlements: %#v", req["entitlements"])
			}
			writeTestJSON(t, w, map[string]any{
				"license":     map[string]any{"id": "lic_1", "app_id": "app_visionflow_windows_prod"},
				"license_key": "LG-VISIONFLOW-DEV",
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	err := runVisionFlowBootstrapWithIO(context.Background(), []string{
		"-server", server.URL,
		"-admin-token", "admin-token",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !appCreated || !policiesSeeded || !releasePatched || !licenseCreated {
		t.Fatalf("flow not completed: appCreated=%v policiesSeeded=%v releasePatched=%v licenseCreated=%v", appCreated, policiesSeeded, releasePatched, licenseCreated)
	}
	env := out.String()
	for _, want := range []string{
		"LICENSE_GUARD_ENDPOINT=" + server.URL + "/v1",
		"LICENSE_GUARD_APP_ID=app_visionflow_windows_prod",
		"LICENSE_GUARD_PUBLIC_KEY=test-public-key",
		"VISIONFLOW_LICENSE_KEY=LG-VISIONFLOW-DEV",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env output missing %q:\n%s", want, env)
		}
	}
}

func decodeTestJSON(t *testing.T, r *http.Request, out any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
