package main

import (
	"strings"
	"testing"

	"license-guard/internal/licensecore"
)

func TestValidateProductionConfigAllowsDevelopmentDefaults(t *testing.T) {
	err := validateProductionConfig(false, "json", "", "*", "")
	if err != nil {
		t.Fatalf("validateProductionConfig returned error for development defaults: %v", err)
	}
}

func TestValidateProductionConfigRequiresPostgresStore(t *testing.T) {
	err := validateProductionConfig(true, "json", "C:/licenseguard/keys", "https://licenseguard.example.com", "https://licenseguard.example.com")
	requireErrorContains(t, err, "requires -store=postgres")
}

func TestValidateProductionConfigRequiresExplicitKeyDir(t *testing.T) {
	err := validateProductionConfig(true, "postgres", "", "https://licenseguard.example.com", "https://licenseguard.example.com")
	requireErrorContains(t, err, "requires explicit -key-dir")
}

func TestValidateProductionConfigRejectsWildcardCORS(t *testing.T) {
	for _, origins := range []string{"*", " https://licenseguard.example.com , * ", ""} {
		err := validateProductionConfig(true, "postgres", "C:/licenseguard/keys", origins, "https://licenseguard.example.com")
		requireErrorContains(t, err, "requires concrete -cors-allowed-origins")
	}
}

func TestValidateProductionConfigRejectsHTTPPublicBaseURL(t *testing.T) {
	for _, publicBaseURL := range []string{"", "http://licenseguard.example.com", "https://licenseguard.example.com?debug=true"} {
		err := validateProductionConfig(true, "postgres", "C:/licenseguard/keys", "https://licenseguard.example.com", publicBaseURL)
		requireErrorContains(t, err, "requires -public-base-url")
	}
}

func TestValidateProductionConfigRejectsHTTPCORSOrigins(t *testing.T) {
	err := validateProductionConfig(true, "postgres", "C:/licenseguard/keys", "http://licenseguard.example.com", "https://licenseguard.example.com")
	requireErrorContains(t, err, "requires HTTPS -cors-allowed-origins")
}

func TestValidateProductionConfigAcceptsProductionSettings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		store   string
		origins string
	}{
		{
			name:    "postgres",
			store:   "postgres",
			origins: "https://licenseguard.example.com",
		},
		{
			name:    "postgresql alias with multiple origins",
			store:   "postgresql",
			origins: "https://licenseguard.example.com,https://ops.example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProductionConfig(true, tc.store, "C:/licenseguard/keys", tc.origins, "https://licenseguard.example.com")
			if err != nil {
				t.Fatalf("validateProductionConfig returned error: %v", err)
			}
		})
	}
}

func TestBootstrapAdminFromConfigRejectsPartialInput(t *testing.T) {
	_, err := bootstrapAdminFromConfig(true, "ops@example.com", "", "Ops")
	requireErrorContains(t, err, "requires both account and password")
}

func TestBootstrapAdminFromConfigRejectsDemoPasswordInProduction(t *testing.T) {
	_, err := bootstrapAdminFromConfig(true, "ops@example.com", licensecore.DemoAdminPass, "Ops")
	requireErrorContains(t, err, "must not use the demo password")
}

func TestBootstrapAdminFromConfigRequiresStrongProductionPassword(t *testing.T) {
	_, err := bootstrapAdminFromConfig(true, "ops@example.com", "shortpass", "Ops")
	requireErrorContains(t, err, "at least 12 characters")
}

func TestBootstrapAdminFromConfigRejectsPlaceholderPasswordInProduction(t *testing.T) {
	_, err := bootstrapAdminFromConfig(true, "ops@example.com", "change-me-bootstrap-password", "Ops")
	requireErrorContains(t, err, "replace the change-me placeholder")
}

func TestBootstrapAdminFromConfigAcceptsProductionBootstrap(t *testing.T) {
	admin, err := bootstrapAdminFromConfig(true, " ops@example.com ", "VeryStrong123!", "Ops")
	if err != nil {
		t.Fatalf("bootstrapAdminFromConfig returned error: %v", err)
	}
	if admin == nil || admin.Account != "ops@example.com" || admin.Name != "Ops" {
		t.Fatalf("unexpected bootstrap admin: %#v", admin)
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("LG_TEST_BOOL", "")
	if !envBool("LG_TEST_BOOL", true) {
		t.Fatal("empty env should return fallback true")
	}
	if envBool("LG_TEST_BOOL", false) {
		t.Fatal("empty env should return fallback false")
	}

	for _, value := range []string{"1", "true", "TRUE", "yes", "y", "on"} {
		t.Setenv("LG_TEST_BOOL", value)
		if !envBool("LG_TEST_BOOL", false) {
			t.Fatalf("envBool(%q) = false, want true", value)
		}
	}

	for _, value := range []string{"0", "false", "FALSE", "no", "n", "off"} {
		t.Setenv("LG_TEST_BOOL", value)
		if envBool("LG_TEST_BOOL", true) {
			t.Fatalf("envBool(%q) = true, want false", value)
		}
	}

	t.Setenv("LG_TEST_BOOL", "maybe")
	if !envBool("LG_TEST_BOOL", true) {
		t.Fatal("unknown env value should return fallback true")
	}
}

func TestRedactLogMessageRedactsDatabaseURLPassword(t *testing.T) {
	input := "connect postgres://licenseguard:super-secret@db.example/license_guard?sslmode=require failed"
	got := redactLogMessage(input)
	if strings.Contains(got, "super-secret") {
		t.Fatalf("redacted log still contains password: %s", got)
	}
	if !strings.Contains(got, "postgres://licenseguard:%5Bredacted%5D@db.example/license_guard") {
		t.Fatalf("redacted log missing sanitized URL: %s", got)
	}
}

func TestRedactedPrefixDoesNotExposeFullValue(t *testing.T) {
	got := redactedPrefix("LG-DEMO-2026-WINDOWS")
	if got == "LG-DEMO-2026-WINDOWS" || strings.Contains(got, "WINDOWS") {
		t.Fatalf("prefix leaked full value: %s", got)
	}
	if got != "LG-DEMO-..." {
		t.Fatalf("prefix = %q, want LG-DEMO-...", got)
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
}
