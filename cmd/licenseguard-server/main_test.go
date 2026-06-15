package main

import (
	"strings"
	"testing"
)

func TestValidateProductionConfigAllowsDevelopmentDefaults(t *testing.T) {
	err := validateProductionConfig(false, "json", "", "*")
	if err != nil {
		t.Fatalf("validateProductionConfig returned error for development defaults: %v", err)
	}
}

func TestValidateProductionConfigRequiresPostgresStore(t *testing.T) {
	err := validateProductionConfig(true, "json", "C:/licenseguard/keys", "https://licenseguard.example.com")
	requireErrorContains(t, err, "requires -store=postgres")
}

func TestValidateProductionConfigRequiresExplicitKeyDir(t *testing.T) {
	err := validateProductionConfig(true, "postgres", "", "https://licenseguard.example.com")
	requireErrorContains(t, err, "requires explicit -key-dir")
}

func TestValidateProductionConfigRejectsWildcardCORS(t *testing.T) {
	for _, origins := range []string{"*", " https://licenseguard.example.com , * ", ""} {
		err := validateProductionConfig(true, "postgres", "C:/licenseguard/keys", origins)
		requireErrorContains(t, err, "requires concrete -cors-allowed-origins")
	}
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
			err := validateProductionConfig(true, tc.store, "C:/licenseguard/keys", tc.origins)
			if err != nil {
				t.Fatalf("validateProductionConfig returned error: %v", err)
			}
		})
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
