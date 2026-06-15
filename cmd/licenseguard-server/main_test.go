package main

import (
	"strings"
	"testing"
)

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
