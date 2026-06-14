package main

import (
	"os"
	"path/filepath"
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
