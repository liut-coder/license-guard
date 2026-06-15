package licenseguard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectIntegrityAppliesHook(t *testing.T) {
	signatureValid := true
	client, err := NewClient(Options{
		AppID:              "app_visionflow_windows_prod",
		Endpoint:           "https://license.example/v1",
		AppVersion:         "1.2.3",
		BinaryHashOverride: "signed-binary-hash",
		SignerThumbprint:   "signer-thumbprint",
		IntegrityHook: func(ctx context.Context, base IntegrityReport) (IntegrityReport, error) {
			if base.AppVersion != "1.2.3" || base.MainBinaryHash != "signed-binary-hash" {
				t.Fatalf("base integrity = %#v, want app version and binary hash", base)
			}
			base.BusinessManifestSHA256 = "business-manifest"
			base.BusinessManifestSignatureValid = &signatureValid
			base.ProtectedDBSchemaHash = "schema"
			base.ProtectedDBTablesHash = "tables"
			base.AssetsManifestSHA256 = "assets"
			base.WorkflowManifestSHA256 = "workflow"
			base.BusinessIntegrityStatus = "ok"
			base.DBEncryptionStatus = "ok"
			return base, nil
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	integrity, err := client.collectIntegrity(context.Background())
	if err != nil {
		t.Fatalf("collect integrity: %v", err)
	}
	if integrity.BusinessManifestSHA256 != "business-manifest" ||
		integrity.BusinessManifestSignatureValid == nil ||
		!*integrity.BusinessManifestSignatureValid ||
		integrity.ProtectedDBSchemaHash != "schema" ||
		integrity.ProtectedDBTablesHash != "tables" ||
		integrity.AssetsManifestSHA256 != "assets" ||
		integrity.WorkflowManifestSHA256 != "workflow" ||
		integrity.BusinessIntegrityStatus != "ok" ||
		integrity.DBEncryptionStatus != "ok" {
		t.Fatalf("integrity = %#v, want business fields", integrity)
	}
}

func TestHeartbeatRequestCanCarryBusinessIntegrity(t *testing.T) {
	signatureValid := true
	request := HeartbeatRequest{
		AppID:        "app_visionflow_windows_prod",
		LicenseToken: "token",
		InstallID:    "install",
		AppVersion:   "1.2.3",
		Integrity: &IntegrityReport{
			AppVersion:                     "1.2.3",
			BusinessManifestSHA256:         "business-manifest",
			BusinessManifestSignatureValid: &signatureValid,
			ProtectedDBSchemaHash:          "schema",
			ProtectedDBTablesHash:          "tables",
			AssetsManifestSHA256:           "assets",
			WorkflowManifestSHA256:         "workflow",
			BusinessIntegrityStatus:        "ok",
			DBEncryptionStatus:             "key_unavailable",
			DBEncryptionErrors:             []string{"dpapi key not found"},
		},
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	for _, want := range []string{
		`"business_manifest_sha256":"business-manifest"`,
		`"business_manifest_signature_valid":true`,
		`"protected_db_schema_hash":"schema"`,
		`"protected_db_tables_hash":"tables"`,
		`"assets_manifest_sha256":"assets"`,
		`"workflow_manifest_sha256":"workflow"`,
		`"business_integrity_status":"ok"`,
		`"db_encryption_status":"key_unavailable"`,
		`"db_encryption_errors":["dpapi key not found"]`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("heartbeat request JSON %s missing %s", data, want)
		}
	}
}
