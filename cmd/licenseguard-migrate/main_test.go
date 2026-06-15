package main

import "testing"

func TestValidateMigrationOptionsRejectsDemoSeedInProduction(t *testing.T) {
	err := validateMigrationOptions(true, true)
	if err == nil {
		t.Fatal("expected production seed demo config to be rejected")
	}
}

func TestValidateMigrationOptionsAllowsDemoSeedOutsideProduction(t *testing.T) {
	if err := validateMigrationOptions(false, true); err != nil {
		t.Fatalf("demo seed should be allowed outside production: %v", err)
	}
}

func TestMigrateEnvBool(t *testing.T) {
	t.Setenv("LG_MIGRATE_TEST_BOOL", "true")
	if !envBool("LG_MIGRATE_TEST_BOOL", false) {
		t.Fatal("envBool should parse true")
	}

	t.Setenv("LG_MIGRATE_TEST_BOOL", "0")
	if envBool("LG_MIGRATE_TEST_BOOL", true) {
		t.Fatal("envBool should parse false")
	}

	t.Setenv("LG_MIGRATE_TEST_BOOL", "unknown")
	if !envBool("LG_MIGRATE_TEST_BOOL", true) {
		t.Fatal("envBool should return fallback for unknown values")
	}
}
