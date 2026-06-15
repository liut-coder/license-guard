package licensecore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const storeOperationTimeout = 10 * time.Second

type PostgresStore struct {
	db          *sql.DB
	databaseURL string
}

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	if databaseURL == "" {
		return nil, errors.New("database url is required")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), storeOperationTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &PostgresStore{db: db, databaseURL: databaseURL}, nil
}

func (s *PostgresStore) Name() string {
	return "postgres:" + redactDatabaseURL(s.databaseURL)
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) Load() (Data, error) {
	ctx, cancel := context.WithTimeout(context.Background(), storeOperationTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Data{}, err
	}
	defer tx.Rollback()

	data := Data{}
	if data.Admins, err = queryAdmins(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.Apps, err = queryApps(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.Releases, err = queryReleases(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.SDKKeys, err = querySDKKeys(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.Licenses, err = queryLicenses(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.CapabilityPolicies, err = queryCapabilityPolicies(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.Devices, err = queryDevices(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.Activations, err = queryActivations(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.IntegrityReports, err = queryIntegrityReports(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.RiskEvents, err = queryRiskEvents(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.AuditLogs, err = queryAuditLogs(ctx, tx); err != nil {
		return Data{}, err
	}
	if data.Settings, err = querySystemSettings(ctx, tx); err != nil {
		return Data{}, err
	}
	if err := tx.Commit(); err != nil {
		return Data{}, err
	}
	if dataIsEmpty(data) {
		return Data{}, ErrStoreNotFound
	}
	return data, nil
}

func (s *PostgresStore) Save(data Data) error {
	ctx, cancel := context.WithTimeout(context.Background(), storeOperationTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := deletePostgresData(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := insertPostgresData(ctx, tx, data); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func queryAdmins(ctx context.Context, q sqlQuerier) ([]Admin, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, account, name, password_hash, status, created_at, updated_at
		FROM admins
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Admin
	for rows.Next() {
		var item Admin
		if err := rows.Scan(&item.ID, &item.Account, &item.Name, &item.PasswordHash, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryApps(ctx context.Context, q sqlQuerier) ([]App, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, app_key, name, description, owner_team, status, created_at, updated_at
		FROM apps
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []App
	for rows.Next() {
		var item App
		if err := rows.Scan(&item.ID, &item.AppKey, &item.Name, &item.Description, &item.OwnerTeam, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryReleases(ctx context.Context, q sqlQuerier) ([]AppRelease, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, app_id, platform, version, build_number, channel, status,
			signer_thumbprint, main_binary_hash, resource_manifest_hash,
			business_manifest_sha256, protected_db_schema_hash, protected_db_tables_hash,
			assets_manifest_sha256, workflow_manifest_sha256, download_url,
			package_sha256, mandatory, min_supported_version, rollout_percent, release_notes, created_at
		FROM app_releases
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AppRelease
	for rows.Next() {
		var item AppRelease
		if err := rows.Scan(
			&item.ID,
			&item.AppID,
			&item.Platform,
			&item.Version,
			&item.BuildNumber,
			&item.Channel,
			&item.Status,
			&item.SignerThumbprint,
			&item.MainBinaryHash,
			&item.ResourceManifestHash,
			&item.BusinessManifestSHA256,
			&item.ProtectedDBSchemaHash,
			&item.ProtectedDBTablesHash,
			&item.AssetsManifestSHA256,
			&item.WorkflowManifestSHA256,
			&item.DownloadURL,
			&item.PackageSHA256,
			&item.Mandatory,
			&item.MinSupportedVersion,
			&item.RolloutPercent,
			&item.ReleaseNotes,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryLicenses(ctx context.Context, q sqlQuerier) ([]License, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, license_key_hash, license_key_prefix, app_id, plan_name, owner_type,
			owner_ref, max_devices, entitlements, expires_at, status, created_at, updated_at
		FROM licenses
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []License
	for rows.Next() {
		var item License
		var entitlements []byte
		if err := rows.Scan(
			&item.ID,
			&item.LicenseKeyHash,
			&item.LicenseKeyPrefix,
			&item.AppID,
			&item.PlanName,
			&item.OwnerType,
			&item.OwnerRef,
			&item.MaxDevices,
			&entitlements,
			&item.ExpiresAt,
			&item.Status,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(entitlements, &item.Entitlements); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func querySDKKeys(ctx context.Context, q sqlQuerier) ([]SDKKey, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, app_id, public_key, secret_hash, key_prefix, status, last_used_at, created_at, rotated_at
		FROM sdk_keys
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []SDKKey
	for rows.Next() {
		var item SDKKey
		if err := rows.Scan(
			&item.ID,
			&item.AppID,
			&item.PublicKey,
			&item.SecretHash,
			&item.KeyPrefix,
			&item.Status,
			&item.LastUsedAt,
			&item.CreatedAt,
			&item.RotatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryCapabilityPolicies(ctx context.Context, q sqlQuerier) ([]CapabilityPolicy, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT app_id, capability, required_entitlement, mode, message,
			limits_json, created_at, updated_at
		FROM capability_policies
		ORDER BY app_id, capability`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []CapabilityPolicy
	for rows.Next() {
		var item CapabilityPolicy
		var limitsJSON []byte
		if err := rows.Scan(
			&item.AppID,
			&item.Capability,
			&item.RequiredEntitlement,
			&item.Mode,
			&item.Message,
			&limitsJSON,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(limitsJSON, &item.LimitsJSON); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryDevices(ctx context.Context, q sqlQuerier) ([]Device, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, device_fingerprint_hash, install_id_hash, platform, os_version,
			machine_name_hash, risk_score, status, first_seen_at, last_seen_at
		FROM devices
		ORDER BY first_seen_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Device
	for rows.Next() {
		var item Device
		if err := rows.Scan(
			&item.ID,
			&item.DeviceFingerprintHash,
			&item.InstallIDHash,
			&item.Platform,
			&item.OSVersion,
			&item.MachineNameHash,
			&item.RiskScore,
			&item.Status,
			&item.FirstSeenAt,
			&item.LastSeenAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryActivations(ctx context.Context, q sqlQuerier) ([]Activation, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, license_id, device_id, app_id, activation_status,
			activated_at, last_verified_at, deactivated_at
		FROM activations
		ORDER BY activated_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Activation
	for rows.Next() {
		var item Activation
		if err := rows.Scan(
			&item.ID,
			&item.LicenseID,
			&item.DeviceID,
			&item.AppID,
			&item.ActivationStatus,
			&item.ActivatedAt,
			&item.LastVerifiedAt,
			&item.DeactivatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryIntegrityReports(ctx context.Context, q sqlQuerier) ([]IntegrityReport, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, app_id, device_id, release_id, verify_session_id, platform,
			app_version, main_binary_hash, signer_thumbprint,
			business_manifest_sha256, business_manifest_signature_valid,
			protected_db_schema_hash, protected_db_tables_hash,
			assets_manifest_sha256, workflow_manifest_sha256,
			business_integrity_status, business_integrity_errors,
			db_encryption_status, db_encryption_errors,
			debugger_detected, suspicious_modules, vm_indicators, created_at
		FROM integrity_reports
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []IntegrityReport
	for rows.Next() {
		var item IntegrityReport
		var businessManifestSignatureValid sql.NullBool
		var businessIntegrityErrors []byte
		var dbEncryptionErrors []byte
		var suspiciousModules []byte
		var vmIndicators []byte
		if err := rows.Scan(
			&item.ID,
			&item.AppID,
			&item.DeviceID,
			&item.ReleaseID,
			&item.VerifySessionID,
			&item.Platform,
			&item.AppVersion,
			&item.MainBinaryHash,
			&item.SignerThumbprint,
			&item.BusinessManifestSHA256,
			&businessManifestSignatureValid,
			&item.ProtectedDBSchemaHash,
			&item.ProtectedDBTablesHash,
			&item.AssetsManifestSHA256,
			&item.WorkflowManifestSHA256,
			&item.BusinessIntegrityStatus,
			&businessIntegrityErrors,
			&item.DBEncryptionStatus,
			&dbEncryptionErrors,
			&item.DebuggerDetected,
			&suspiciousModules,
			&vmIndicators,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		if businessManifestSignatureValid.Valid {
			value := businessManifestSignatureValid.Bool
			item.BusinessManifestSignatureValid = &value
		}
		if err := json.Unmarshal(businessIntegrityErrors, &item.BusinessIntegrityErrors); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(dbEncryptionErrors, &item.DBEncryptionErrors); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(suspiciousModules, &item.SuspiciousModules); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(vmIndicators, &item.VMIndicators); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryRiskEvents(ctx context.Context, q sqlQuerier) ([]RiskEvent, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, app_id, device_id, license_id, event_type, severity, action,
			summary, metadata, created_at, resolved_at
		FROM risk_events
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []RiskEvent
	for rows.Next() {
		var item RiskEvent
		var metadata []byte
		if err := rows.Scan(
			&item.ID,
			&item.AppID,
			&item.DeviceID,
			&item.LicenseID,
			&item.EventType,
			&item.Severity,
			&item.Action,
			&item.Summary,
			&metadata,
			&item.CreatedAt,
			&item.ResolvedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
			return nil, err
		}
		if len(item.Metadata) == 0 {
			item.Metadata = nil
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryAuditLogs(ctx context.Context, q sqlQuerier) ([]AuditLog, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, admin_id, action, target_type, target_id, ip, user_agent, metadata, created_at
		FROM audit_logs
		ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AuditLog
	for rows.Next() {
		var item AuditLog
		var metadata []byte
		if err := rows.Scan(
			&item.ID,
			&item.AdminID,
			&item.Action,
			&item.TargetType,
			&item.TargetID,
			&item.IP,
			&item.UserAgent,
			&metadata,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(metadata, &item.Metadata); err != nil {
			return nil, err
		}
		if len(item.Metadata) == 0 {
			item.Metadata = nil
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func querySystemSettings(ctx context.Context, q sqlQuerier) (SystemSettings, error) {
	var item SystemSettings
	err := q.QueryRowContext(ctx, `
		SELECT default_token_ttl_minutes, medium_risk_token_ttl_minutes, offline_grace_days,
			default_max_devices, default_license_days, audit_log_retention_days,
			mfa_required, sensitive_action_confirm, updated_at
		FROM system_settings
		WHERE id = 'system'`).Scan(
		&item.DefaultTokenTTLMinutes,
		&item.MediumRiskTokenTTLMinutes,
		&item.OfflineGraceDays,
		&item.DefaultMaxDevices,
		&item.DefaultLicenseDays,
		&item.AuditLogRetentionDays,
		&item.MFARequired,
		&item.SensitiveActionConfirm,
		&item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SystemSettings{}, nil
	}
	return item, err
}

func deletePostgresData(ctx context.Context, tx *sql.Tx) error {
	tables := []string{
		"system_settings",
		"audit_logs",
		"risk_events",
		"integrity_reports",
		"activations",
		"devices",
		"licenses",
		"capability_policies",
		"sdk_keys",
		"app_releases",
		"apps",
		"admins",
	}
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	return nil
}

func insertPostgresData(ctx context.Context, tx *sql.Tx, data Data) error {
	settings := normalizeSystemSettings(data.Settings, time.Now())
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO system_settings (
			id, default_token_ttl_minutes, medium_risk_token_ttl_minutes, offline_grace_days,
			default_max_devices, default_license_days, audit_log_retention_days,
			mfa_required, sensitive_action_confirm, updated_at
		) VALUES ('system', $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		settings.DefaultTokenTTLMinutes,
		settings.MediumRiskTokenTTLMinutes,
		settings.OfflineGraceDays,
		settings.DefaultMaxDevices,
		settings.DefaultLicenseDays,
		settings.AuditLogRetentionDays,
		settings.MFARequired,
		settings.SensitiveActionConfirm,
		settings.UpdatedAt,
	); err != nil {
		return fmt.Errorf("insert system settings: %w", err)
	}

	for _, item := range data.Admins {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO admins (id, account, name, password_hash, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			item.ID,
			item.Account,
			item.Name,
			item.PasswordHash,
			item.Status,
			item.CreatedAt,
			item.UpdatedAt,
		); err != nil {
			return fmt.Errorf("insert admin %s: %w", item.Account, err)
		}
	}

	for _, item := range data.Apps {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO apps (id, app_key, name, description, owner_team, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			item.ID,
			item.AppKey,
			item.Name,
			item.Description,
			item.OwnerTeam,
			item.Status,
			item.CreatedAt,
			item.UpdatedAt,
		); err != nil {
			return fmt.Errorf("insert app %s: %w", item.AppKey, err)
		}
	}

	for _, item := range data.Releases {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_releases (
				id, app_id, platform, version, build_number, channel, status,
				signer_thumbprint, main_binary_hash, resource_manifest_hash,
				business_manifest_sha256, protected_db_schema_hash, protected_db_tables_hash,
				assets_manifest_sha256, workflow_manifest_sha256, download_url,
				package_sha256, mandatory, min_supported_version, rollout_percent, release_notes, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)`,
			item.ID,
			item.AppID,
			item.Platform,
			item.Version,
			item.BuildNumber,
			item.Channel,
			item.Status,
			item.SignerThumbprint,
			item.MainBinaryHash,
			item.ResourceManifestHash,
			item.BusinessManifestSHA256,
			item.ProtectedDBSchemaHash,
			item.ProtectedDBTablesHash,
			item.AssetsManifestSHA256,
			item.WorkflowManifestSHA256,
			item.DownloadURL,
			item.PackageSHA256,
			item.Mandatory,
			item.MinSupportedVersion,
			item.RolloutPercent,
			item.ReleaseNotes,
			item.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert release %s: %w", item.ID, err)
		}
	}

	for _, item := range data.SDKKeys {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sdk_keys (
				id, app_id, public_key, secret_hash, key_prefix, status, last_used_at, created_at, rotated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			item.ID,
			item.AppID,
			item.PublicKey,
			item.SecretHash,
			item.KeyPrefix,
			item.Status,
			item.LastUsedAt,
			item.CreatedAt,
			item.RotatedAt,
		); err != nil {
			return fmt.Errorf("insert sdk key %s: %w", item.ID, err)
		}
	}

	for _, item := range data.CapabilityPolicies {
		limitsJSON, err := jsonForDB(item.LimitsJSON, map[string]any{})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO capability_policies (
				app_id, capability, required_entitlement, mode, message,
				limits_json, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
			item.AppID,
			item.Capability,
			item.RequiredEntitlement,
			item.Mode,
			item.Message,
			limitsJSON,
			item.CreatedAt,
			item.UpdatedAt,
		); err != nil {
			return fmt.Errorf("insert capability policy %s/%s: %w", item.AppID, item.Capability, err)
		}
	}

	for _, item := range data.Licenses {
		entitlements, err := jsonForDB(item.Entitlements, []string{})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO licenses (
				id, license_key_hash, license_key_prefix, app_id, plan_name, owner_type,
				owner_ref, max_devices, entitlements, expires_at, status, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13)`,
			item.ID,
			item.LicenseKeyHash,
			item.LicenseKeyPrefix,
			item.AppID,
			item.PlanName,
			item.OwnerType,
			item.OwnerRef,
			item.MaxDevices,
			entitlements,
			item.ExpiresAt,
			item.Status,
			item.CreatedAt,
			item.UpdatedAt,
		); err != nil {
			return fmt.Errorf("insert license %s: %w", item.ID, err)
		}
	}

	for _, item := range data.Devices {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devices (
				id, device_fingerprint_hash, install_id_hash, platform, os_version,
				machine_name_hash, risk_score, status, first_seen_at, last_seen_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			item.ID,
			item.DeviceFingerprintHash,
			item.InstallIDHash,
			item.Platform,
			item.OSVersion,
			item.MachineNameHash,
			item.RiskScore,
			item.Status,
			item.FirstSeenAt,
			item.LastSeenAt,
		); err != nil {
			return fmt.Errorf("insert device %s: %w", item.ID, err)
		}
	}

	for _, item := range data.Activations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO activations (
				id, license_id, device_id, app_id, activation_status,
				activated_at, last_verified_at, deactivated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			item.ID,
			item.LicenseID,
			item.DeviceID,
			item.AppID,
			item.ActivationStatus,
			item.ActivatedAt,
			item.LastVerifiedAt,
			item.DeactivatedAt,
		); err != nil {
			return fmt.Errorf("insert activation %s: %w", item.ID, err)
		}
	}

	for _, item := range data.IntegrityReports {
		businessIntegrityErrors, err := jsonForDB(item.BusinessIntegrityErrors, []string{})
		if err != nil {
			return err
		}
		dbEncryptionErrors, err := jsonForDB(item.DBEncryptionErrors, []string{})
		if err != nil {
			return err
		}
		suspiciousModules, err := jsonForDB(item.SuspiciousModules, []string{})
		if err != nil {
			return err
		}
		vmIndicators, err := jsonForDB(item.VMIndicators, []string{})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO integrity_reports (
				id, app_id, device_id, release_id, verify_session_id, platform,
				app_version, main_binary_hash, signer_thumbprint,
				business_manifest_sha256, business_manifest_signature_valid,
				protected_db_schema_hash, protected_db_tables_hash,
				assets_manifest_sha256, workflow_manifest_sha256,
				business_integrity_status, business_integrity_errors,
				db_encryption_status, db_encryption_errors,
				debugger_detected, suspicious_modules, vm_indicators, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb, $18, $19::jsonb, $20, $21::jsonb, $22::jsonb, $23)`,
			item.ID,
			item.AppID,
			item.DeviceID,
			item.ReleaseID,
			item.VerifySessionID,
			item.Platform,
			item.AppVersion,
			item.MainBinaryHash,
			item.SignerThumbprint,
			item.BusinessManifestSHA256,
			item.BusinessManifestSignatureValid,
			item.ProtectedDBSchemaHash,
			item.ProtectedDBTablesHash,
			item.AssetsManifestSHA256,
			item.WorkflowManifestSHA256,
			item.BusinessIntegrityStatus,
			businessIntegrityErrors,
			item.DBEncryptionStatus,
			dbEncryptionErrors,
			item.DebuggerDetected,
			suspiciousModules,
			vmIndicators,
			item.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert integrity report %s: %w", item.ID, err)
		}
	}

	for _, item := range data.RiskEvents {
		metadata, err := jsonForDB(item.Metadata, map[string]any{})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO risk_events (
				id, app_id, device_id, license_id, event_type, severity, action,
				summary, metadata, created_at, resolved_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)`,
			item.ID,
			item.AppID,
			item.DeviceID,
			item.LicenseID,
			item.EventType,
			item.Severity,
			item.Action,
			item.Summary,
			metadata,
			item.CreatedAt,
			item.ResolvedAt,
		); err != nil {
			return fmt.Errorf("insert risk event %s: %w", item.ID, err)
		}
	}

	for _, item := range data.AuditLogs {
		metadata, err := jsonForDB(item.Metadata, map[string]any{})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_logs (
				id, admin_id, action, target_type, target_id, ip, user_agent, metadata, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`,
			item.ID,
			item.AdminID,
			item.Action,
			item.TargetType,
			item.TargetID,
			item.IP,
			item.UserAgent,
			metadata,
			item.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert audit log %s: %w", item.ID, err)
		}
	}

	return nil
}

type sqlQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func dataIsEmpty(data Data) bool {
	return len(data.Admins) == 0 &&
		len(data.Apps) == 0 &&
		len(data.Releases) == 0 &&
		len(data.Licenses) == 0 &&
		len(data.CapabilityPolicies) == 0 &&
		len(data.Devices) == 0 &&
		len(data.Activations) == 0 &&
		len(data.IntegrityReports) == 0 &&
		len(data.RiskEvents) == 0 &&
		len(data.AuditLogs) == 0
}

func jsonForDB[T any](value T, fallback T) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if string(payload) == "null" {
		payload, err = json.Marshal(fallback)
		if err != nil {
			return "", err
		}
	}
	return string(payload), nil
}

func redactDatabaseURL(databaseURL string) string {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "<redacted>"
	}
	return parsed.Redacted()
}
