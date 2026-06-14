CREATE TABLE IF NOT EXISTS system_settings (
  id text PRIMARY KEY,
  default_token_ttl_minutes integer NOT NULL DEFAULT 720,
  medium_risk_token_ttl_minutes integer NOT NULL DEFAULT 30,
  offline_grace_days integer NOT NULL DEFAULT 7,
  default_max_devices integer NOT NULL DEFAULT 3,
  default_license_days integer NOT NULL DEFAULT 365,
  audit_log_retention_days integer NOT NULL DEFAULT 365,
  mfa_required boolean NOT NULL DEFAULT false,
  sensitive_action_confirm boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO system_settings (
  id,
  default_token_ttl_minutes,
  medium_risk_token_ttl_minutes,
  offline_grace_days,
  default_max_devices,
  default_license_days,
  audit_log_retention_days,
  mfa_required,
  sensitive_action_confirm,
  updated_at
) VALUES (
  'system',
  720,
  30,
  7,
  3,
  365,
  365,
  false,
  false,
  now()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO schema_migrations(version) VALUES ('004_system_settings')
ON CONFLICT (version) DO NOTHING;
