-- License Guard PostgreSQL schema
-- This schema mirrors the current Go domain model and is the target for the
-- next PostgreSQL Store implementation.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS apps (
  id text PRIMARY KEY,
  app_key text NOT NULL UNIQUE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  owner_team text NOT NULL DEFAULT '',
  status text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_apps_status ON apps(status);

CREATE TABLE IF NOT EXISTS app_releases (
  id text PRIMARY KEY,
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  platform text NOT NULL,
  version text NOT NULL,
  build_number integer NOT NULL DEFAULT 0,
  channel text NOT NULL DEFAULT 'production',
  status text NOT NULL,
  signer_thumbprint text NOT NULL DEFAULT '',
  main_binary_hash text NOT NULL DEFAULT '',
  resource_manifest_hash text NOT NULL DEFAULT '',
  download_url text NOT NULL DEFAULT '',
  package_sha256 text NOT NULL DEFAULT '',
  mandatory boolean NOT NULL DEFAULT false,
  min_supported_version text NOT NULL DEFAULT '',
  rollout_percent integer NOT NULL DEFAULT 100,
  release_notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  UNIQUE(app_id, platform, version, channel)
);

CREATE INDEX IF NOT EXISTS idx_app_releases_app_platform ON app_releases(app_id, platform);
CREATE INDEX IF NOT EXISTS idx_app_releases_lookup ON app_releases(app_id, platform, version);
CREATE INDEX IF NOT EXISTS idx_app_releases_latest ON app_releases(app_id, platform, status, build_number DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS licenses (
  id text PRIMARY KEY,
  license_key_hash text NOT NULL UNIQUE,
  license_key_prefix text NOT NULL,
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  plan_name text NOT NULL,
  owner_type text NOT NULL,
  owner_ref text NOT NULL DEFAULT '',
  max_devices integer NOT NULL,
  entitlements jsonb NOT NULL DEFAULT '[]'::jsonb,
  expires_at timestamptz NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_licenses_app ON licenses(app_id);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
CREATE INDEX IF NOT EXISTS idx_licenses_owner ON licenses(owner_type, owner_ref);

CREATE TABLE IF NOT EXISTS capability_policies (
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  capability text NOT NULL,
  required_entitlement text NOT NULL,
  mode text NOT NULL,
  message text NOT NULL DEFAULT '',
  limits_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY(app_id, capability)
);

CREATE INDEX IF NOT EXISTS idx_capability_policies_app ON capability_policies(app_id);
CREATE INDEX IF NOT EXISTS idx_capability_policies_entitlement ON capability_policies(app_id, required_entitlement);

CREATE TABLE IF NOT EXISTS devices (
  id text PRIMARY KEY,
  device_fingerprint_hash text NOT NULL UNIQUE,
  install_id_hash text NOT NULL,
  platform text NOT NULL,
  os_version text NOT NULL DEFAULT '',
  machine_name_hash text NOT NULL DEFAULT '',
  risk_score integer NOT NULL DEFAULT 0,
  status text NOT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_risk_score ON devices(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS activations (
  id text PRIMARY KEY,
  license_id text NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  device_id text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  activation_status text NOT NULL,
  activated_at timestamptz NOT NULL,
  last_verified_at timestamptz NOT NULL,
  deactivated_at timestamptz,
  UNIQUE(license_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_id);
CREATE INDEX IF NOT EXISTS idx_activations_device ON activations(device_id);
CREATE INDEX IF NOT EXISTS idx_activations_status ON activations(activation_status);

CREATE TABLE IF NOT EXISTS integrity_reports (
  id text PRIMARY KEY,
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  device_id text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  release_id text NOT NULL DEFAULT '',
  verify_session_id text NOT NULL DEFAULT '',
  platform text NOT NULL,
  app_version text NOT NULL DEFAULT '',
  main_binary_hash text NOT NULL DEFAULT '',
  signer_thumbprint text NOT NULL DEFAULT '',
  business_manifest_sha256 text NOT NULL DEFAULT '',
  business_manifest_signature_valid boolean,
  protected_db_schema_hash text NOT NULL DEFAULT '',
  protected_db_tables_hash text NOT NULL DEFAULT '',
  assets_manifest_sha256 text NOT NULL DEFAULT '',
  workflow_manifest_sha256 text NOT NULL DEFAULT '',
  business_integrity_status text NOT NULL DEFAULT '',
  business_integrity_errors jsonb NOT NULL DEFAULT '[]'::jsonb,
  debugger_detected boolean NOT NULL DEFAULT false,
  suspicious_modules jsonb NOT NULL DEFAULT '[]'::jsonb,
  vm_indicators jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_integrity_reports_app_created ON integrity_reports(app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_reports_device_created ON integrity_reports(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_reports_version ON integrity_reports(app_id, platform, app_version);

CREATE TABLE IF NOT EXISTS risk_events (
  id text PRIMARY KEY,
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  device_id text NOT NULL DEFAULT '',
  license_id text NOT NULL DEFAULT '',
  event_type text NOT NULL,
  severity text NOT NULL,
  action text NOT NULL,
  summary text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  resolved_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_risk_events_app_created ON risk_events(app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_type ON risk_events(event_type);
CREATE INDEX IF NOT EXISTS idx_risk_events_severity ON risk_events(severity);
CREATE INDEX IF NOT EXISTS idx_risk_events_device ON risk_events(device_id);
CREATE INDEX IF NOT EXISTS idx_risk_events_license ON risk_events(license_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id text PRIMARY KEY,
  admin_id text NOT NULL,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text NOT NULL,
  ip text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_created ON audit_logs(admin_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type, target_id);

INSERT INTO schema_migrations(version) VALUES ('001_initial_schema')
ON CONFLICT (version) DO NOTHING;
