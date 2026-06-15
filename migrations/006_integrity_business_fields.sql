ALTER TABLE integrity_reports
  ADD COLUMN IF NOT EXISTS business_manifest_sha256 text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS business_manifest_signature_valid boolean,
  ADD COLUMN IF NOT EXISTS protected_db_schema_hash text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS protected_db_tables_hash text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS assets_manifest_sha256 text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS workflow_manifest_sha256 text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS business_integrity_status text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS business_integrity_errors jsonb NOT NULL DEFAULT '[]'::jsonb;

INSERT INTO schema_migrations(version) VALUES ('006_integrity_business_fields')
ON CONFLICT (version) DO NOTHING;
