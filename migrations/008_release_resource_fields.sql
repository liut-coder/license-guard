ALTER TABLE app_releases
  ADD COLUMN IF NOT EXISTS business_manifest_sha256 text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS protected_db_schema_hash text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS protected_db_tables_hash text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS assets_manifest_sha256 text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS workflow_manifest_sha256 text NOT NULL DEFAULT '';

INSERT INTO schema_migrations(version) VALUES ('008_release_resource_fields')
ON CONFLICT (version) DO NOTHING;
