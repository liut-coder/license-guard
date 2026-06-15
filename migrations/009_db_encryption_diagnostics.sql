ALTER TABLE integrity_reports
  ADD COLUMN IF NOT EXISTS db_encryption_status text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS db_encryption_errors jsonb NOT NULL DEFAULT '[]'::jsonb;

INSERT INTO schema_migrations(version) VALUES ('009_db_encryption_diagnostics')
ON CONFLICT (version) DO NOTHING;
