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

INSERT INTO schema_migrations(version) VALUES ('007_capability_policies')
ON CONFLICT (version) DO NOTHING;
