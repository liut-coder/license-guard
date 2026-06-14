CREATE TABLE IF NOT EXISTS sdk_keys (
  id text PRIMARY KEY,
  app_id text NOT NULL REFERENCES apps(app_key) ON DELETE CASCADE,
  public_key text NOT NULL DEFAULT '',
  secret_hash text NOT NULL,
  key_prefix text NOT NULL,
  status text NOT NULL,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL,
  rotated_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_sdk_keys_app_status ON sdk_keys(app_id, status);
CREATE INDEX IF NOT EXISTS idx_sdk_keys_prefix ON sdk_keys(key_prefix);

INSERT INTO schema_migrations(version) VALUES ('005_sdk_keys')
ON CONFLICT (version) DO NOTHING;
