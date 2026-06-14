CREATE TABLE IF NOT EXISTS admins (
  id text PRIMARY KEY,
  account text NOT NULL UNIQUE,
  name text NOT NULL,
  password_hash text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admins_status ON admins(status);

INSERT INTO schema_migrations(version) VALUES ('003_admins')
ON CONFLICT (version) DO NOTHING;
