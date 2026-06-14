-- Optional local seed data matching the JSONStore seed.

INSERT INTO apps (
  id, app_key, name, description, owner_team, status, created_at, updated_at
) VALUES (
  'app_demo_nax',
  'app_nax_desktop_prod',
  'Nax Desktop',
  'Windows Go demo application',
  'Core',
  'active',
  now(),
  now()
) ON CONFLICT (app_key) DO NOTHING;

INSERT INTO app_releases (
  id, app_id, platform, version, build_number, channel, status,
  signer_thumbprint, main_binary_hash, download_url, package_sha256,
  mandatory, rollout_percent, release_notes, created_at
) VALUES (
  'rel_demo_nax_142',
  'app_nax_desktop_prod',
  'windows',
  '1.4.2',
  10402,
  'production',
  'active',
  'demo-signer-thumbprint',
  'demo-main-binary-sha256',
  'https://download.example.com/nax-desktop/1.4.2/setup.exe',
  'demo-package-sha256',
  false,
  100,
  'Seed release for local Windows Go integration.',
  now()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO licenses (
  id, license_key_hash, license_key_prefix, app_id, plan_name,
  owner_type, owner_ref, max_devices, entitlements, expires_at, status,
  created_at, updated_at
) VALUES (
  'lic_demo_windows',
  '01a58fe9acb5f56a09c5d095ed425357938ed59829bc16b70148cb6ced8d3d00',
  'LG-DEMO-2026',
  'app_nax_desktop_prod',
  'Pro',
  'user',
  'demo-customer',
  3,
  '["feature.pro", "export.enabled"]'::jsonb,
  now() + interval '365 days',
  'active',
  now(),
  now()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO schema_migrations(version) VALUES ('002_seed_demo')
ON CONFLICT (version) DO NOTHING;

