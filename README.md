# License Guard

License Guard is a local MVP implementation of the authorization and integrity platform described in `docs/`.

It currently delivers the first closed loop:

- Admin API and Admin UI
- Persistent admin accounts with bcrypt password hashes
- Admin password change with current-password verification, audit logging, and other-session invalidation
- Admin logout session invalidation with audit trail
- Admin SDK onboarding workbench with progress evidence, generated snippets, demo commands, and integration bundle download
- Admin settings for default license policy, token TTL, offline grace, audit retention, and security switches
- SDK key lifecycle with one-time secret rotation and audit logging
- Read-only SDK onboarding status API and secret-free integration bundle generation
- Multi-app registry seed
- License issue/list APIs
- License revoke/suspend/resume actions
- Release creation and release status management
- Windows Go client challenge, activate, verify, heartbeat, deactivate
- Ed25519 signed short-lived license token
- Device binding and max device enforcement
- Client deactivate and admin device unbind lifecycle
- License token device binding and stolen-token transfer denial
- Device block/unblock actions
- Integrity report persistence
- Update advisory for newer releases, mandatory updates, minimum supported versions, and staged rollout
- Blocked release denial
- Binary hash mismatch risk event and deny action
- Risk event resolve action with audit trail
- Local JSON persistence for development
- PostgreSQL schema migrations and runtime storage backend

## Quick Start

```bash
cd /root/license-guard
go run ./cmd/licenseguard-server -addr 127.0.0.1:8090 -data-dir ./data -admin-dir ./web/admin
```

Open:

```text
http://127.0.0.1:8090/admin-ui/
```

Demo admin:

```text
admin@example.com
ChangeMe123!
```

Seed Windows Go app:

```text
App ID: app_nax_desktop_prod
License: LG-DEMO-2026-WINDOWS
Version: 1.4.2
Binary hash: demo-main-binary-sha256
Signer: demo-signer-thumbprint
```

## Windows Go Demo

Fetch the demo public key:

```bash
go run ./examples/windows-go-demo -mode public-key
```

Use the returned `public_key` when you want the SDK demo to validate cached license tokens locally.

Activate:

```bash
LG_INSTALL_ID_PATH=/tmp/license-guard-demo/install_id \
LG_TOKEN_CACHE_PATH=/tmp/license-guard-demo/token.json \
go run ./examples/windows-go-demo -mode activate -public-key '<public_key>'
```

Verify:

```bash
LG_INSTALL_ID_PATH=/tmp/license-guard-demo/install_id \
LG_TOKEN_CACHE_PATH=/tmp/license-guard-demo/token.json \
go run ./examples/windows-go-demo -mode verify -public-key '<public_key>'
```

Heartbeat:

```bash
LG_INSTALL_ID_PATH=/tmp/license-guard-demo/install_id \
LG_TOKEN_CACHE_PATH=/tmp/license-guard-demo/token.json \
go run ./examples/windows-go-demo -mode heartbeat -public-key '<public_key>'
```

Deactivate:

```bash
LG_INSTALL_ID_PATH=/tmp/license-guard-demo/install_id \
LG_TOKEN_CACHE_PATH=/tmp/license-guard-demo/token.json \
go run ./examples/windows-go-demo -mode deactivate -public-key '<public_key>'
```

Local cached authorization check:

```bash
LG_INSTALL_ID_PATH=/tmp/license-guard-demo/install_id \
LG_TOKEN_CACHE_PATH=/tmp/license-guard-demo/token.json \
go run ./examples/windows-go-demo -mode local -public-key '<public_key>'
```

Tamper test:

```bash
LG_INSTALL_ID_PATH=/tmp/license-guard-demo/install_id \
LG_TOKEN_CACHE_PATH=/tmp/license-guard-demo/token.json \
go run ./examples/windows-go-demo -mode verify -public-key '<public_key>' -binary-hash tampered-hash
```

Expected result: `allowed=false`, `code=INTEGRITY_FAILED`, and a `binary_hash_mismatch` risk event in Admin UI.

## Smoke Test

```bash
bash scripts/smoke.sh
```

The smoke test starts an isolated server on `127.0.0.1:18090`, then verifies:

- Health endpoint
- Admin login
- Admin dashboard
- Admin logout session invalidation and audit logging
- Admin settings persistence, default license policy application, and audit logging
- SDK key rotation with one-time secret response, hash-only persistence, and audit logging
- SDK onboarding status aggregation and integration bundle zip generation
- Mandatory release creation and update advisory
- Release PATCH, staged rollout, and minimum-supported-version update rules
- Windows Go demo activation
- Windows Go demo verification
- Local cached token verification and stolen-token transfer denial
- Heartbeat
- Client deactivate and admin device unbind token invalidation
- Device block and `DEVICE_BLOCKED` denial
- Tampered binary hash denial
- Blocked app version denial
- License suspend/resume and `LICENSE_SUSPENDED` denial
- License revoke and `LICENSE_REVOKED` denial
- Risk event persistence
- Risk event resolve persistence and audit logging

## Production Readiness Check

Before a deployable build is accepted, run:

```bash
bash scripts/production-check.sh
```

The production check runs unit tests, builds the server and migration binaries, runs the end-to-end smoke test, and verifies deployment documentation, migration ordering, Admin UI JavaScript parsing, and SDK key `secret_hash` exposure guards.

Use `docs/04-production-readiness-checklist.md` as the manual gate for PostgreSQL, HTTPS, backups, persistent `-key-dir`, demo seed caveats, admin access controls, and multi-replica migration rollout. Use `docs/06-backup-restore-runbook.md` for the concrete PostgreSQL plus signing-key backup and restore sequence. Production traffic must use HTTPS; `licenseguard-migrate -seed-demo` is for local/demo databases, not production tenants.

## Deployment Templates

Production-oriented templates live under `deploy/`:

- `deploy/docker-compose.yml` starts PostgreSQL, runs `licenseguard-migrate`, then starts the API with a persistent signing-key volume.
- `deploy/.env.example` lists the environment values that must be replaced before deployment, including the HTTPS `LICENSEGUARD_PUBLIC_BASE_URL` used for client endpoints.
- `deploy/nginx/licenseguard.conf` is a HTTPS reverse-proxy baseline.
- `deploy/systemd/` contains VM/bare-metal service units for migration and API startup.

See `deploy/README.md` for the operational flow and `docs/06-backup-restore-runbook.md` for backup and restore steps.

## VisionFlow Authorization Productization

The current VisionFlow-facing roadmap is tracked in `docs/2026-06-15-visionflow-support-enhancement-plan.md`. It covers the one-command bootstrap flow, capability policy model, Admin UI policy editor, signed policy delivery, release automation, and acceptance checks for VisionFlow integration.

## VisionFlow Bootstrap CLI

`licenseguardctl` can create or reuse the VisionFlow app, seed the default capability policies, patch the local development release with integrity metadata, issue a development license, fetch the public key, and print env values VisionFlow can use directly:

```bash
go run ./cmd/licenseguardctl visionflow bootstrap \
  -server http://127.0.0.1:8090 \
  -admin-account admin@example.com \
  -admin-password 'ChangeMe123!' \
  -write-env ../vision-flow/.env.local
```

The generated env includes:

```text
LICENSE_GUARD_ENDPOINT
LICENSE_GUARD_APP_ID
LICENSE_GUARD_PUBLIC_KEY
LICENSE_GUARD_APP_VERSION
LICENSE_GUARD_BINARY_HASH
LICENSE_GUARD_SIGNER_THUMBPRINT
VISIONFLOW_LICENSE_KEY
```

## Authorization Diagnostics API

Admins can inspect a VisionFlow authorization decision with:

```text
GET /admin/apps/{app_id}/diagnostics?license_id=...&device_id=...&app_version=...&capability=...
```

The response explains the license, device, activation, release, capability policy, latest integrity report, latest risk event, and the latest `capability_denied` reason when present.

The Go SDK also decodes the signed `capability_policy` returned by `/activate` and `/verify`. When a public key is configured, cached authorization only exposes the policy bundle after its Ed25519 signature verifies.

For VisionFlow business integrity, the Go SDK exposes an `IntegrityHook` that can attach `business_manifest_sha256`, protected DB hashes, assets/workflow hashes, and `business_integrity_status` to activate, verify, and heartbeat calls. Heartbeat integrity denial is surfaced as an `APIError` instead of being treated as a successful heartbeat.

## Release Publish CLI

`licenseguardctl` can register a release without manually copying artifact hashes:

```bash
go run ./cmd/licenseguardctl release publish \
  -server https://licenseguard.example.com \
  -admin-token "$LICENSE_GUARD_ADMIN_TOKEN" \
  -app-id app_visionflow_windows_prod \
  -platform windows \
  -version 0.2.0 \
  -build-number 42 \
  -main-binary ./dist/VisionFlow.exe \
  -package ./dist/VisionFlowSetup.exe \
  -signer-thumbprint "<certificate-thumbprint>" \
  -download-url https://download.example.com/VisionFlowSetup.exe \
  -release-notes-file ./release-notes.md
```

The CLI computes `main_binary_hash` and `package_sha256` from the supplied files. Sign the EXE before running it.

## PostgreSQL Storage

JSON is still the default for local development. For a deployable server, initialize PostgreSQL first:

```bash
DATABASE_URL='postgres://user:pass@127.0.0.1:5432/license_guard?sslmode=disable' \
go run ./cmd/licenseguard-migrate -migrations-dir ./migrations
```

Optional demo seed:

```bash
DATABASE_URL='postgres://user:pass@127.0.0.1:5432/license_guard?sslmode=disable' \
go run ./cmd/licenseguard-migrate -migrations-dir ./migrations -seed-demo
```

Run the API with PostgreSQL:

```bash
DATABASE_URL='postgres://user:pass@127.0.0.1:5432/license_guard?sslmode=disable' \
go run ./cmd/licenseguard-server \
  -addr 127.0.0.1:8090 \
  -store postgres \
  -key-dir ./data \
  -admin-dir ./web/admin
```

For a small single-node deployment you can let the API apply schema migrations before startup:

```bash
DATABASE_URL='postgres://user:pass@127.0.0.1:5432/license_guard?sslmode=disable' \
go run ./cmd/licenseguard-server \
  -addr 127.0.0.1:8090 \
  -store postgres \
  -auto-migrate \
  -key-dir ./data \
  -admin-dir ./web/admin
```

Notes:

- `-key-dir` stores the Ed25519 signing key. Keep it persistent and backed up.
- In development mode, an empty store seeds the demo admin/app/license used by the local quickstart.
- In production mode, automatic demo seed is disabled. If the production store has no admins, set `LG_BOOTSTRAP_ADMIN_ACCOUNT` and `LG_BOOTSTRAP_ADMIN_PASSWORD` only for first startup, then rotate the password and remove the bootstrap secret.
- Admin credentials are stored as bcrypt hashes in the configured store after first startup.
- `licenseguard-migrate -seed-demo` is intended for local/demo databases. `LG_PRODUCTION=true` or `-production=true` makes the migration tool reject `-seed-demo`.

## API Surface

Admin:

```text
POST /admin/login
POST /admin/logout
POST /admin/me/password
GET  /admin/dashboard
GET  /admin/apps
POST /admin/apps
GET  /admin/apps/:id
GET  /admin/apps/:id/onboarding
POST /admin/apps/:id/integration-bundle
POST /admin/apps/:id/releases
POST /admin/apps/:id/sdk-keys/rotate
PATCH /admin/apps/:id/releases/:release_id
GET  /admin/licenses
POST /admin/licenses
POST /admin/licenses/:id/revoke
POST /admin/licenses/:id/suspend
POST /admin/licenses/:id/resume
GET  /admin/devices
POST /admin/devices/:id/block
POST /admin/devices/:id/unblock
POST /admin/devices/:id/unbind
GET  /admin/risk-events
POST /admin/risk-events/:id/resolve
GET  /admin/audit-logs
GET  /admin/settings
PATCH /admin/settings
```

Client:

```text
GET  /v1/public-key
POST /v1/challenge
POST /v1/activate
POST /v1/verify
POST /v1/heartbeat
POST /v1/deactivate
```

## Project Layout

```text
cmd/licenseguard-server        Go HTTP server entrypoint
cmd/licenseguard-migrate       PostgreSQL migration command
internal/licensecore           API, data model, token signing, risk logic
sdk/go/licenseguard            Windows Go SDK package
examples/windows-go-demo       CLI demo app using the SDK
web/admin                      API-connected Admin UI
docs                           Product, implementation, and integration docs
scripts/smoke.sh               End-to-end local verification
migrations                     PostgreSQL schema and optional demo seed
```

## Storage Modes

Local development uses JSON files under `data/`:

```text
data/store.json
data/signing-key.json
```

Production-oriented deployments can use PostgreSQL with the same API protocol. The current PostgreSQL adapter saves the same domain model transactionally, so client SDK integration does not change when switching storage modes.
