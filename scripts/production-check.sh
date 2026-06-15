#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR=""

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

cd "$ROOT"

section() {
  printf '\n==> %s\n' "$1"
}

fail() {
  printf 'production-check failed: %s\n' "$1" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "missing required command: $1"
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    fail "missing required file: $1"
  fi
}

require_text() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if ! grep -Eiq -- "$pattern" "$file"; then
    fail "$label not found in $file"
  fi
}

require_cmd go
require_cmd bash
require_cmd node
require_cmd curl
require_cmd grep
require_cmd find
require_cmd sort

section "Required files"
require_file README.md
require_file docs/01-development-implementation-plan.md
require_file docs/04-production-readiness-checklist.md
require_file docs/06-backup-restore-runbook.md
require_file scripts/smoke.sh
require_file web/admin/index.html
require_file internal/licensecore/types.go
require_file internal/licensecore/server.go
require_file internal/licensecore/server_test.go

section "Documentation gates"
require_text README.md "Production Readiness Check" "production check README section"
require_text README.md "scripts/production-check\\.sh" "production check command"
require_text README.md "docs/04-production-readiness-checklist\\.md" "production checklist link"
require_text README.md "PostgreSQL Storage" "PostgreSQL storage guidance"
require_text README.md "licenseguard-migrate" "migration command guidance"
require_text README.md "-store postgres" "PostgreSQL runtime flag guidance"
require_text README.md "-key-dir" "signing key directory guidance"
require_text README.md "HTTPS" "HTTPS guidance"
require_text README.md "backup|backed up|备份" "backup guidance"
require_text README.md "docs/06-backup-restore-runbook\\.md" "backup runbook link"
require_text README.md "seed-demo.*not production|not production.*seed-demo|demo.*not production" "demo seed production caveat"
require_text docs/01-development-implementation-plan.md "多副本.*licenseguard-migrate|licenseguard-migrate.*多副本" "multi-replica migration guidance"
require_text docs/01-development-implementation-plan.md "-key-dir.*备份|备份.*-key-dir|signing-key\\.json.*备份" "signing key backup guidance"
require_text docs/01-development-implementation-plan.md "HTTPS" "deployment HTTPS requirement"
require_text docs/04-production-readiness-checklist.md "DATABASE_URL" "production database checklist"
require_text docs/04-production-readiness-checklist.md "signing-key\\.json" "signing key checklist"
require_text docs/04-production-readiness-checklist.md "secret_hash" "SDK key leak checklist"
require_text docs/04-production-readiness-checklist.md "seed-demo.*生产|生产.*seed-demo" "demo seed checklist"
require_text docs/04-production-readiness-checklist.md "06-backup-restore-runbook" "backup runbook checklist"
require_text docs/04-production-readiness-checklist.md "public.*HTTPS|HTTPS.*public|LICENSEGUARD_PUBLIC_BASE_URL" "public HTTPS URL checklist"
require_text docs/06-backup-restore-runbook.md "pg_dump" "PostgreSQL backup command"
require_text docs/06-backup-restore-runbook.md "pg_restore" "PostgreSQL restore command"
require_text docs/06-backup-restore-runbook.md "signing-key\\.json" "signing key restore guidance"
require_text docs/06-backup-restore-runbook.md "/v1/public-key" "public key restore validation"
require_text deploy/docker-compose.yml "licenseguard-migrate" "compose migration service"
require_text deploy/docker-compose.yml "-production=\\$\\{LG_PRODUCTION\\}" "compose migration production flag"
require_text deploy/docker-compose.yml "-public-base-url=\\$\\{LICENSEGUARD_PUBLIC_BASE_URL\\}" "compose public base URL flag"
require_text deploy/docker-compose.yml "LG_BOOTSTRAP_ADMIN_PASSWORD:[[:space:]]*\\$\\{LG_BOOTSTRAP_ADMIN_PASSWORD\\}" "compose bootstrap admin env"
require_text deploy/systemd/licenseguard-migrate.service "-production=\\$\\{LG_PRODUCTION\\}" "systemd migration production flag"
require_text deploy/systemd/licenseguard.service "-public-base-url=\\$\\{LICENSEGUARD_PUBLIC_BASE_URL\\}" "systemd public base URL flag"
require_text deploy/.env.example "LG_BOOTSTRAP_ADMIN_PASSWORD" "compose bootstrap admin env"
require_text deploy/.env.example "LICENSEGUARD_PUBLIC_BASE_URL=https://" "compose HTTPS public base URL env"
require_text deploy/systemd/licenseguard.env.example "LICENSEGUARD_PUBLIC_BASE_URL=https://" "systemd HTTPS public base URL env"
require_text deploy/nginx/licenseguard.conf 'return 301 https://\$host\$request_uri' "nginx HTTP to HTTPS redirect"
require_text deploy/nginx/licenseguard.conf "X-Forwarded-Proto https" "nginx HTTPS forwarded proto"

section "Migration chain"
expected=(
  "001_initial_schema.sql"
  "002_seed_demo.sql"
  "003_admins.sql"
  "004_system_settings.sql"
  "005_sdk_keys.sql"
  "006_integrity_business_fields.sql"
  "007_capability_policies.sql"
  "008_release_resource_fields.sql"
  "009_db_encryption_diagnostics.sql"
)
mapfile -t actual < <(find migrations -maxdepth 1 -type f -name '*.sql' -printf '%f\n' | sort)
if [[ "${#actual[@]}" -ne "${#expected[@]}" ]]; then
  printf 'expected migrations:\n%s\n' "${expected[@]}" >&2
  printf 'actual migrations:\n%s\n' "${actual[@]}" >&2
  fail "unexpected migration file count"
fi
for i in "${!expected[@]}"; do
  if [[ "${actual[$i]}" != "${expected[$i]}" ]]; then
    fail "migration order mismatch at index $i: expected ${expected[$i]}, got ${actual[$i]}"
  fi
  migration="${expected[$i]%.sql}"
  require_text "migrations/${expected[$i]}" "INSERT INTO[[:space:]]+schema_migrations\\(version\\)[[:space:]]+VALUES[[:space:]]+\\('$migration'\\)" "schema_migrations record for $migration"
done

section "Admin UI JavaScript parse"
node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('web/admin/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (scripts.length !== 1) {
  throw new Error(`expected one inline admin script, got ${scripts.length}`);
}
new Function(scripts[0][1]);
NODE

section "SDK key exposure guards"
if grep -RIn -- 'secret_hash' web/admin >/tmp/license-guard-production-check-secret-hash.txt 2>/dev/null; then
  cat /tmp/license-guard-production-check-secret-hash.txt >&2
  fail "admin UI references secret_hash"
fi
rm -f /tmp/license-guard-production-check-secret-hash.txt

node - <<'NODE'
const fs = require('fs');
const types = fs.readFileSync('internal/licensecore/types.go', 'utf8');
const server = fs.readFileSync('internal/licensecore/server.go', 'utf8');
const tests = fs.readFileSync('internal/licensecore/server_test.go', 'utf8');
const smoke = fs.readFileSync('scripts/smoke.sh', 'utf8');

const view = types.match(/type SDKKeyView struct \{([\s\S]*?)\n\}/);
if (!view) throw new Error('SDKKeyView is missing');
if (/SecretHash|secret_hash/.test(view[1])) throw new Error('SDKKeyView exposes secret_hash');

const sdkKeyViewResponses = server.match(/"sdk_key":\s*sdkKeyView\(sdkKey\)/g) || [];
if (sdkKeyViewResponses.length < 2) {
  throw new Error('SDK key create/rotate responses must use sdkKeyView');
}
if (!/sdkKeys := s\.sdkKeyViewsForAppLocked\(appID\)[\s\S]*"sdk_keys": sdkKeys/.test(server)) {
  throw new Error('app detail response must use sdkKeyViewsForAppLocked');
}
if (!/secret_hash/.test(tests) || !/sdk key leaked secret_hash/.test(tests)) {
  throw new Error('server tests must assert SDK key secret_hash is not exposed');
}
if (!/secret_hash/.test(smoke) || !/sdk key .*secret_hash/.test(smoke)) {
  throw new Error('smoke test must assert SDK key secret_hash is not exposed');
}
NODE

section "Go tests"
go test ./...

section "Go binary builds"
TMP_DIR="$(mktemp -d)"
go build -buildvcs=false -o "$TMP_DIR/licenseguard-server" ./cmd/licenseguard-server
go build -buildvcs=false -o "$TMP_DIR/licenseguard-migrate" ./cmd/licenseguard-migrate
[[ -x "$TMP_DIR/licenseguard-server" ]] || fail "server binary was not created"
[[ -x "$TMP_DIR/licenseguard-migrate" ]] || fail "migrate binary was not created"

section "End-to-end smoke"
bash scripts/smoke.sh

section "Production check complete"
printf 'All production readiness checks passed.\n'
