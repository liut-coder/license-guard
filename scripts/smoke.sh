#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-18090}"
DATA_DIR="$(mktemp -d)"
CLIENT_DIR="$(mktemp -d)"
OUTPUT_DIR="$(mktemp -d)"
export OUTPUT_DIR
LOG_FILE="$DATA_DIR/server.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$CLIENT_DIR" "$OUTPUT_DIR"
}
trap cleanup EXIT

cd "$ROOT"

go run ./cmd/licenseguard-server \
  -addr "127.0.0.1:${PORT}" \
  -data-dir "$DATA_DIR" \
  -admin-dir ./web/admin >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

for _ in {1..80}; do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null

node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('web/admin/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (scripts.length !== 1) throw new Error('expected one inline admin script, got ' + scripts.length);
new Function(scripts[0][1]);
NODE

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account: 'admin@example.com', password: 'wrong-password'})
  });
  if (res.status !== 401) {
    throw new Error('invalid admin login should be rejected, got ' + res.status);
  }
})();
NODE

PUBLIC_KEY="$(
  node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/v1/public-key');
  if (!res.ok) process.exit(1);
  const data = await res.json();
  if (data.alg !== 'EdDSA' || data.key_type !== 'Ed25519' || !data.public_key) {
    throw new Error('unexpected public key response: ' + JSON.stringify(data));
  }
  console.log(data.public_key);
})();
NODE
)"

TOKEN="$(
  node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account: 'admin@example.com', password: 'ChangeMe123!'})
  });
  if (!res.ok) process.exit(1);
  const data = await res.json();
  console.log(data.admin_token);
})();
NODE
)"

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/dashboard', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) throw new Error('dashboard failed');
  const data = await res.json();
  if (data.app_count !== 1 || data.active_license_count !== 1) {
    throw new Error('unexpected dashboard metrics: ' + JSON.stringify(data));
  }
})();
NODE

node - <<NODE
(async () => {
  const before = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!before.ok) throw new Error('app detail before sdk rotate failed: ' + await before.text());
  const beforeData = await before.json();
  const beforeKeys = beforeData.sdk_keys || [];
  if (beforeKeys.length !== 1 || beforeKeys[0].status !== 'active' || !beforeKeys[0].key_prefix) {
    throw new Error('unexpected initial sdk keys: ' + JSON.stringify(beforeKeys));
  }
  if ('secret_hash' in beforeKeys[0]) throw new Error('sdk key detail leaked secret_hash');
  const oldPrefix = beforeKeys[0].key_prefix;

  const rotated = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/sdk-keys/rotate', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!rotated.ok) throw new Error('sdk key rotate failed: ' + await rotated.text());
  const rotatedData = await rotated.json();
  if (!rotatedData.sdk_secret || !rotatedData.sdk_secret.startsWith('lgsk_')) {
    throw new Error('sdk key rotate did not return one-time secret: ' + JSON.stringify(rotatedData));
  }
  if (!rotatedData.sdk_key || rotatedData.sdk_key.status !== 'active' || !rotatedData.sdk_key.key_prefix) {
    throw new Error('sdk key rotate returned invalid sdk_key: ' + JSON.stringify(rotatedData));
  }
  if ('secret_hash' in rotatedData.sdk_key) throw new Error('sdk key rotate leaked secret_hash');
  const newPrefix = rotatedData.sdk_key.key_prefix;
  if (newPrefix === oldPrefix) throw new Error('sdk key prefix did not change after rotate');

  const after = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!after.ok) throw new Error('app detail after sdk rotate failed: ' + await after.text());
  const afterData = await after.json();
  const afterKeys = afterData.sdk_keys || [];
  if (afterKeys.some((item) => 'secret_hash' in item)) throw new Error('sdk key list leaked secret_hash');
  const active = afterKeys.find((item) => item.status === 'active');
  const old = afterKeys.find((item) => item.key_prefix === oldPrefix);
  if (!active || active.key_prefix !== newPrefix || !old || old.status !== 'rotated') {
    throw new Error('sdk key states not updated: ' + JSON.stringify(afterKeys));
  }

  const onboarding = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/onboarding', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!onboarding.ok) throw new Error('app onboarding failed: ' + await onboarding.text());
  const onboardingData = await onboarding.json();
  if (!onboardingData.has_active_sdk_key || !onboardingData.has_release || !onboardingData.has_license) {
    throw new Error('unexpected onboarding base state: ' + JSON.stringify(onboardingData));
  }
  const sdkStep = (onboardingData.steps || []).find((item) => item.id === 'sdk_key_active');
  if (!sdkStep || sdkStep.status !== 'passed') {
    throw new Error('sdk_key_active onboarding step not passed: ' + JSON.stringify(onboardingData.steps));
  }

  const bundle = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/integration-bundle', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({endpoint: 'http://127.0.0.1:${PORT}/v1'})
  });
  if (!bundle.ok) throw new Error('integration bundle failed: ' + await bundle.text());
  if (bundle.headers.get('content-type') !== 'application/zip') {
    throw new Error('integration bundle content-type was ' + bundle.headers.get('content-type'));
  }
  const zip = new Uint8Array(await bundle.arrayBuffer());
  if (zip.length < 400 || zip[0] !== 0x50 || zip[1] !== 0x4b) {
    throw new Error('integration bundle was not a zip payload, size=' + zip.length);
  }
})();
NODE

node - <<NODE
(async () => {
  const patch = await fetch('http://127.0.0.1:${PORT}/admin/settings', {
    method: 'PATCH',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      default_token_ttl_minutes: 90,
      medium_risk_token_ttl_minutes: 20,
      offline_grace_days: 2,
      default_max_devices: 4,
      default_license_days: 90,
      audit_log_retention_days: 180,
      mfa_required: false,
      sensitive_action_confirm: true
    })
  });
  if (!patch.ok) throw new Error('settings patch failed: ' + await patch.text());
  const patched = await patch.json();
  if (patched.settings.default_max_devices !== 4 || patched.settings.default_license_days !== 90 || patched.settings.offline_grace_days !== 2) {
    throw new Error('unexpected patched settings: ' + JSON.stringify(patched));
  }

  const get = await fetch('http://127.0.0.1:${PORT}/admin/settings', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!get.ok) throw new Error('settings get failed: ' + await get.text());
  const current = await get.json();
  if (!current.settings.sensitive_action_confirm || current.settings.default_token_ttl_minutes !== 90) {
    throw new Error('settings were not persisted: ' + JSON.stringify(current));
  }

  const license = await fetch('http://127.0.0.1:${PORT}/admin/licenses', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({app_id: 'app_nax_desktop_prod', owner_ref: 'settings-smoke-defaults'})
  });
  if (!license.ok) throw new Error('settings default license create failed: ' + await license.text());
  const licenseData = await license.json();
  if (licenseData.license.max_devices !== 4) {
    throw new Error('settings default max_devices was not applied: ' + JSON.stringify(licenseData));
  }
  const days = (new Date(licenseData.license.expires_at).getTime() - Date.now()) / (24 * 60 * 60 * 1000);
  if (days < 89 || days > 91) {
    throw new Error('settings default license days was not applied: ' + JSON.stringify(licenseData));
  }
})();
NODE

LATEST_RELEASE_ID="$(
  node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/releases', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      platform: 'windows',
      version: '1.5.0',
      build_number: 10500,
      channel: 'production',
      status: 'active',
      mandatory: true,
      rollout_percent: 100,
      main_binary_hash: 'demo-main-binary-sha256-v150',
      signer_thumbprint: 'demo-signer-thumbprint',
      download_url: 'https://download.example.com/nax-desktop/1.5.0/setup.exe',
      package_sha256: 'demo-package-v150-sha256',
      release_notes: 'Mandatory smoke-test release'
    })
  });
  if (!res.ok) throw new Error('create latest release failed: ' + await res.text());
  const data = await res.json();
  console.log(data.release.id);
})();
NODE
)"

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode activate >$OUTPUT_DIR/license-guard-activate.json

grep -q '"allowed": true' $OUTPUT_DIR/license-guard-activate.json
grep -q '"available": true' $OUTPUT_DIR/license-guard-activate.json
grep -q '"required": true' $OUTPUT_DIR/license-guard-activate.json
grep -q '"latest_version": "1.5.0"' $OUTPUT_DIR/license-guard-activate.json
grep -q 'export.enabled: true' $OUTPUT_DIR/license-guard-activate.json

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode local >$OUTPUT_DIR/license-guard-local.json

grep -q '"allowed": true' $OUTPUT_DIR/license-guard-local.json
grep -q 'export.enabled: true' $OUTPUT_DIR/license-guard-local.json

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/releases/${LATEST_RELEASE_ID}', {
    method: 'PATCH',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({mandatory: false, rollout_percent: 0, min_supported_version: ''})
  });
  if (!res.ok) throw new Error('release rollout patch failed: ' + await res.text());
})();
NODE

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-rollout-zero.json

node - <<'NODE'
const fs = require('fs');
const data = JSON.parse(fs.readFileSync(process.env.OUTPUT_DIR + '/license-guard-rollout-zero.json', 'utf8'));
if (!data.allowed) throw new Error('rollout zero verification should be allowed');
if (data.update && data.update.available) throw new Error('rollout zero should not return an update advisory');
NODE

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/releases/${LATEST_RELEASE_ID}', {
    method: 'PATCH',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({mandatory: false, rollout_percent: 0, min_supported_version: '1.5.0'})
  });
  if (!res.ok) throw new Error('release min-supported patch failed: ' + await res.text());
})();
NODE

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-min-supported-update.json

grep -q '"available": true' $OUTPUT_DIR/license-guard-min-supported-update.json
grep -q '"required": true' $OUTPUT_DIR/license-guard-min-supported-update.json
grep -q '"latest_version": "1.5.0"' $OUTPUT_DIR/license-guard-min-supported-update.json

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/stolen_install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-stolen-token.json 2>$OUTPUT_DIR/license-guard-stolen-token.err
STOLEN_TOKEN_EXIT=$?
set -e

if [[ "$STOLEN_TOKEN_EXIT" -eq 0 ]]; then
  echo "stolen token verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-stolen-token.json
grep -q '"code": "TOKEN_DEVICE_MISMATCH"' $OUTPUT_DIR/license-guard-stolen-token.json

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/stolen_install_id_heartbeat" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode heartbeat >$OUTPUT_DIR/license-guard-stolen-heartbeat.txt 2>$OUTPUT_DIR/license-guard-stolen-heartbeat.err
STOLEN_HEARTBEAT_EXIT=$?
set -e

if [[ "$STOLEN_HEARTBEAT_EXIT" -eq 0 ]]; then
  echo "stolen token heartbeat unexpectedly passed" >&2
  exit 1
fi
grep -q 'TOKEN_DEVICE_MISMATCH' $OUTPUT_DIR/license-guard-stolen-heartbeat.err

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-verify.json

grep -q '"allowed": true' $OUTPUT_DIR/license-guard-verify.json

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode heartbeat >$OUTPUT_DIR/license-guard-heartbeat.txt

grep -q 'heartbeat ok' $OUTPUT_DIR/license-guard-heartbeat.txt

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/onboarding', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) throw new Error('onboarding after client verification failed: ' + await res.text());
  const data = await res.json();
  for (const id of ['first_activation', 'online_verify', 'heartbeat', 'integrity_report']) {
    const step = (data.steps || []).find((item) => item.id === id);
    if (!step || step.status !== 'passed') {
      throw new Error(id + ' onboarding step not passed: ' + JSON.stringify(data.steps));
    }
  }
  if (!data.latest_device || !data.latest_integrity_report) {
    throw new Error('onboarding missing latest device or integrity report: ' + JSON.stringify(data));
  }
})();
NODE

KNOWN_DEVICE_IDS="$(
  node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/devices', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) process.exit(1);
  const data = await res.json();
  console.log(JSON.stringify((data.items || []).map((item) => item.id)));
})();
NODE
)"

LG_INSTALL_ID_PATH="$CLIENT_DIR/deactivate_install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/deactivate_token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode activate >$OUTPUT_DIR/license-guard-deactivate-activate.json

DEACTIVATE_DEVICE_ID="$(
  node - <<NODE
(async () => {
  const known = new Set(${KNOWN_DEVICE_IDS});
  const res = await fetch('http://127.0.0.1:${PORT}/admin/devices', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) process.exit(1);
  const data = await res.json();
  const created = (data.items || []).find((item) => !known.has(item.id));
  if (!created) process.exit(1);
  console.log(created.id);
})();
NODE
)"

cp "$CLIENT_DIR/deactivate_token.json" "$CLIENT_DIR/deactivate_token_old.json"

LG_INSTALL_ID_PATH="$CLIENT_DIR/deactivate_install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/deactivate_token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode deactivate >$OUTPUT_DIR/license-guard-deactivate.txt

grep -q 'deactivate ok' $OUTPUT_DIR/license-guard-deactivate.txt
cp "$CLIENT_DIR/deactivate_token_old.json" "$CLIENT_DIR/deactivate_token.json"

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/deactivate_install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/deactivate_token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-deactivated-token.json 2>$OUTPUT_DIR/license-guard-deactivated-token.err
DEACTIVATED_TOKEN_EXIT=$?
set -e

if [[ "$DEACTIVATED_TOKEN_EXIT" -eq 0 ]]; then
  echo "deactivated token verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-deactivated-token.json
grep -q '"code": "TOKEN_DEACTIVATED"' $OUTPUT_DIR/license-guard-deactivated-token.json

LG_INSTALL_ID_PATH="$CLIENT_DIR/deactivate_install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/deactivate_token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode activate >$OUTPUT_DIR/license-guard-reactivate.json

grep -q '"allowed": true' $OUTPUT_DIR/license-guard-reactivate.json

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/devices/${DEACTIVATE_DEVICE_ID}/unbind', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!res.ok) throw new Error('device unbind failed: ' + await res.text());
})();
NODE

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/deactivate_install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/deactivate_token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-unbound-token.json 2>$OUTPUT_DIR/license-guard-unbound-token.err
UNBOUND_TOKEN_EXIT=$?
set -e

if [[ "$UNBOUND_TOKEN_EXIT" -eq 0 ]]; then
  echo "unbound token verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-unbound-token.json
grep -q '"code": "TOKEN_DEACTIVATED"' $OUTPUT_DIR/license-guard-unbound-token.json

DEVICE_ID="$(
  node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/devices', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) process.exit(1);
  const data = await res.json();
  console.log(data.items[0].id);
})();
NODE
)"

node - <<NODE
(async () => {
  const block = await fetch('http://127.0.0.1:${PORT}/admin/devices/${DEVICE_ID}/block', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!block.ok) throw new Error('device block failed: ' + await block.text());
})();
NODE

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-blocked-device.json 2>$OUTPUT_DIR/license-guard-blocked-device.err
BLOCKED_DEVICE_EXIT=$?
set -e

if [[ "$BLOCKED_DEVICE_EXIT" -eq 0 ]]; then
  echo "blocked device verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-blocked-device.json
grep -q '"code": "DEVICE_BLOCKED"' $OUTPUT_DIR/license-guard-blocked-device.json

node - <<NODE
(async () => {
  const unblock = await fetch('http://127.0.0.1:${PORT}/admin/devices/${DEVICE_ID}/unblock', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!unblock.ok) throw new Error('device unblock failed: ' + await unblock.text());
})();
NODE

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify -binary-hash tampered-hash >$OUTPUT_DIR/license-guard-tamper.json 2>$OUTPUT_DIR/license-guard-tamper.err
TAMPER_EXIT=$?
set -e

if [[ "$TAMPER_EXIT" -eq 0 ]]; then
  echo "tamper verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-tamper.json
grep -q '"code": "INTEGRITY_FAILED"' $OUTPUT_DIR/license-guard-tamper.json

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/apps/app_nax_desktop_prod/releases', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      platform: 'windows',
      version: '1.3.0',
      build_number: 10300,
      channel: 'production',
      status: 'blocked',
      mandatory: false,
      rollout_percent: 100,
      main_binary_hash: 'demo-main-binary-sha256-v130',
      signer_thumbprint: 'demo-signer-thumbprint',
      release_notes: 'Blocked smoke-test release'
    })
  });
  if (!res.ok) throw new Error('create blocked release failed: ' + await res.text());
})();
NODE

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify -version 1.3.0 -binary-hash demo-main-binary-sha256-v130 >$OUTPUT_DIR/license-guard-blocked-version.json 2>$OUTPUT_DIR/license-guard-blocked-version.err
BLOCKED_VERSION_EXIT=$?
set -e

if [[ "$BLOCKED_VERSION_EXIT" -eq 0 ]]; then
  echo "blocked version verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-blocked-version.json
grep -q '"code": "INTEGRITY_FAILED"' $OUTPUT_DIR/license-guard-blocked-version.json

LICENSE_ID="$(
  node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/licenses', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) process.exit(1);
  const data = await res.json();
  const demo = data.items.find((item) => item.license_key_prefix === 'LG-DEMO-2026');
  console.log(demo.id);
})();
NODE
)"

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/licenses/${LICENSE_ID}/suspend', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!res.ok) throw new Error('license suspend failed: ' + await res.text());
})();
NODE

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-suspended-license.json 2>$OUTPUT_DIR/license-guard-suspended-license.err
SUSPENDED_LICENSE_EXIT=$?
set -e

if [[ "$SUSPENDED_LICENSE_EXIT" -eq 0 ]]; then
  echo "suspended license verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-suspended-license.json
grep -q '"code": "LICENSE_SUSPENDED"' $OUTPUT_DIR/license-guard-suspended-license.json

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/licenses/${LICENSE_ID}/resume', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!res.ok) throw new Error('license resume failed: ' + await res.text());
})();
NODE

LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-resumed-license.json

grep -q '"allowed": true' $OUTPUT_DIR/license-guard-resumed-license.json

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/licenses/${LICENSE_ID}/revoke', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!res.ok) throw new Error('license revoke failed: ' + await res.text());
})();
NODE

set +e
LG_INSTALL_ID_PATH="$CLIENT_DIR/install_id" \
LG_TOKEN_CACHE_PATH="$CLIENT_DIR/token.json" \
go run ./examples/windows-go-demo -endpoint "http://127.0.0.1:${PORT}/v1" -public-key "$PUBLIC_KEY" -mode verify >$OUTPUT_DIR/license-guard-revoked-license.json 2>$OUTPUT_DIR/license-guard-revoked-license.err
REVOKED_LICENSE_EXIT=$?
set -e

if [[ "$REVOKED_LICENSE_EXIT" -eq 0 ]]; then
  echo "revoked license verification unexpectedly passed" >&2
  exit 1
fi
grep -q '"allowed": false' $OUTPUT_DIR/license-guard-revoked-license.json
grep -q '"code": "LICENSE_REVOKED"' $OUTPUT_DIR/license-guard-revoked-license.json

node - <<NODE
(async () => {
  const res = await fetch('http://127.0.0.1:${PORT}/admin/risk-events', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!res.ok) throw new Error('risk-events failed');
  const data = await res.json();
  const riskItems = data.items || [];
  const found = riskItems.find((item) => item.event_type === 'binary_hash_mismatch');
  if (!found) throw new Error('binary_hash_mismatch risk event not found');
  const blockedVersion = (data.items || []).some((item) => item.event_type === 'app_version_blocked');
  if (!blockedVersion) throw new Error('app_version_blocked risk event not found');
  const blockedDevice = (data.items || []).some((item) => item.event_type === 'device_blocked');
  if (!blockedDevice) throw new Error('device_blocked risk event not found');
  const tokenDeviceMismatch = (data.items || []).some((item) => item.event_type === 'token_device_mismatch');
  if (!tokenDeviceMismatch) throw new Error('token_device_mismatch risk event not found');
  const tokenActivationInactive = (data.items || []).some((item) => item.event_type === 'token_activation_inactive');
  if (!tokenActivationInactive) throw new Error('token_activation_inactive risk event not found');

  const resolved = await fetch('http://127.0.0.1:${PORT}/admin/risk-events/' + encodeURIComponent(found.id) + '/resolve', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!resolved.ok) throw new Error('risk resolve failed: ' + await resolved.text());
  const resolvedData = await resolved.json();
  if (!resolvedData.risk_event || !resolvedData.risk_event.resolved_at) {
    throw new Error('risk resolve did not set resolved_at: ' + JSON.stringify(resolvedData));
  }

  const reread = await fetch('http://127.0.0.1:${PORT}/admin/risk-events', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!reread.ok) throw new Error('risk-events reread failed');
  const rereadData = await reread.json();
  const persisted = (rereadData.items || []).find((item) => item.id === found.id);
  if (!persisted || !persisted.resolved_at) throw new Error('resolved risk event was not persisted');

  const audits = await fetch('http://127.0.0.1:${PORT}/admin/audit-logs', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (!audits.ok) throw new Error('audit logs failed');
  const auditData = await audits.json();
  const auditFound = (auditData.items || []).some((item) => item.action === 'risk.resolve' && item.target_id === found.id);
  if (!auditFound) throw new Error('risk.resolve audit log not found');
  const settingsAuditFound = (auditData.items || []).some((item) => item.action === 'settings.update' && item.target_id === 'system');
  if (!settingsAuditFound) throw new Error('settings.update audit log not found');
  const sdkRotateAuditFound = (auditData.items || []).some((item) => item.action === 'sdk_key.rotate' && item.target_id === 'app_nax_desktop_prod');
  if (!sdkRotateAuditFound) throw new Error('sdk_key.rotate audit log not found');
})();
NODE

node - <<NODE
(async () => {
  const secondLogin = await fetch('http://127.0.0.1:${PORT}/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account: 'admin@example.com', password: 'ChangeMe123!'})
  });
  if (!secondLogin.ok) throw new Error('second admin login failed before password change: ' + await secondLogin.text());
  const secondLoginData = await secondLogin.json();

  const passwordChange = await fetch('http://127.0.0.1:${PORT}/admin/me/password', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: JSON.stringify({current_password: 'ChangeMe123!', new_password: 'NewChangeMe123!'})
  });
  if (!passwordChange.ok) throw new Error('admin password change failed: ' + await passwordChange.text());

  const otherSession = await fetch('http://127.0.0.1:${PORT}/admin/me', {
    headers: {Authorization: 'Bearer ' + secondLoginData.admin_token}
  });
  if (otherSession.status !== 401) {
    throw new Error('other admin session should be rejected after password change, got ' + otherSession.status);
  }

  const oldPasswordLogin = await fetch('http://127.0.0.1:${PORT}/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account: 'admin@example.com', password: 'ChangeMe123!'})
  });
  if (oldPasswordLogin.status !== 401) {
    throw new Error('old admin password should be rejected after password change, got ' + oldPasswordLogin.status);
  }

  const logout = await fetch('http://127.0.0.1:${PORT}/admin/logout', {
    method: 'POST',
    headers: {Authorization: 'Bearer ${TOKEN}', 'Content-Type': 'application/json'},
    body: '{}'
  });
  if (!logout.ok) throw new Error('admin logout failed: ' + await logout.text());

  const rejected = await fetch('http://127.0.0.1:${PORT}/admin/me', {
    headers: {Authorization: 'Bearer ${TOKEN}'}
  });
  if (rejected.status !== 401) {
    throw new Error('logged out token should be rejected, got ' + rejected.status);
  }

  const login = await fetch('http://127.0.0.1:${PORT}/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account: 'admin@example.com', password: 'NewChangeMe123!'})
  });
  if (!login.ok) throw new Error('admin relogin failed: ' + await login.text());
  const loginData = await login.json();

  const audits = await fetch('http://127.0.0.1:${PORT}/admin/audit-logs', {
    headers: {Authorization: 'Bearer ' + loginData.admin_token}
  });
  if (!audits.ok) throw new Error('audit logs after logout failed');
  const auditData = await audits.json();
  const logoutFound = (auditData.items || []).some((item) => item.action === 'admin.logout');
  if (!logoutFound) throw new Error('admin.logout audit log not found');
  const passwordUpdateFound = (auditData.items || []).some((item) => item.action === 'admin.password.update');
  if (!passwordUpdateFound) throw new Error('admin.password.update audit log not found');
})();
NODE

echo "License Guard smoke test passed"
