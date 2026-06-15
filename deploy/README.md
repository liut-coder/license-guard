# License Guard Deployment Templates

These templates are production-oriented starting points. Replace placeholders, wire secrets through your deployment platform, and keep PostgreSQL data plus `-key-dir` backed up together.

## Docker Compose

1. Copy `deploy/.env.example` to `deploy/.env`.
2. Replace `POSTGRES_PASSWORD`, `DATABASE_URL`, `LICENSEGUARD_HTTP_PORT`, `LICENSEGUARD_PUBLIC_BASE_URL`, and `LG_CORS_ALLOWED_ORIGINS`. Keep `LG_PRODUCTION=true` for production deployments. If this is a new production database, set `LG_BOOTSTRAP_ADMIN_ACCOUNT` and `LG_BOOTSTRAP_ADMIN_PASSWORD` for first startup only.
3. Start PostgreSQL, run migrations, then start the API:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --build
```

Older hosts with the standalone Compose binary can run the same template with `docker-compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --build`.

The Compose template runs `licenseguard-migrate` once before the API and stores signing keys in the `licenseguard_keys` volume. Do not delete or rotate that volume unless you intentionally invalidate issued tokens.

`LICENSEGUARD_PUBLIC_BASE_URL` must be the HTTPS URL clients and operators use externally, for example `https://licenseguard.example.com`. The server uses it to generate SDK endpoints and integration bundles.

`LG_CORS_ALLOWED_ORIGINS` should be a comma-separated list of concrete HTTPS origins that host the Admin UI or operator console, for example `https://licenseguard.example.com`. Use `*` only for local development.

`LG_PRODUCTION=true` makes `licenseguard-server` fail fast unless it runs with PostgreSQL, an explicit persistent `-key-dir`, concrete HTTPS CORS origins, and a HTTPS `LICENSEGUARD_PUBLIC_BASE_URL`. It also disables automatic demo seed data; an empty production database must already contain an admin or receive an explicit bootstrap admin through the `LG_BOOTSTRAP_ADMIN_*` variables.

## HTTPS Reverse Proxy

Use `deploy/nginx/licenseguard.conf` as the nginx baseline. Change `server_name` and certificate paths, then expose only HTTPS publicly. The API container should stay on loopback or a private network.

## Systemd

For a bare-metal or VM deployment:

1. Build binaries with `go build -buildvcs=false`.
2. Install `licenseguard-server` and `licenseguard-migrate` under `/usr/local/bin`.
3. Copy `web/admin` and `migrations` to `/opt/licenseguard`.
4. Create the `licenseguard` user and `/var/lib/licenseguard/keys`.
5. Copy `deploy/systemd/licenseguard.env.example` to `/etc/licenseguard/licenseguard.env` and replace the database URL plus `LG_CORS_ALLOWED_ORIGINS`. Keep `LG_PRODUCTION=true` unless this is a local development instance.
6. Install both unit files, then run:

```bash
systemctl daemon-reload
systemctl start licenseguard-migrate.service
systemctl enable --now licenseguard.service
```

## Operational Checks

- Run `bash scripts/production-check.sh` before cutting a deployable build.
- Back up PostgreSQL and `/var/lib/licenseguard/keys` together; follow `docs/06-backup-restore-runbook.md` and keep both artifacts under the same recovery point ID.
- `licenseguard-migrate -seed-demo` is rejected when `LG_PRODUCTION=true`; use demo seed only for local or demo databases.
- Remove `LG_BOOTSTRAP_ADMIN_PASSWORD` after first successful production login and rotate the bootstrap password through Admin UI.
- Keep `DATABASE_URL`, signing private keys, SDK secrets, admin tokens, and license keys out of logs and client bundles.
