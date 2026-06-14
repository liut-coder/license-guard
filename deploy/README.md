# License Guard Deployment Templates

These templates are production-oriented starting points. Replace placeholders, wire secrets through your deployment platform, and keep PostgreSQL data plus `-key-dir` backed up together.

## Docker Compose

1. Copy `deploy/.env.example` to `deploy/.env`.
2. Replace `POSTGRES_PASSWORD`, `DATABASE_URL`, `LICENSEGUARD_HTTP_PORT`, and `LICENSEGUARD_PUBLIC_BASE_URL`.
3. Start PostgreSQL, run migrations, then start the API:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --build
```

Older hosts with the standalone Compose binary can run the same template with `docker-compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --build`.

The Compose template runs `licenseguard-migrate` once before the API and stores signing keys in the `licenseguard_keys` volume. Do not delete or rotate that volume unless you intentionally invalidate issued tokens.

## HTTPS Reverse Proxy

Use `deploy/nginx/licenseguard.conf` as the nginx baseline. Change `server_name` and certificate paths, then expose only HTTPS publicly. The API container should stay on loopback or a private network.

## Systemd

For a bare-metal or VM deployment:

1. Build binaries with `go build -buildvcs=false`.
2. Install `licenseguard-server` and `licenseguard-migrate` under `/usr/local/bin`.
3. Copy `web/admin` and `migrations` to `/opt/licenseguard`.
4. Create the `licenseguard` user and `/var/lib/licenseguard/keys`.
5. Copy `deploy/systemd/licenseguard.env.example` to `/etc/licenseguard/licenseguard.env` and replace the database URL.
6. Install both unit files, then run:

```bash
systemctl daemon-reload
systemctl start licenseguard-migrate.service
systemctl enable --now licenseguard.service
```

## Operational Checks

- Run `bash scripts/production-check.sh` before cutting a deployable build.
- Back up PostgreSQL and `/var/lib/licenseguard/keys` together.
- Do not run `licenseguard-migrate -seed-demo` for production tenants.
- Change the demo admin password immediately after first startup if demo seed data exists.
- Keep `DATABASE_URL`, signing private keys, SDK secrets, admin tokens, and license keys out of logs and client bundles.
