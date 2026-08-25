# Deployment Guide

This guide covers deploying Pramana Protocol to [Fly.io](https://fly.io) with a managed PostgreSQL database.

## Production profile (`PRAMANA_ENV=production`)

Pramana ships with demo-safe defaults so the local demo "just works". For any real deployment set a single switch to flip every component to production-safe behavior:

```bash
# Backend and gateway both honor this. (The backend also accepts ENV=production.)
PRAMANA_ENV=production
DATABASE_URL=postgresql://...   # required in production
```

What `PRAMANA_ENV=production` changes:

| Area | Development default | Production default | Runtime override |
|------|---------------------|--------------------|------------------|
| Gateway status-list errors | fail-open (not revoked) | fail-closed (revoked) after bounded retry | `GATEWAY_FAIL_CLOSED=0/1` |
| Gateway audit | in-memory fallback allowed | Postgres required; startup fails without `DATABASE_URL` | `GATEWAY_REQUIRE_PG_AUDIT=0/1` |
| Cold-path trust refresh | best-effort | authenticated (`BACKEND_API_KEY`) + retried, bounded worker pool | — |
| Session decide, no scored credential | allow | step-up (fail-safe) | — |

Related env vars:
- `BACKEND_URL` / `PRAMANA_BACKEND_URL` + `BACKEND_API_KEY` — let the gateway cold-path call the backend trust API authenticated.
- Explicit values in `gateway/config.yaml` always win over the profile default; runtime env vars (`GATEWAY_FAIL_CLOSED`, `GATEWAY_REQUIRE_PG_AUDIT`) win over both.

Known limitation (documented, not yet closed): the gateway trust cache is per-process. It is thread-safe within a single process and durably persists cold-path scores to Postgres, but is **not** shared across multiple replicas. For multi-replica HA, a shared cache (e.g. Redis) is planned in Phase 2 — until then run the gateway as a single replica or accept per-replica cache warmup.

## Prerequisites

- [Fly CLI](https://fly.io/docs/hands-on/install-flyctl/) installed and authenticated (`fly auth login`)
- Docker installed (for the build step)
- A Fly.io account

## 1. Initial Setup

Clone the repo and navigate to the root:

```bash
git clone https://github.com/vinaysflow/pramana-protocol.git
cd pramana-protocol
```

If this is a first-time deploy, run:

```bash
fly launch --copy-config --no-deploy
```

This reads `fly.toml` and creates the app without deploying. Accept the generated app name or supply `--name pramana-protocol`.

## 2. Create and Attach a PostgreSQL Database

```bash
fly postgres create \
  --name pramana-db \
  --region iad \
  --vm-size shared-cpu-1x \
  --volume-size 10

fly postgres attach --app pramana-protocol pramana-db
```

`attach` automatically sets the `DATABASE_URL` secret on your app.

## 3. Set Required Secrets

```bash
# Generate a strong random key (macOS/Linux)
API_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

fly secrets set \
  --app pramana-protocol \
  API_SECRET_KEY="$API_SECRET" \
  AUTH_JWT_SECRET="$JWT_SECRET" \
  PRAMANA_DOMAIN="pramana-protocol.fly.dev" \
  PRAMANA_SCHEME="https" \
  ALLOWED_ORIGINS="https://pramana-protocol.fly.dev" \
  AUTH_MODE="hs256"
```

For OIDC (Keycloak / Auth0 / Okta) deployments also set:

```bash
fly secrets set \
  --app pramana-protocol \
  AUTH_MODE="oidc" \
  OIDC_ISSUER="https://your-idp/realms/pramana" \
  OIDC_AUDIENCE="pramana-api" \
  OIDC_JWKS_URL="https://your-idp/realms/pramana/protocol/openid-connect/certs"
```

## 4. Deploy

```bash
./scripts/deploy.sh
```

The script will:
1. SSH into the running instance and run `alembic upgrade head`
2. Deploy a new release using a rolling strategy (zero-downtime)
3. Print the health check result

For subsequent deploys the same command applies — migrations are always run first.

### Manual deploy (no script)

```bash
fly ssh console -C "cd /app/backend && python -m alembic upgrade head"
fly deploy --strategy rolling
```

## 5. Verify

```bash
# Health endpoint (returns 200 {"status":"healthy"})
curl https://pramana-protocol.fly.dev/health

# Readiness endpoint (checks DB connectivity + migrations)
curl https://pramana-protocol.fly.dev/ready
```

Expected `/ready` response when healthy:

```json
{"ready": true}
```

## 6. Optional Configuration

| Environment variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Python logging level |
| `RATE_LIMIT_ENABLED` | `false` | Enable per-IP rate limiting |
| `RATE_LIMIT_PER_MINUTE` | `120` | Requests/minute per IP |
| `DB_POOL_SIZE` | `10` | SQLAlchemy connection pool size |
| `DB_MAX_OVERFLOW` | `20` | Max overflow connections |
| `DB_POOL_TIMEOUT` | `30` | Connection acquire timeout (seconds) |
| `DB_POOL_RECYCLE` | `1800` | Recycle connections after N seconds |
| `DID_CACHE_TTL_SECONDS` | `300` | DID document cache TTL |
| `DID_CACHE_MAX_SIZE` | `10000` | Max cached DID documents |

Set any of these via `fly secrets set` or `fly env set` as appropriate.

## 7. Monitoring and Scaling

### View logs

```bash
fly logs --app pramana-protocol
```

### Scale horizontally

```bash
fly scale count 2 --app pramana-protocol
```

### Scale vertically

```bash
fly scale vm shared-cpu-2x --app pramana-protocol
```

### View machine status

```bash
fly status --app pramana-protocol
```

### Roll back a deploy

```bash
fly releases --app pramana-protocol   # list releases
fly deploy --image <previous-image>   # redeploy a specific image
```

## 8. Flush the DID Resolution Cache

If you need to force re-fetching of external DID documents (e.g., after a key rotation at a remote issuer):

```bash
# Obtain an admin token first
TOKEN=$(cd backend && .venv/bin/python3 scripts/mint_token.py)

curl -X POST https://pramana-protocol.fly.dev/v1/admin/cache/flush \
  -H "Authorization: Bearer $TOKEN"
```

Response: `{"flushed": true}`
