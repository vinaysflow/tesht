#!/usr/bin/env bash
# scripts/deploy.sh — Deploy Tesht (Pramana) to Fly.io with pre-flight migrations.
# Usage: ./scripts/deploy.sh [--app <app-name>]
set -euo pipefail

APP="${FLY_APP:-tesht}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) APP="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

echo "==> Deploying app: $APP"
echo "==> Checking fly CLI is available..."
command -v fly >/dev/null 2>&1 || { echo "fly CLI not found. Install from https://fly.io/docs/hands-on/install-flyctl/"; exit 1; }

echo "==> Running Alembic migrations..."
fly ssh console --app "$APP" -C \
  "cd /app/backend && DATABASE_URL=\$DATABASE_URL python -m alembic upgrade head"

echo "==> Deploying with rolling strategy..."
fly deploy --app "$APP" --strategy rolling

echo "==> Verifying health..."
APP_URL=$(fly status --app "$APP" --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Hostname',''))" || echo "")
if [[ -n "$APP_URL" ]]; then
  curl -sf "https://${APP_URL}/health" && echo "" && echo "==> Health check passed."
else
  echo "==> Could not determine hostname. Check health manually at https://${APP}.fly.dev/health"
fi

echo "==> Deploy complete."
