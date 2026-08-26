#!/usr/bin/env bash
# demo_web.sh — Start all Tesht demo services + React dev server
#
# Usage:
#   ./scripts/demo_web.sh
#
# Starts:
#   - Mock OIDC provider   :9200
#   - IdP Bridge           :5053
#   - Mock MCP server      :9100
#   - SQLite MCP server    :9102  (real SQLite database)
#   - MCP Gateway          :5052  (uses PostgreSQL audit if available)
#   - Vite React dev server :5174
#
# All Python services run with TESHT_CORS_ENABLED=true so the React app
# can make cross-origin API calls.
#
# If PostgreSQL is running on :5432, the gateway automatically enables
# persistent SHA-256 hash-chained audit logging.
#
# Press Ctrl-C to stop all services.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEMO_APP_DIR="$PROJECT_ROOT/demo-app"
PYTHONPATH="$PROJECT_ROOT/sdk/python:$PROJECT_ROOT"

# ── Colours ───────────────────────────────────────────────────────────────────
RESET="\033[0m"; BOLD="\033[1m"; GREEN="\033[92m"; RED="\033[91m"
CYAN="\033[96m"; YELLOW="\033[93m"; DIM="\033[2m"

log()  { echo -e "  ${CYAN}[demo_web]${RESET} $*"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
fail() { echo -e "  ${RED}✗${RESET} $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $*"; }

# ── Config path (temp file, same as demo_mega.py) ─────────────────────────────
CFG_FILE=$(mktemp /tmp/tesht_demo_config_XXXXXX.yaml)

# Base config — always include the mock IdP
cat > "$CFG_FILE" <<'YAML'
providers:
  mock_idp:
    name: "Acme Corp Okta (Mock)"
    issuer: "https://mock-idp.tesht.local"
    jwks_uri: "http://127.0.0.1:9200/.well-known/jwks.json"
    audience: "tesht"
    claim_mapping:
      name: name
      email: email
      organization: org
      department: department
      role: role
    default_credential_type: OrganizationalRoleCredential
    allowed_algorithms:
      - RS256
YAML

# If OKTA_ISSUER is set, inject the real Auth0/Okta provider
if [ -n "${OKTA_ISSUER:-}" ]; then
  OKTA_ISSUER_NORM="${OKTA_ISSUER%/}"  # strip trailing slash
  if echo "$OKTA_ISSUER_NORM" | grep -q "auth0.com"; then
    DERIVED_JWKS="${OKTA_ISSUER_NORM}/.well-known/jwks.json"
  else
    DERIVED_JWKS="${OKTA_ISSUER_NORM}/v1/keys"
  fi
  OKTA_JWKS_URI="${OKTA_JWKS_URI:-$DERIVED_JWKS}"
  OKTA_AUDIENCE="${OKTA_AUDIENCE:-${OKTA_CLIENT_ID:-your_client_id}}"

  cat >> "$CFG_FILE" <<YAML
  acme_okta:
    name: "Acme Corp (Auth0/Okta Dev)"
    issuer: "${OKTA_ISSUER_NORM}"
    jwks_uri: "${OKTA_JWKS_URI}"
    audience: "${OKTA_AUDIENCE}"
    claim_mapping:
      name: name
      email: email
      organization: org_name
      department: department
      role: job_title
    default_credential_type: OrganizationalRoleCredential
    allowed_algorithms:
      - RS256
YAML
  ok "Real IdP (Auth0/Okta) configured: $OKTA_ISSUER_NORM"
fi

# ── Service PID tracking ──────────────────────────────────────────────────────
PIDS=()

cleanup() {
  echo ""
  log "Shutting down all services…"
  for pid in "${PIDS[@]:-}"; do
    [ -z "$pid" ] && continue
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  rm -f "$CFG_FILE"
  log "All services stopped."
}
trap cleanup EXIT INT TERM

# ── Helper: start a uvicorn service ──────────────────────────────────────────
start_service() {
  local name="$1" module="$2" port="$3"
  shift 3
  local extra_env=("${@}")  # e.g. IDP_BRIDGE_CONFIG=...

  if [ ${#extra_env[@]} -gt 0 ]; then
    env \
      PYTHONPATH="$PYTHONPATH" \
      TESHT_CORS_ENABLED=true \
      "${extra_env[@]}" \
      python3 -m uvicorn "$module" \
        --host 127.0.0.1 --port "$port" \
        --log-level error \
      > "/tmp/tesht_${name}.log" 2>&1 &
  else
    env \
      PYTHONPATH="$PYTHONPATH" \
      TESHT_CORS_ENABLED=true \
      python3 -m uvicorn "$module" \
        --host 127.0.0.1 --port "$port" \
        --log-level error \
      > "/tmp/tesht_${name}.log" 2>&1 &
  fi
  local pid=$!
  PIDS+=("$pid")
  echo -e "  ${DIM}Started ${name} (pid ${pid}) on :${port}${RESET}"
}

# ── Helper: wait for HTTP service to respond ─────────────────────────────────
wait_healthy() {
  local label="$1" url="$2"
  local deadline=$((SECONDS + 20))
  while [ $SECONDS -lt $deadline ]; do
    if curl -sf "$url" -o /dev/null 2>/dev/null; then
      ok "$label healthy"
      return 0
    fi
    sleep 0.3
  done
  fail "$label failed to start (check /tmp/tesht_${label// /_}.log)"
  return 1
}

echo ""
echo -e "${BOLD}${CYAN}━━━ Tesht (Pramana) — Web Demo Startup ━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log "Project root: $PROJECT_ROOT"

# ── Detect PostgreSQL ─────────────────────────────────────────────────────────
PG_DATABASE_URL=""
if nc -z 127.0.0.1 5432 2>/dev/null; then
  PG_USER="${POSTGRES_USER:-tesht}"
  PG_PASS="${POSTGRES_PASSWORD:-tesht_dev_password}"
  PG_DB="${POSTGRES_DB:-tesht}"
  PG_DATABASE_URL="postgresql://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}"
  ok "PostgreSQL detected on :5432 — enabling persistent hash-chained audit"
else
  warn "PostgreSQL not found on :5432 — gateway will use in-memory audit"
  warn "Run 'docker compose up postgres -d' to enable persistent audit"
fi

log "Starting Python services with TESHT_CORS_ENABLED=true…"
echo ""

# ── Start Python services ─────────────────────────────────────────────────────
start_service "oidc"    "idp_bridge.mock_oidc_provider:app" 9200

# Pass OKTA_* env vars to bridge so it can validate real IdP tokens
BRIDGE_EXTRA_ENV=("IDP_BRIDGE_CONFIG=$CFG_FILE")
[ -n "${OKTA_ISSUER:-}" ]    && BRIDGE_EXTRA_ENV+=("OKTA_ISSUER=${OKTA_ISSUER%/}")
[ -n "${OKTA_CLIENT_ID:-}" ] && BRIDGE_EXTRA_ENV+=("OKTA_CLIENT_ID=$OKTA_CLIENT_ID")
[ -n "${OKTA_AUDIENCE:-}" ]  && BRIDGE_EXTRA_ENV+=("OKTA_AUDIENCE=$OKTA_AUDIENCE")
[ -n "${OKTA_JWKS_URI:-}" ]  && BRIDGE_EXTRA_ENV+=("OKTA_JWKS_URI=$OKTA_JWKS_URI")
start_service "bridge"  "idp_bridge.app:app"                5053 "${BRIDGE_EXTRA_ENV[@]}"
start_service "mcp"     "gateway.mock_mcp_server:app"        9100
start_service "sqlite"  "gateway.sqlite_mcp_server:app"      9102

# Start gateway — pass DATABASE_URL if PostgreSQL is available
if [ -n "$PG_DATABASE_URL" ]; then
  start_service "gateway" "gateway.app:app" 5052 "DATABASE_URL=$PG_DATABASE_URL"
else
  start_service "gateway" "gateway.app:app" 5052
fi

sleep 1  # brief wait before polling

# ── Health checks ─────────────────────────────────────────────────────────────
wait_healthy "Mock OIDC provider"  "http://127.0.0.1:9200/health"         || exit 1
wait_healthy "IdP Bridge"          "http://127.0.0.1:5053/health"         || exit 1
wait_healthy "Mock MCP server"     "http://127.0.0.1:9100/health"         || exit 1
wait_healthy "SQLite MCP server"   "http://127.0.0.1:9102/health"         || exit 1
wait_healthy "MCP Gateway"         "http://127.0.0.1:5052/gateway/health" || exit 1

echo ""
log "All Python services healthy!"

# ── npm install if needed ─────────────────────────────────────────────────────
if [ ! -d "$DEMO_APP_DIR/node_modules" ]; then
  log "Installing npm dependencies (first run)…"
  (cd "$DEMO_APP_DIR" && npm install --silent)
  ok "npm install complete"
fi

# ── Start Vite dev server ─────────────────────────────────────────────────────
echo ""
log "Starting Vite React dev server on :5174…"
  (cd "$DEMO_APP_DIR" && npm run dev) &
PIDS+=($!)

sleep 2

echo ""
echo -e "${BOLD}${GREEN}━━━ Demo ready! ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${BOLD}React app:${RESET}  http://localhost:5174"
echo -e "  ${DIM}Gateway:    http://localhost:5052${RESET}"
echo -e "  ${DIM}IdP Bridge: http://localhost:5053${RESET}"
echo -e "  ${DIM}SQLite MCP: http://localhost:9102${RESET}"
if [ -n "$PG_DATABASE_URL" ]; then
  echo -e "  ${GREEN}Audit:      PostgreSQL hash-chain (persistent)${RESET}"
else
  echo -e "  ${YELLOW}Audit:      in-memory (start postgres for persistence)${RESET}"
fi
echo ""
echo -e "  ${YELLOW}Press Ctrl-C to stop all services.${RESET}"
echo ""

# ── Keep alive until Ctrl-C ───────────────────────────────────────────────────
wait
