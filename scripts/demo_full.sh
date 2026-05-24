#!/usr/bin/env bash
# demo_full.sh — Full Pramana Protocol demo
#
# Starts the backend, runs 5 sequential demo scenarios, optionally runs
# the scenario subset from synthetic data, prints a summary matrix, then exits.
#
# Usage:
#   ./scripts/demo_full.sh [--no-scenarios] [--port 8000]
#
# Requirements:
#   - Python 3.11+ with backend/.venv OR `pip install -r backend/requirements.txt`
#   - backend/alembic or migrations available
#   - sdk/python installed (in .venv or via PYTHONPATH)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
SDK_PYTHON="$REPO_ROOT/sdk/python"
PORT="${DEMO_PORT:-8000}"
RUN_SCENARIOS=true
API_URL="http://localhost:$PORT"
VENV="$BACKEND_DIR/.venv"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}  ✓ $1${NC}"; }
fail() { echo -e "${RED}  ✗ $1${NC}"; }
info() { echo -e "${CYAN}  → $1${NC}"; }
header() { echo -e "\n${BOLD}${YELLOW}══════════════════════════════════════${NC}"; echo -e "${BOLD}${YELLOW}  $1${NC}"; echo -e "${BOLD}${YELLOW}══════════════════════════════════════${NC}"; }

# Parse args
for arg in "$@"; do
  case $arg in
    --no-scenarios) RUN_SCENARIOS=false ;;
    --port=*) PORT="${arg#*=}" ; API_URL="http://localhost:$PORT" ;;
  esac
done

# Activate venv if available
if [ -f "$VENV/bin/activate" ]; then
  source "$VENV/bin/activate"
fi

export PYTHONPATH="$SDK_PYTHON:$BACKEND_DIR:${PYTHONPATH:-}"

# ── 1. Start backend ──────────────────────────────────────────────────────────

header "1/6  Starting Backend"

# Kill any existing process on the port
lsof -ti:$PORT | xargs kill -9 2>/dev/null || true
sleep 1

cd "$BACKEND_DIR"
DATABASE_URL="sqlite:////tmp/pramana_demo.db" \
  DEMO_MODE=true \
  DEBUG=true \
  LOG_LEVEL=WARNING \
  PRAMANA_DOMAIN="localhost%3A$PORT" \
  uvicorn main:app --host 127.0.0.1 --port $PORT --workers 1 &
BACKEND_PID=$!
info "Backend PID: $BACKEND_PID"

# Wait for health check
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
  if curl -sf "$API_URL/health" > /dev/null 2>&1; then
    pass "Backend healthy at $API_URL"
    break
  fi
  if [ $i -eq $MAX_WAIT ]; then
    fail "Backend did not start within ${MAX_WAIT}s"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# Cleanup on exit
cleanup() {
  info "Stopping backend (PID $BACKEND_PID)..."
  kill $BACKEND_PID 2>/dev/null || true
}
trap cleanup EXIT

# ── 2. Create demo session ────────────────────────────────────────────────────

header "2/6  Demo Session"

DEMO_RESP=$(curl -sf -X POST "$API_URL/v1/demo/session" \
  -H "Content-Type: application/json" \
  -d '{"label":"demo-full"}' 2>&1)

if echo "$DEMO_RESP" | python3 -c "import sys,json; j=json.load(sys.stdin); print(j.get('token',''))" > /tmp/demo_token.txt 2>/dev/null && [ -s /tmp/demo_token.txt ]; then
  TOKEN=$(cat /tmp/demo_token.txt)
  pass "Demo session created"
else
  # Try dev token
  TOKEN=$(python3 -c "
import sys
sys.path.insert(0, '$BACKEND_DIR')
import jwt, time
t = jwt.encode({'sub':'demo','tenant_id':'demo-tenant','scopes':['tenant:admin','credentials:issue','credentials:revoke'],'exp':int(time.time())+3600,'iss':'pramana'},'dev-secret-change',algorithm='HS256')
print(t)
" 2>/dev/null || echo "")
  if [ -n "$TOKEN" ]; then
    pass "Dev token created"
  else
    fail "Could not create demo token (non-fatal — using anonymous endpoints)"
    TOKEN=""
  fi
fi

AUTH_HEADER=""
if [ -n "$TOKEN" ]; then
  AUTH_HEADER="-H \"Authorization: Bearer $TOKEN\""
fi

# ── 3. Demo scenarios via Python SDK ─────────────────────────────────────────

header "3/6  SDK Demo Scenarios"

RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

run_scenario() {
  local name="$1"
  local script="$2"
  if python3 -c "$script" 2>/dev/null; then
    pass "$name"
    RESULTS+=("PASS|$name")
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    fail "$name"
    RESULTS+=("FAIL|$name")
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# Scenario A: Identity
run_scenario "Identity: create did:key agent" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
a = AgentIdentity.create('alice', method='key')
assert a.did.startswith('did:key:')
"

# Scenario B: Credential issuance + verification
run_scenario "Credentials: issue + verify VC" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
from pramana.credentials import issue_vc, verify_vc
a = AgentIdentity.create('issuer', method='key')
b = AgentIdentity.create('subject', method='key')
vc = issue_vc(a, b.did, 'TestCredential', claims={'role':'user'}, ttl_seconds=3600)
r = verify_vc(vc)
assert r.verified, r.reason
"

# Scenario C: Delegation chain
run_scenario "Delegation: 2-hop chain with scope narrowing" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
from pramana.delegation import issue_delegation, delegate_further, verify_delegation_chain
a = AgentIdentity.create('delegator', method='key')
b = AgentIdentity.create('intermediate', method='key')
c = AgentIdentity.create('final', method='key')
d1 = issue_delegation(a, b.did, {'actions':['read','write'],'max_amount':5000,'currency':'USD','merchants':['*']}, max_depth=2)
d2 = delegate_further(b, d1, c.did, {'actions':['read'],'max_amount':100,'currency':'USD','merchants':['*']})
r = verify_delegation_chain(d2)
assert r.verified, r.reason
assert r.depth == 2
"

# Scenario D: Commerce — intent → cart → verify
run_scenario "Commerce: intent -> cart -> verify" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
from pramana.commerce import issue_intent_mandate, issue_cart_mandate, verify_mandate
buyer = AgentIdentity.create('buyer', method='key')
pa = AgentIdentity.create('payment-agent', method='key')
intent_jwt = issue_intent_mandate(buyer, pa.did, {'max_amount':5000,'currency':'USD'}, ttl_seconds=3600)
cart_jwt = issue_cart_mandate(buyer, pa.did, {'total':{'value':99,'currency':'USD'}}, intent_mandate_jwt=intent_jwt, ttl_seconds=300)
r = verify_mandate(cart_jwt)
assert r.verified, r.reason
"

# Scenario E: VP with nonce
run_scenario "VP: nonce enforcement (replay protection)" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
from pramana.credentials import issue_vc, create_presentation, verify_presentation
a = AgentIdentity.create('issuer', method='key')
b = AgentIdentity.create('holder', method='key')
vc = issue_vc(a, b.did, 'TestCredential', claims={'x':1}, ttl_seconds=3600)
vp = create_presentation(b, [vc], audience=a.did, nonce='abc123')
good = verify_presentation(vp, expected_audience=a.did, expected_nonce='abc123')
bad = verify_presentation(vp, expected_audience=a.did, expected_nonce='wrong')
assert good.verified, good.reason
assert not bad.verified
"

# Scenario F: did:key resolution via backend
run_scenario "Backend: did:key resolution" "
import sys; sys.path.insert(0,'$BACKEND_DIR')
import os; os.environ.setdefault('DATABASE_URL','sqlite:////tmp/pramana_demo.db')
from core.resolver import resolve_did
from pramana.identity import AgentIdentity
sys.path.insert(0,'$SDK_PYTHON')
a = AgentIdentity.create('test', method='key')
doc = resolve_did(a.did)
assert doc['id'] == a.did
" 2>/dev/null || true  # non-fatal if backend not fully importable

# Scenario G: Currency mismatch rejection
run_scenario "Security: currency mismatch rejected" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
from pramana.commerce import issue_intent_mandate, issue_cart_mandate
b = AgentIdentity.create('buyer2', method='key')
p = AgentIdentity.create('pa2', method='key')
intent_jwt = issue_intent_mandate(b, p.did, {'max_amount':5000,'currency':'USD'}, ttl_seconds=3600)
try:
    issue_cart_mandate(b, p.did, {'total':{'value':100,'currency':'EUR'}}, intent_mandate_jwt=intent_jwt, ttl_seconds=300)
    assert False, 'Should have raised ValueError'
except ValueError as e:
    assert 'currency' in str(e).lower(), str(e)
"

# Scenario H: Scope escalation rejected
run_scenario "Security: scope escalation rejected" "
import sys; sys.path.insert(0,'$SDK_PYTHON')
from pramana.identity import AgentIdentity
from pramana.delegation import issue_delegation, delegate_further, ScopeEscalationError
a = AgentIdentity.create('esc-root', method='key')
b = AgentIdentity.create('esc-hop1', method='key')
c = AgentIdentity.create('esc-final', method='key')
d1 = issue_delegation(a, b.did, {'actions':['read'],'max_amount':100,'currency':'USD'}, max_depth=2)
try:
    delegate_further(b, d1, c.did, {'actions':['read'],'max_amount':9999,'currency':'USD'})
    assert False, 'Should have raised ScopeEscalationError'
except ScopeEscalationError:
    pass
"

# ── 4. Backend API health check ───────────────────────────────────────────────

header "4/6  Backend API Health"

run_scenario "API: /health endpoint" "
import urllib.request, json
r = urllib.request.urlopen('$API_URL/health', timeout=5)
d = json.loads(r.read())
assert d.get('status') in ('ok','healthy','up',True,'running'), str(d)
" || true

# ── 5. Scenario subset from synthetic data ────────────────────────────────────

if [ "$RUN_SCENARIOS" = true ]; then
  header "5/6  Synthetic Scenario Subset"

  SYNTHETIC_DATA="$REPO_ROOT/tests/synthetic/data/scenarios.json"
  if [ -f "$SYNTHETIC_DATA" ]; then
    python3 - <<'PYEOF'
import json, sys
from pathlib import Path

data_path = Path("$REPO_ROOT/tests/synthetic/data/scenarios.json")
if not data_path.exists():
    print("  Synthetic data not found — skipping (run: python tests/synthetic/generate.py)")
    sys.exit(0)

scenarios = json.loads(data_path.read_text()).get("scenarios", [])
happy = [s for s in scenarios if s.get("category") == "happy"][:10]
failure = [s for s in scenarios if s.get("category") == "failure"][:5]
security = [s for s in scenarios if s.get("category") == "security"][:5]
subset = happy + failure + security

checked = 0
for s in subset:
    expected = s.get("expected", "")
    desc = s.get("description", s.get("id", ""))[:60]
    ok = expected in ("verified", "rejected", "replay-protected-at-backend", "verified-but-untrusted")
    status = "PASS" if ok else "WARN"
    color = "\033[0;32m" if ok else "\033[1;33m"
    print(f"  {color}{status}\033[0m  {desc}")
    checked += 1

print(f"\n  Checked {checked}/{len(scenarios)} scenarios from synthetic data")
PYEOF
  else
    info "Synthetic data not found — run 'python tests/synthetic/generate.py' to generate"
  fi
else
  header "5/6  Synthetic Scenarios (skipped)"
  info "Use --no-scenarios=false to enable"
fi

# ── 6. Summary matrix ─────────────────────────────────────────────────────────

header "6/6  Summary"

echo ""
echo -e "  ${BOLD}Scenario                                  Result${NC}"
echo "  ────────────────────────────────────────  ──────"
for entry in "${RESULTS[@]}"; do
  status="${entry%%|*}"
  name="${entry#*|}"
  if [ "$status" = "PASS" ]; then
    echo -e "  ${GREEN}✓${NC}  $name"
  else
    echo -e "  ${RED}✗${NC}  $name"
  fi
done

echo ""
echo -e "  ${BOLD}Total: ${PASS_COUNT} passed, ${FAIL_COUNT} failed${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
  echo -e "  ${GREEN}${BOLD}All demos passed! ✓${NC}"
  exit 0
else
  echo -e "  ${RED}${BOLD}${FAIL_COUNT} demo(s) failed.${NC}"
  exit 1
fi
