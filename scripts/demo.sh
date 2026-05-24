#!/usr/bin/env bash
# demo.sh — Pramana Protocol core demo
# Create DID → Issue scoped VC → Verify → Revoke → Verify (fails)
# Requires backend running: DATABASE_URL=sqlite:////tmp/pramana_demo.db DEMO_MODE=true uvicorn main:app
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE="${API_BASE:-http://127.0.0.1:5051}"
AUTH_JWT_SECRET="${AUTH_JWT_SECRET:-dev-secret-change}"
AUTH_JWT_ISSUER="${AUTH_JWT_ISSUER:-pramana}"
FMT="$REPO_ROOT/scripts/lib/format_output.py"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step()  { echo -e "\n${BOLD}${CYAN}[$1]${NC} $2"; }
pass()  { echo -e "  ${GREEN}✓${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; exit 1; }
info()  { echo -e "  ${YELLOW}→${NC} $1"; }

# ── Mint Walmart tenant token (HS256 stub) ────────────────────────────────────
TOKEN=$(python3 - <<PY
import os, time, jwt
payload = {
    "iss":    os.environ.get('AUTH_JWT_ISSUER', 'pramana'),
    "sub":    "demo",
    "tenant": "walmart",
    "iat":    int(time.time()),
    "exp":    int(time.time()) + 3600,
    "scope":  ["agents:create", "credentials:issue", "credentials:revoke"],
}
print(jwt.encode(payload, os.environ.get('AUTH_JWT_SECRET','dev-secret-change'), algorithm='HS256'))
PY
)

HDR_AUTH=( -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" )

echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${YELLOW}  PRAMANA PROTOCOL — CORE DEMO${NC}"
echo -e "${BOLD}${YELLOW}  Create DID · Issue VC · Verify · Revoke · Verify (fails)${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════${NC}"
info "API: $API_BASE  |  Tenant: walmart"

# ── [1/6] Create issuer agent (Walmart Procurement) ──────────────────────────
step "1/6" "Creating Walmart issuer agent..."
WALMART=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_AUTH[@]}" \
    -d '{"name":"walmart-procurement-agent"}')
WALMART_DID=$(echo "$WALMART" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')
WALMART_ID=$(echo  "$WALMART" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
pass "Issuer DID: $WALMART_DID"

# ── [2/6] Create subject agent (Supplier) ────────────────────────────────────
step "2/6" "Creating Supplier subject agent..."
SUPPLIER=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_AUTH[@]}" \
    -d '{"name":"supplier-api-agent"}')
SUPPLIER_DID=$(echo "$SUPPLIER" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')
pass "Subject DID: $SUPPLIER_DID"

# ── [3/6] Issue scoped VC ─────────────────────────────────────────────────────
step "3/6" "Issuing scoped capability credential..."
T0=$(python3 -c 'import time; print(int(time.time()*1000))')
CREDENTIAL=$(curl -sSf -X POST "$API_BASE/v1/credentials/issue" "${HDR_AUTH[@]}" \
    -d "{
      \"issuer_agent_id\": \"$WALMART_ID\",
      \"subject_did\":     \"$SUPPLIER_DID\",
      \"credential_type\": \"CapabilityCredential\",
      \"ttl_seconds\":     3600,
      \"subject_claims\":  {
        \"capability\":    \"negotiate_contracts\",
        \"max_amount\":    100000,
        \"scope\":         [\"purchase_orders\", \"invoices\"],
        \"trust_tier\":    \"vendor_verified\"
      }
    }")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
VC_JWT=$(echo   "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')
CRED_ID=$(echo  "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["credential_id"])')
ELAPSED=$(python3 -c "print($T1 - $T0)")
echo "$CREDENTIAL" | python3 "$FMT" issued "$ELAPSED"

# ── [4/6] Verify (should PASS) ────────────────────────────────────────────────
step "4/6" "Verifying credential (expect: PASSED)..."
T0=$(python3 -c 'import time; print(int(time.time()*1000))')
VERIFY_BEFORE=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" \
    -H "Content-Type: application/json" \
    -d "{\"jwt\":\"$VC_JWT\"}")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
ELAPSED=$(python3 -c "print($T1 - $T0)")
python3 - <<PY
import json, sys
v = json.loads('''$VERIFY_BEFORE''')
assert v.get('verified') is True, f"Expected verified=True, got: {v}"
PY
echo "$VERIFY_BEFORE" | python3 "$FMT" verify "$ELAPSED"
pass "Verification PASSED"

# ── [5/6] Revoke ─────────────────────────────────────────────────────────────
step "5/6" "Revoking credential (supplier contract terminated)..."
REVOKE=$(curl -sSf -X POST "$API_BASE/v1/credentials/$CRED_ID/revoke" \
    "${HDR_AUTH[@]}" -d '{}')
python3 - <<PY
import json
r = json.loads('''$REVOKE''')
assert r.get('revoked') is True, f"Expected revoked=True, got: {r}"
PY
echo "$REVOKE" | python3 "$FMT" revoked
REVOKED_AT=$(python3 -c 'import time; from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
pass "Credential revoked"

# ── [6/6] Verify after revoke (should FAIL) ───────────────────────────────────
step "6/6" "Re-verifying revoked credential (expect: FAILED)..."
T0=$(python3 -c 'import time; print(int(time.time()*1000))')
VERIFY_AFTER=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" \
    -H "Content-Type: application/json" \
    -d "{\"jwt\":\"$VC_JWT\"}")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
ELAPSED=$(python3 -c "print($T1 - $T0)")
python3 - <<PY
import json
v = json.loads('''$VERIFY_AFTER''')
assert v.get('verified') is False, f"Expected verified=False, got: {v}"
assert v.get('reason') == 'revoked',  f"Expected reason=revoked, got: {v}"
PY
echo "$VERIFY_AFTER" | python3 "$FMT" verify "$ELAPSED" "$(python3 -c 'import time; from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
pass "Verification correctly FAILED (revoked)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}${GREEN}DEMO COMPLETE — all 6 steps passed ✓${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════${NC}"
echo ""
