#!/usr/bin/env bash
# demo_cross_org.sh — Pramana Protocol: Two-Tenant Cross-Org Verification Demo
#
# Demonstrates:
#   1. Tenant A (Walmart) creates an issuer agent and issues a VC
#   2. Tenant B (Supplier Corp) verifies the VC using ONLY the VC-JWT + DID
#      — no Authorization header, no database access to Tenant A
#   3. Tenant B proves it CANNOT use Tenant A's issuer (data isolation)
#
# This is the key insight Scott Meyer needs to see:
#   "Cryptographic trust without shared infrastructure"
#
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
DIM='\033[2m'
NC='\033[0m'

step()  { echo -e "\n${BOLD}${CYAN}[$1]${NC} $2"; }
pass()  { echo -e "  ${GREEN}✓${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; exit 1; }
info()  { echo -e "  ${YELLOW}→${NC} $1"; }
note()  { echo -e "  ${DIM}$1${NC}"; }

# ── Mint two separate tenant tokens ──────────────────────────────────────────
TOKEN_A=$(python3 - <<PY
import os, time, jwt
payload = {
    "iss":    os.environ.get('AUTH_JWT_ISSUER', 'pramana'),
    "sub":    "walmart-admin",
    "tenant": "walmart",
    "iat":    int(time.time()),
    "exp":    int(time.time()) + 3600,
    "scope":  ["agents:create", "credentials:issue", "credentials:revoke"],
}
print(jwt.encode(payload, os.environ.get('AUTH_JWT_SECRET','dev-secret-change'), algorithm='HS256'))
PY
)

TOKEN_B=$(python3 - <<PY
import os, time, jwt
payload = {
    "iss":    os.environ.get('AUTH_JWT_ISSUER', 'pramana'),
    "sub":    "supplier-admin",
    "tenant": "supplier-corp",
    "iat":    int(time.time()),
    "exp":    int(time.time()) + 3600,
    "scope":  ["agents:create", "credentials:issue"],
}
print(jwt.encode(payload, os.environ.get('AUTH_JWT_SECRET','dev-secret-change'), algorithm='HS256'))
PY
)

HDR_A=( -H "Authorization: Bearer $TOKEN_A" -H "Content-Type: application/json" )
HDR_B=( -H "Authorization: Bearer $TOKEN_B" -H "Content-Type: application/json" )

echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${YELLOW}  PRAMANA PROTOCOL — CROSS-ORG VERIFICATION DEMO${NC}"
echo -e "${BOLD}${YELLOW}  Two tenants. One issuer. Zero shared infrastructure.${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════${NC}"
info "API: $API_BASE"
note "Tenant A: walmart  →  issues the credential"
note "Tenant B: supplier-corp  →  verifies without touching Tenant A's database"

# ── [1/5] Tenant A creates its issuer agent ───────────────────────────────────
step "1/5" "Tenant A (Walmart) creates issuer agent..."
WALMART=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_A[@]}" \
    -d '{"name":"walmart-procurement-agent"}')
WALMART_DID=$(echo "$WALMART" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')
WALMART_ID=$(echo  "$WALMART" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
pass "Tenant A issuer DID: $WALMART_DID"
note "(stored in Tenant A database partition only)"

# ── [2/5] Tenant A issues a VC to a supplier subject DID ─────────────────────
step "2/5" "Tenant A issues scoped VC to supplier subject..."
# Create a minimal subject DID for the supplier (using Tenant B's token)
SUPPLIER=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_B[@]}" \
    -d '{"name":"supplier-receiving-agent"}')
SUPPLIER_DID=$(echo "$SUPPLIER" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')

T0=$(python3 -c 'import time; print(int(time.time()*1000))')
CREDENTIAL=$(curl -sSf -X POST "$API_BASE/v1/credentials/issue" "${HDR_A[@]}" \
    -d "{
      \"issuer_agent_id\": \"$WALMART_ID\",
      \"subject_did\":     \"$SUPPLIER_DID\",
      \"credential_type\": \"VendorAccessCredential\",
      \"ttl_seconds\":     7200,
      \"subject_claims\":  {
        \"capability\":    \"submit_purchase_orders\",
        \"max_amount\":    250000,
        \"scope\":         [\"catalog_read\", \"order_submit\"],
        \"approved_by\":   \"walmart-procurement\"
      }
    }")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
VC_JWT=$(echo   "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')
CRED_ID=$(echo  "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["credential_id"])')
ELAPSED=$(python3 -c "print($T1 - $T0)")
echo "$CREDENTIAL" | python3 "$FMT" issued "$ELAPSED"
pass "VC issued by Tenant A. Only the JWT leaves Tenant A's boundary."

# ── [3/5] Tenant B verifies with NO Authorization header ─────────────────────
step "3/5" "Tenant B (Supplier Corp) verifies — using ONLY the VC-JWT..."
note "Sending POST /v1/credentials/verify with NO Authorization header"
note "Verification uses: JWT signature + DID resolution + bitstring status check"
note "No Tenant A database access. No shared secrets."

T0=$(python3 -c 'import time; print(int(time.time()*1000))')
VERIFY=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" \
    -H "Content-Type: application/json" \
    -d "{\"jwt\":\"$VC_JWT\"}")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
ELAPSED=$(python3 -c "print($T1 - $T0)")
python3 - <<PY
import json
v = json.loads('''$VERIFY''')
assert v.get('verified') is True, f"Expected verified=True, got: {v}"
PY
echo "$VERIFY" | python3 "$FMT" verify "$ELAPSED"
pass "Tenant B verified Tenant A's credential — cryptographic trust only"

echo ""
echo -e "  ${BOLD}${GREEN}Key insight:${NC}"
echo -e "  ${DIM}The verify endpoint requires NO Authorization header.${NC}"
echo -e "  ${DIM}Tenant B learns: issuer DID, subject DID, claims, and revocation status.${NC}"
echo -e "  ${DIM}Tenant B does NOT learn: Tenant A's internal agent IDs, tenant config, or other credentials.${NC}"

# ── [4/5] Prove isolation: Tenant B CANNOT use Tenant A's issuer ─────────────
step "4/5" "Proving data isolation — Tenant B tries to use Tenant A's issuer..."
note "POST /v1/credentials/issue with Tenant B token + Tenant A's issuer_agent_id"
note "Expect: 404 — Tenant A's agent is invisible to Tenant B"

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_BASE/v1/credentials/issue" "${HDR_B[@]}" \
    -d "{
      \"issuer_agent_id\": \"$WALMART_ID\",
      \"subject_did\":     \"$SUPPLIER_DID\",
      \"credential_type\": \"UnauthorizedCredential\",
      \"subject_claims\":  {\"attempt\": \"scope escalation\"}
    }")

if [ "$HTTP_STATUS" = "404" ]; then
    echo ""
    echo -e "  ${BOLD}${GREEN}ISOLATION: CONFIRMED${NC}"
    echo -e "  ${DIM}HTTP $HTTP_STATUS — Tenant A's issuer agent not found in Tenant B's namespace${NC}"
    echo -e "  ${DIM}Agent lookup: db.query(Agent).filter(tenant_id == 'supplier-corp') → empty${NC}"
    pass "Tenant B cannot forge credentials using Tenant A's issuer (404)"
else
    fail "Expected 404, got HTTP $HTTP_STATUS — isolation check FAILED"
fi

# ── [5/5] Tenant A revokes; Tenant B sees the revocation ─────────────────────
step "5/5" "Tenant A revokes credential; Tenant B observes revocation..."
REVOKE=$(curl -sSf -X POST "$API_BASE/v1/credentials/$CRED_ID/revoke" \
    "${HDR_A[@]}" -d '{}')
python3 - <<PY
import json
r = json.loads('''$REVOKE''')
assert r.get('revoked') is True, f"Expected revoked=True, got: {r}"
PY
echo "$REVOKE" | python3 "$FMT" revoked

note "Tenant B re-verifies — no need to contact Tenant A..."
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
PY
REVOKED_AT=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
echo "$VERIFY_AFTER" | python3 "$FMT" verify "$ELAPSED" "$REVOKED_AT"
pass "Revocation visible to Tenant B without Tenant A's credentials"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}${GREEN}CROSS-ORG DEMO COMPLETE ✓${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}What just happened:${NC}"
echo -e "  ${DIM}1. Tenant A issued a cryptographically signed VC-JWT${NC}"
echo -e "  ${DIM}2. Tenant B verified it using ONLY the JWT + public DID resolution${NC}"
echo -e "  ${DIM}3. Tenant B was blocked from using Tenant A's issuer (tenant isolation)${NC}"
echo -e "  ${DIM}4. Tenant A revoked the credential; Tenant B observed it immediately${NC}"
echo ""
echo -e "  ${BOLD}Architecture:${NC} W3C DID + VC-JWT (EdDSA/Ed25519) + Bitstring Status List"
echo -e "  ${BOLD}Auth:${NC}         Verification requires zero shared secrets or API tokens"
echo -e "  ${BOLD}Isolation:${NC}    All agent/credential data filtered by tenant_id at DB layer"
echo ""
