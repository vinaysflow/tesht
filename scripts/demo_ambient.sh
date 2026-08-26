#!/usr/bin/env bash
# demo_ambient.sh — Tesht (Pramana): AI-Powered Security Incident Demo
#
# Narrative: Ambient.ai detects a physical threat. An AI agent is issued a
# time-bounded, scoped credential to dispatch alerts to ServiceNow and PagerDuty.
# Once the incident closes, the credential is revoked instantly.
# Any further dispatch attempt is cryptographically denied.
#
# Maps to checklist:
#   detect threat → issue credential → verify (PASS) → revoke → verify (FAIL)
#
# Requires backend running: DATABASE_URL=sqlite:////tmp/tesht_demo.db DEMO_MODE=true uvicorn main:app
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE="${API_BASE:-http://127.0.0.1:5051}"
AUTH_JWT_SECRET="${AUTH_JWT_SECRET:-dev-secret-change}"
AUTH_JWT_ISSUER="${AUTH_JWT_ISSUER:-tesht}"
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
alert() { echo -e "  ${BOLD}${RED}⚠  $1${NC}"; }

# ── Mint security operations tenant token ─────────────────────────────────────
TOKEN=$(python3 - <<PY
import os, time, jwt
payload = {
    "iss":    os.environ.get('AUTH_JWT_ISSUER', 'tesht'),
    "sub":    "secops-admin",
    "tenant": "ambient-ai-secops",
    "iat":    int(time.time()),
    "exp":    int(time.time()) + 3600,
    "scope":  ["agents:create", "credentials:issue", "credentials:revoke"],
}
print(jwt.encode(payload, os.environ.get('AUTH_JWT_SECRET','dev-secret-change'), algorithm='HS256'))
PY
)

HDR_AUTH=( -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" )

echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${YELLOW}  TESHT PROTOCOL — AI SECURITY INCIDENT DEMO${NC}"
echo -e "${BOLD}${YELLOW}  Ambient.ai Detection · Scoped Credential · Dispatch · Revoke${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
info "API: $API_BASE  |  Tenant: ambient-ai-secops"

# ── [1/6] Simulated threat detection ─────────────────────────────────────────
step "1/6" "THREAT DETECTED — Ambient.ai camera system"
echo ""
echo -e "  ${BOLD}${RED}ALERT: Unauthorized person detected${NC}"
echo -e "  ${DIM}Location:    Server Room B — Rack 3${NC}"
echo -e "  ${DIM}Confidence:  94.7% (multi-camera correlation)${NC}"
echo -e "  ${DIM}Timestamp:   $(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')${NC}"
echo -e "  ${DIM}Policy:      HIGH threat → auto-issue dispatch credential${NC}"
echo ""
note "Tesht is called to issue a time-bounded, scoped authorization..."

# ── [2/6] Create the two agents ───────────────────────────────────────────────
step "2/6" "Provisioning agents (threat detector + incident responder)..."
DETECTOR=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_AUTH[@]}" \
    -d '{"name":"ambient-threat-detector"}')
DETECTOR_DID=$(echo "$DETECTOR" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')
DETECTOR_ID=$(echo  "$DETECTOR" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

RESPONDER=$(curl -sSf -X POST "$API_BASE/v1/agents" "${HDR_AUTH[@]}" \
    -d '{"name":"incident-response-agent"}')
RESPONDER_DID=$(echo "$RESPONDER" | python3 -c 'import sys,json; print(json.load(sys.stdin)["did"])')

pass "Threat detector DID: $DETECTOR_DID"
pass "Incident responder DID: $RESPONDER_DID"

# ── [3/6] Issue time-bounded scoped credential ────────────────────────────────
step "3/6" "Issuing scoped security credential (servicenow + pagerduty only)..."
note "Scope is deliberately narrow: dispatch ONLY to approved integrations"
note "TTL: 900s (15 minutes) — auto-expires after incident window"

T0=$(python3 -c 'import time; print(int(time.time()*1000))')
CREDENTIAL=$(curl -sSf -X POST "$API_BASE/v1/credentials/issue" "${HDR_AUTH[@]}" \
    -d "{
      \"issuer_agent_id\": \"$DETECTOR_ID\",
      \"subject_did\":     \"$RESPONDER_DID\",
      \"credential_type\": \"SecurityDispatchCredential\",
      \"ttl_seconds\":     900,
      \"subject_claims\":  {
        \"capability\":    \"dispatch_security_alert\",
        \"scope\":         [\"servicenow\", \"pagerduty\"],
        \"threat_level\":  \"high\",
        \"zone\":          \"server-room-b\",
        \"incident_id\":   \"INC-2026-0311-001\",
        \"authorized_by\": \"ambient-ai-policy-engine\"
      }
    }")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
VC_JWT=$(echo   "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')
CRED_ID=$(echo  "$CREDENTIAL" | python3 -c 'import sys,json; print(json.load(sys.stdin)["credential_id"])')
ELAPSED=$(python3 -c "print($T1 - $T0)")
echo "$CREDENTIAL" | python3 "$FMT" issued "$ELAPSED"
pass "Credential scoped to: servicenow, pagerduty ONLY"

# ── [4/6] Incident responder verifies before dispatching ──────────────────────
step "4/6" "Incident responder verifies authorization before dispatching..."
note "Agent checks: Is this credential valid? Am I authorized to dispatch?"

T0=$(python3 -c 'import time; print(int(time.time()*1000))')
VERIFY_BEFORE=$(curl -sSf -X POST "$API_BASE/v1/credentials/verify" \
    -H "Content-Type: application/json" \
    -d "{\"jwt\":\"$VC_JWT\"}")
T1=$(python3 -c 'import time; print(int(time.time()*1000))')
ELAPSED=$(python3 -c "print($T1 - $T0)")
python3 - <<PY
import json
v = json.loads('''$VERIFY_BEFORE''')
assert v.get('verified') is True, f"Expected verified=True, got: {v}"
PY
echo "$VERIFY_BEFORE" | python3 "$FMT" verify "$ELAPSED"
pass "Authorization verified — dispatching to ServiceNow and PagerDuty"

echo ""
echo -e "  ${BOLD}${GREEN}ALERT DISPATCHED${NC}"
echo -e "  ${DIM}→ ServiceNow: INC-2026-0311-001 created (P1)${NC}"
echo -e "  ${DIM}→ PagerDuty:  On-call team notified (escalation level 2)${NC}"
echo -e "  ${DIM}→ Slack #secops: automated thread opened${NC}"
echo -e "  ${DIM}(simulated — agent held valid credential at dispatch time)${NC}"

# ── [5/6] Incident resolved → revoke credential ───────────────────────────────
step "5/6" "Incident resolved — revoking dispatch credential instantly..."
note "Security team confirms: unauthorized person escorted out"
note "Policy: revoke immediately — no lingering permissions"

REVOKE=$(curl -sSf -X POST "$API_BASE/v1/credentials/$CRED_ID/revoke" \
    "${HDR_AUTH[@]}" -d '{}')
python3 - <<PY
import json
r = json.loads('''$REVOKE''')
assert r.get('revoked') is True, f"Expected revoked=True, got: {r}"
PY
echo "$REVOKE" | python3 "$FMT" revoked
REVOKED_AT=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
pass "Credential revoked — dispatch window closed"

# ── [6/6] Post-incident: any dispatch attempt is now denied ──────────────────
step "6/6" "Post-incident verification — credential must be DENIED..."
note "Any agent presenting this credential after revocation is blocked"

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
echo "$VERIFY_AFTER" | python3 "$FMT" verify "$ELAPSED" "$REVOKED_AT"
pass "Post-incident dispatch attempt correctly DENIED"

echo ""
echo -e "  ${BOLD}${GREEN}Incident closed. Audit trail sealed.${NC}"
echo -e "  ${DIM}Every action — issuance, verification, dispatch, revocation — is${NC}"
echo -e "  ${DIM}cryptographically logged in the hash-chained audit ledger.${NC}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}${GREEN}SECURITY INCIDENT DEMO COMPLETE ✓${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}What just happened:${NC}"
echo -e "  ${DIM}1. Ambient.ai detected a threat; Tesht issued a scoped credential${NC}"
echo -e "  ${DIM}2. Credential scope: dispatch_security_alert → servicenow, pagerduty ONLY${NC}"
echo -e "  ${DIM}3. Incident responder verified authorization before acting${NC}"
echo -e "  ${DIM}4. Alert dispatched (credential was valid at time of action)${NC}"
echo -e "  ${DIM}5. Incident resolved; credential revoked instantly${NC}"
echo -e "  ${DIM}6. Any post-incident dispatch attempt is cryptographically blocked${NC}"
echo ""
echo -e "  ${BOLD}Why this matters:${NC}"
echo -e "  ${DIM}SOC2 CC6.1: Access to sensitive systems is time-bounded and auditable${NC}"
echo -e "  ${DIM}EU AI Act Art.12: Tamper-evident log of every agent action${NC}"
echo -e "  ${DIM}Zero-trust: agent proves authorization at dispatch time, not login time${NC}"
echo ""
