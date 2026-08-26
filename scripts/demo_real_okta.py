#!/usr/bin/env python3
"""
scripts/demo_real_okta.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Standalone demonstration of the full Okta → MCP Gateway flow.

Shows the "enterprise story" in one focused script:

  Step 1: Reads a real Okta id_token (or obtains one via PKCE flow)
  Step 2: Calls IdP Bridge /attest — validates RS256 Okta JWT, issues
          an OrganizationalRoleCredential binding Alice's Okta identity
          to a W3C DID
  Step 3: Calls IdP Bridge /bind — issues delegation VC: Alice → ShoppingBot
  Step 4: Builds blended VP (Agent + Human + Enterprise credentials)
  Step 5: Sends the blended VP through the MCP Gateway to SQLite MCP
  Step 6: Displays the audit event showing the real enterprise identity
  Step 7: Verifies the audit chain integrity

Prerequisites:
  - All services running (use scripts/demo_web.sh or start manually)
  - A real Okta id_token (use scripts/get_okta_token.py to obtain one)
  - idp_bridge/config.yaml has acme_okta provider with matching issuer

Usage:
  # First obtain a real Okta token:
  python scripts/get_okta_token.py --save /tmp/okta_token.txt

  # Then run this demo:
  PYTHONPATH=".:sdk/python" python scripts/demo_real_okta.py \\
      --okta-token /tmp/okta_token.txt

  # Or set env vars and get token inline:
  PYTHONPATH=".:sdk/python" \\
  OKTA_ISSUER="https://dev-XXX.okta.com/oauth2/default" \\
  OKTA_CLIENT_ID="your_client_id" \\
  python scripts/demo_real_okta.py --get-token
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from tesht.credentials import create_blended_presentation, issue_vc
from tesht.identity import AgentIdentity

# ── Service URLs (must be running) ────────────────────────────────────────────
BRIDGE_URL = os.environ.get("BRIDGE_URL", "http://127.0.0.1:5053")
GW_URL = os.environ.get("GW_URL", "http://127.0.0.1:5052")
SQLITE_MCP_URL = os.environ.get("SQLITE_MCP_URL", "http://127.0.0.1:9102")

# ── Terminal colours ──────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
DIM = "\033[2m"

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"


def banner(text: str) -> None:
    w = 70
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def step(tag: str, msg: str, ok: bool = True) -> None:
    icon = PASS if ok else FAIL
    color = "" if ok else RED
    print(f"  [{CYAN}{tag:<8}{RESET}] {color}{msg}{RESET}  {icon}")


def info(tag: str, label: str, value: str) -> None:
    print(f"  [{CYAN}{tag:<8}{RESET}] {DIM}{label:<18}{RESET} {value}")


def section(n: str, title: str) -> None:
    line = f"Step {n}: {title}"
    pad = max(0, 64 - len(line))
    print(f"\n{BOLD}{CYAN}━━━ {line} {'━' * pad}━━━{RESET}")


def _check_service(url: str, name: str) -> bool:
    try:
        r = httpx.get(url, timeout=3.0)
        if r.status_code < 500:
            step("CHECK", f"{name} healthy", ok=True)
            return True
    except httpx.HTTPError:
        pass
    step("CHECK", f"{name} not reachable at {url}", ok=False)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tesht — Real Okta → MCP Gateway demo"
    )
    # Auto-derive OKTA_JWKS_URI and OKTA_AUDIENCE
    okta_issuer = os.environ.get("OKTA_ISSUER", "").rstrip("/")
    if okta_issuer:
        os.environ["OKTA_ISSUER"] = okta_issuer
        if not os.environ.get("OKTA_JWKS_URI"):
            if "auth0.com" in okta_issuer:
                os.environ["OKTA_JWKS_URI"] = okta_issuer + "/.well-known/jwks.json"
            else:
                os.environ["OKTA_JWKS_URI"] = okta_issuer + "/v1/keys"
        if not os.environ.get("OKTA_AUDIENCE"):
            os.environ["OKTA_AUDIENCE"] = os.environ.get("OKTA_CLIENT_ID", "")

    token_src = parser.add_mutually_exclusive_group(required=True)
    token_src.add_argument(
        "--okta-token",
        metavar="PATH_OR_TOKEN",
        help="Path to a file containing the Okta id_token, or the token string itself",
    )
    token_src.add_argument(
        "--get-token",
        action="store_true",
        help=(
            "Obtain a real Okta token interactively (requires OKTA_ISSUER and "
            "OKTA_CLIENT_ID env vars, opens browser)"
        ),
    )
    parser.add_argument(
        "--agent",
        default="shopping-bot",
        help="Agent name to use (default: shopping-bot)",
    )
    args = parser.parse_args()

    banner("Tesht — Real Okta → MCP Gateway — Enterprise Demo")

    # ── Pre-flight service checks ─────────────────────────────────────────────
    section("0", "Service Health Checks")
    ok_bridge = _check_service(f"{BRIDGE_URL}/health", "IdP Bridge")
    ok_gw = _check_service(f"{GW_URL}/gateway/health", "MCP Gateway")
    ok_sqlite = _check_service(f"{SQLITE_MCP_URL}/health", "SQLite MCP")

    if not (ok_bridge and ok_gw):
        print(f"\n  {FAIL} {RED}Required services not running.{RESET}")
        print("  Start them with:  bash scripts/demo_web.sh")
        return 1

    # ── Get the Okta token ────────────────────────────────────────────────────
    section("1", "Obtain Real Okta id_token")
    okta_token: str

    if args.get_token:
        from scripts.get_okta_token import get_okta_token
        issuer = os.environ.get("OKTA_ISSUER", "")
        client_id = os.environ.get("OKTA_CLIENT_ID", "")
        client_secret = os.environ.get("OKTA_CLIENT_SECRET") or None
        if not issuer or not client_id:
            print(f"  {FAIL} Set OKTA_ISSUER and OKTA_CLIENT_ID environment variables")
            return 1
        print(f"  {DIM}Opening browser for Okta login…{RESET}")
        okta_token = get_okta_token(issuer, client_id, client_secret, quiet=False)
    else:
        token_arg = args.okta_token
        p = Path(token_arg)
        if p.exists():
            okta_token = p.read_text().strip()
            step("TOKEN", f"Loaded Okta token from {p}")
        else:
            okta_token = token_arg.strip()
            step("TOKEN", "Using inline Okta token")

    info("TOKEN", "Length", str(len(okta_token)))
    info("TOKEN", "Preview", okta_token[:40] + "…")

    with httpx.Client() as client:
        # ── Step 2: IdP Bridge /attest ────────────────────────────────────────
        section("2", "IdP Bridge /attest — Okta JWT → Verifiable Credential")
        print(f"  {DIM}Validating Okta RS256 signature, extracting enterprise claims…{RESET}\n")

        try:
            r = client.post(
                f"{BRIDGE_URL}/attest",
                json={"oidc_token": okta_token},
                timeout=15.0,
            )
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            step("ATTEST", f"IdP Bridge /attest failed: {exc.response.status_code} {exc.response.text[:200]}", ok=False)
            print(f"\n  {YELLOW}Hint: Make sure your Okta issuer is configured in idp_bridge/config.yaml{RESET}")
            print(f"  {DIM}OKTA_ISSUER env var: {os.environ.get('OKTA_ISSUER', '(not set)')}{RESET}")
            return 1
        except httpx.HTTPError as exc:
            step("ATTEST", f"Request failed: {exc}", ok=False)
            return 1

        attest_result = r.json()
        claims = attest_result.get("claims", {})
        alice_did = attest_result.get("did", "")
        enterprise_vc = attest_result.get("vc_jwt", "")

        step("ATTEST", "OrganizationalRoleCredential issued by IdP Bridge")
        info("ATTEST", "Name",   claims.get("name", "?"))
        info("ATTEST", "Email",  claims.get("email", "?"))
        info("ATTEST", "Org",    claims.get("organization", "?"))
        info("ATTEST", "Role",   claims.get("role", "?"))
        info("ATTEST", "DID",    alice_did[:52] + "…" if len(alice_did) > 52 else alice_did)
        info("ATTEST", "Issuer", attest_result.get("provider_name", "?"))

        # ── Step 3: Create agent identity + delegation ────────────────────────
        section("3", "Create Agent + Delegation Chain")
        agent = AgentIdentity.create(args.agent)
        step("AGENT", f"Agent identity: {agent.did[:52]}…")

        r = client.post(
            f"{BRIDGE_URL}/bind",
            json={
                "oidc_token": okta_token,
                "agent_did": agent.did,
                "scope": {
                    "actions": ["read_data", "write_data", "browse_products"],
                    "max_amount": 10000,
                    "currency": "USD",
                },
                "ttl_seconds": 3600,
            },
            timeout=15.0,
        )
        r.raise_for_status()
        bind_result = r.json()
        delegation_vc = bind_result.get("delegation_vc", "")
        effective_scope = bind_result.get("effective_scope", {})

        step("BIND", f"Delegation issued: {claims.get('name', 'Alice')} → {args.agent}")
        info("BIND", "Actions", str(effective_scope.get("actions", [])))
        info("BIND", "Max amount", f"${effective_scope.get('max_amount', 0):,} USD")

        # ── Step 4: Build blended VP ──────────────────────────────────────────
        section("4", "Build Blended VP-JWT")
        print(f"  {DIM}Bundling: AgentCredential + DelegationCredential + OrganizationalRoleCredential{RESET}\n")

        gw_health = client.get(f"{GW_URL}/gateway/health", timeout=5.0).json()
        gateway_did = gw_health["gateway_did"]

        agent_vc = issue_vc(
            issuer=agent,
            subject_did=agent.did,
            credential_type="AgentCredential",
            claims={"agentName": args.agent, "ownerOrg": claims.get("organization", "Unknown")},
        )
        blended_vp = create_blended_presentation(
            agent=agent,
            delegation_jwt=delegation_vc,
            delegator_identity_jwt=enterprise_vc,
            additional_credentials=[agent_vc],
            audience=gateway_did,
        )
        step("VP", "Blended VP created")
        info("VP", "Credentials", "3 (Agent + Delegation + Enterprise)")
        info("VP", "Enterprise", f"{claims.get('name', '?')} ({claims.get('email', '?')})")
        info("VP", "Gateway DID", gateway_did[:52] + "…")

        # ── Step 5: Send through MCP Gateway ─────────────────────────────────
        section("5", "MCP Gateway — Real SQL Query")
        sql = "SELECT name, price, category FROM products WHERE in_stock = 1 LIMIT 3"
        print(f"  {DIM}SQL: {sql}{RESET}\n")

        body = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "query_database", "arguments": {"sql": sql}},
        })
        r = client.post(
            f"{GW_URL}/mcp/sqlite_database",
            content=body.encode(),
            headers={
                "Authorization": f"Bearer {blended_vp}",
                "Content-Type": "application/json",
            },
            timeout=10.0,
        )

        if r.status_code == 200:
            resp = r.json()
            result = resp.get("result", {})
            data = result.get("_data", {})
            rows = data.get("rows", [])
            trust_factors_raw = r.headers.get("X-Tesht-Trust-Factors", "{}")
            try:
                trust_factors = json.loads(trust_factors_raw)
            except json.JSONDecodeError:
                trust_factors = {}

            step("GW", "query_database → Auth ✓ | Scope ✓ | Trust ✓ → ALLOWED")
            info("GW", "Real enterprise", f"{claims.get('name', '?')} via Okta VERIFIED")

            if rows:
                info("GW", "Rows returned", f"{GREEN}{len(rows)} real rows from SQLite{RESET}")
                for row in rows:
                    info("GW", "  →", f"{row.get('name', '?')}  ${row.get('price', 0):.2f}  [{row.get('category', '?')}]")

            if trust_factors:
                base = trust_factors.get("base_score", "?")
                total_penalty = sum(
                    abs(v) for k, v in trust_factors.items()
                    if k.endswith("_penalty") and isinstance(v, (int, float))
                )
                info("TRUST", "Base score", str(base))
                info("TRUST", "Penalties", f"{total_penalty:.1f}")
                info("TRUST", "Blended VP", f"{GREEN}verified (enterprise identity in chain){RESET}")
        else:
            step("GW", f"Gateway returned {r.status_code}: {r.text[:100]}", ok=False)
            return 1

        # ── Step 6: Audit trail ───────────────────────────────────────────────
        section("6", "Audit Trail — Real Enterprise Identity")
        events_r = client.get(f"{GW_URL}/gateway/events?n=5", timeout=5.0)
        if events_r.status_code == 200:
            events = events_r.json()
            last_allowed = next((e for e in reversed(events) if e.get("decision") == "allowed"), None)
            if last_allowed:
                dc = last_allowed.get("delegator_claims", {}) or {}
                step("AUDIT", "Event recorded in audit trail")
                info("AUDIT", "Agent DID",    (last_allowed.get("agent_did") or "")[:52] + "…")
                info("AUDIT", "Human identity", f"{dc.get('name', '?')} ({dc.get('email', '?')})")
                info("AUDIT", "Org",          dc.get("organization", "?"))
                info("AUDIT", "Trust score",  str(last_allowed.get("trust_score", "?")))
                info("AUDIT", "Decision",     f"{GREEN}ALLOWED{RESET}")
                info("AUDIT", "Latency",      f"{round(last_allowed.get('total_latency_ms', 0))}ms")
                info("AUDIT", "Blended VP",   f"{GREEN}enterprise identity visible in trail{RESET}")

        # ── Step 7: Audit chain verification ─────────────────────────────────
        section("7", "Audit Chain Verification")
        verify_r = client.get(f"{GW_URL}/gateway/audit/verify", timeout=10.0)
        if verify_r.status_code == 200:
            vfy = verify_r.json()
            storage = vfy.get("storage", "unknown")
            n = vfy.get("events_checked", 0)
            is_valid = vfy.get("valid", False)

            if storage == "postgresql":
                step("CHAIN", f"SHA-256 hash chain: {n} events checked", ok=is_valid)
                info("CHAIN", "Storage",   "PostgreSQL (persistent)")
                info("CHAIN", "Integrity", f"{GREEN}VALID{RESET}" if is_valid else f"{RED}BROKEN{RESET}")
            else:
                in_mem = vfy.get("in_memory_count", n)
                step("CHAIN", f"In-memory audit: {in_mem} events")
                info("CHAIN", "Storage", "in-memory (start PostgreSQL for persistence)")
                info("CHAIN", "Hint",    "docker compose up postgres -d")

    print(f"\n{BOLD}{GREEN}━━━ Real Okta enterprise demo complete ━━━━━━━━━━━━━━━━━━━━━━━━{RESET}{BOLD}{RESET}")
    print(f"\n  Enterprise user authenticated via real Okta RS256 JWT.")
    print(f"  Tesht issued a W3C Verifiable Credential binding {claims.get('name', 'the user')}")
    print(f"  to a DID and delegated to the agent.")
    print(f"  The blended VP was verified by the MCP Gateway with full")
    print(f"  enterprise identity visible in the tamper-evident audit trail.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
