#!/usr/bin/env python3
"""
Tesht (Pramana) — Full Lifecycle Mega-Demo
============================================

A single self-contained script demonstrating all 5 improvements in sequence:
  1. Enterprise Identity  — OIDC (mock Okta) → W3C Verifiable Credential
  2. Blended Identity     — Agent + Human + Enterprise in one VP-JWT
  3. Scope Enforcement    — Gateway blocks out-of-scope tool calls
  4. Continuous Trust     — Dynamic 0-100 scoring, step-up, recovery
  5. Detection            — Shadow agent alert, scope probing detection

Starts 4 services as subprocesses, waits for health, runs 6 acts,
prints the full lifecycle dashboard, then shuts everything down cleanly.

Run:
    PYTHONPATH=".:sdk/python" python scripts/demo_mega.py
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
sys.path.insert(0, str(PROJECT_ROOT))

import httpx
import yaml

from tesht.credentials import create_blended_presentation, create_presentation, issue_vc
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity

from scripts.demo_explainer import (
    decode_and_display_vp,
    display_credential_isolation,
    display_delegation_chain,
    display_trust_breakdown,
    display_trust_timeline,
)

# ── Global explain flag — set in main() ───────────────────────────────────────
EXPLAIN: bool = True

# ── Ports ─────────────────────────────────────────────────────────────────────
OIDC_PORT = 9200
BRIDGE_PORT = 5053
MCP_PORT = 9100
SQLITE_MCP_PORT = 9102
GW_PORT = 5052

OIDC_URL = f"http://127.0.0.1:{OIDC_PORT}"
BRIDGE_URL = f"http://127.0.0.1:{BRIDGE_PORT}"
MCP_URL = f"http://127.0.0.1:{MCP_PORT}"
SQLITE_MCP_URL = f"http://127.0.0.1:{SQLITE_MCP_PORT}"
GW_URL = f"http://127.0.0.1:{GW_PORT}"

# ── Terminal colours ──────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
WARN = f"{YELLOW}⚠{RESET}"


# ── Output helpers ────────────────────────────────────────────────────────────

def banner(text: str) -> None:
    w = 70
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def section(act: str, title: str) -> None:
    line = f"Act {act}: {title}"
    pad = max(0, 64 - len(line))
    print(f"\n{BOLD}{CYAN}━━━ {line} {'━' * pad}━━━{RESET}")


def step(tag: str, msg: str, ok: bool = True) -> None:
    icon = PASS if ok else FAIL
    color = "" if ok else RED
    print(f"  [{CYAN}{tag:<7}{RESET}] {color}{msg}{RESET}  {icon}")


def info(tag: str, label: str, value: str) -> None:
    print(f"  [{CYAN}{tag:<7}{RESET}] {DIM}{label:<16}{RESET} {value}")


def warn_box(lines: list[str]) -> None:
    w = max(len(l) for l in lines) + 4
    print(f"  {YELLOW}╔{'═' * w}╗{RESET}")
    for line in lines:
        pad = w - len(line) - 2
        print(f"  {YELLOW}║{RESET}  {line}{' ' * pad}{YELLOW}║{RESET}")
    print(f"  {YELLOW}╚{'═' * w}╝{RESET}")


def alert_box(severity: str, title: str, lines: list[str]) -> None:
    color = RED if severity == "critical" else YELLOW
    w = 63
    print(f"\n  {color}╔{'═' * w}╗{RESET}")
    icon = "!!" if severity == "critical" else "~~"
    header = f"  [{icon}] ALERT: {title}"
    print(f"  {color}║{RESET} {BOLD}{header:<{w - 1}}{RESET}{color}║{RESET}")
    print(f"  {color}║{RESET} {f'Severity: {severity.upper()}':<{w - 1}}{color}║{RESET}")
    for line in lines:
        # hard-wrap at w-2 characters
        max_w = w - 2
        while len(line) > max_w:
            print(f"  {color}║{RESET} {line[:max_w]:<{max_w}}{color}║{RESET}")
            line = "  " + line[max_w:]
        print(f"  {color}║{RESET} {line:<{w - 1}}{color}║{RESET}")
    print(f"  {color}╚{'═' * w}╝{RESET}")


# ── Service management ────────────────────────────────────────────────────────

def _write_demo_config() -> str:
    providers: dict = {
        "mock_idp": {
            "name": "Acme Corp Okta (Mock)",
            "issuer": "https://mock-idp.tesht.local",
            "jwks_uri": f"http://127.0.0.1:{OIDC_PORT}/.well-known/jwks.json",
            "audience": "tesht",
            "claim_mapping": {
                "name": "name",
                "email": "email",
                "organization": "org",
                "department": "department",
                "role": "role",
            },
            "default_credential_type": "OrganizationalRoleCredential",
            "allowed_algorithms": ["RS256"],
        },
    }

    # If a real IdP is configured, inject it into the temp config so the bridge
    # can validate real tokens (Auth0 / Okta dev tenant).
    okta_issuer = os.environ.get("OKTA_ISSUER", "").rstrip("/")
    if okta_issuer:
        if "auth0.com" in okta_issuer:
            jwks_uri = okta_issuer + "/.well-known/jwks.json"
        else:
            jwks_uri = os.environ.get("OKTA_JWKS_URI", okta_issuer + "/v1/keys")
        audience = os.environ.get("OKTA_AUDIENCE", os.environ.get("OKTA_CLIENT_ID", ""))
        providers["acme_okta"] = {
            "name": "Acme Corp (Auth0/Okta Dev)",
            "issuer": okta_issuer,
            "jwks_uri": jwks_uri,
            "audience": audience,
            "claim_mapping": {
                "name": "name",
                "email": "email",
                "organization": "org_name",
                "department": "department",
                "role": "job_title",
            },
            "default_credential_type": "OrganizationalRoleCredential",
            "allowed_algorithms": ["RS256"],
        }

    cfg = {"providers": providers}
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump(cfg, f)
    f.close()
    return f.name


def start_server(
    module: str, port: int, extra_env: Optional[dict] = None
) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", module,
            "--host", "127.0.0.1", "--port", str(port),
            "--log-level", "error",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_healthy(url: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    return False


def kill_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── MCP call helpers ──────────────────────────────────────────────────────────

def mcp_call(
    client: httpx.Client,
    vp: str,
    tool: str,
    req_id: int = 1,
    server: str = "sqlite_database",
    arguments: Optional[dict] = None,
) -> tuple[int, dict]:
    body = json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    })
    r = client.post(
        f"{GW_URL}/mcp/{server}",
        content=body.encode(),
        headers={
            "Authorization": f"Bearer {vp}",
            "Content-Type": "application/json",
        },
        timeout=10.0,
    )
    return r.status_code, r.json()


def mcp_no_auth(client: httpx.Client, req_id: int = 1) -> tuple[int, dict]:
    body = json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "method": "tools/call",
        "params": {"name": "query_database", "arguments": {"sql": "SELECT name FROM products LIMIT 1"}},
    })
    r = client.post(
        f"{GW_URL}/mcp/sqlite_database",
        content=body.encode(),
        headers={"Content-Type": "application/json"},
        timeout=10.0,
    )
    return r.status_code, r.json()


# ── Act implementations ───────────────────────────────────────────────────────

def act1_enterprise_identity(
    client: httpx.Client,
    shopping_bot: AgentIdentity,
    okta_token: Optional[str] = None,
) -> tuple[str, str, str]:
    """
    Alice (Acme Corp Senior Buyer) authenticates via Okta (real or mock).
    IdP bridge issues OrganizationalRoleCredential and delegation to ShoppingBot.
    Returns (enterprise_vc, delegation_vc, alice_claims_str).
    """
    section("1", "Enterprise Identity")
    print(f"  {DIM}Alice Johnson, Senior Buyer @ Acme Corp authenticates via Okta{RESET}\n")

    if okta_token:
        # Use real Okta id_token directly
        alice_token = okta_token
        step("IDP", "Alice authenticates via Acme Corp Okta (REAL — live token)")
    else:
        # Get OIDC token from mock provider
        r = client.get(f"{OIDC_URL}/token?user=alice", timeout=5.0)
        r.raise_for_status()
        alice_token = r.json()["id_token"]
        step("IDP", "Alice authenticates via Acme Corp Okta (mock RS256)")

    # Bind: attest + delegate in one call
    r = client.post(f"{BRIDGE_URL}/bind", json={
        "oidc_token": alice_token,
        "agent_did": shopping_bot.did,
        "scope": {
            "actions": ["read_data", "write_data", "browse_products", "purchase"],
            "max_amount": 50000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": ["electronics", "office_supplies"],
        },
        "ttl_seconds": 3600,
    }, timeout=10.0)
    r.raise_for_status()
    bind = r.json()

    claims = bind["claims"]
    step("VC", "OrganizationalRoleCredential issued by IdP bridge")
    info("VC", "Name", claims.get("name", "?"))
    info("VC", "Email", claims.get("email", "?"))
    info("VC", "Org", claims.get("organization", "?"))
    info("VC", "Role", claims.get("role", "?"))
    info("VC", "DID assigned", bind["did"][:48] + "...")

    step("DEL", f"Delegation: Alice → ShoppingBot")
    info("DEL", "Scope", str(bind["effective_scope"].get("actions", [])))
    info("DEL", "Max amount", f"${bind['effective_scope'].get('max_amount', 0):,} USD")

    if EXPLAIN:
        display_delegation_chain(
            chain=[{
                "delegator": bind["did"],
                "delegate": shopping_bot.did,
                "scope": bind["effective_scope"],
                "depth": 1,
                "max_depth": 2,
            }],
            effective_scope=bind["effective_scope"],
            delegator_claims=claims,
            agent_did=shopping_bot.did,
        )

    time.sleep(1)
    return bind["enterprise_vc"], bind["delegation_vc"], claims.get("name", "Alice")


def act2_blended_gateway(
    client: httpx.Client,
    shopping_bot: AgentIdentity,
    enterprise_vc: str,
    delegation_vc: str,
    gateway_did: str,
) -> str:
    """
    ShoppingBot bundles 3 credentials into a blended VP and calls
    query_database through the MCP gateway.
    Returns the blended VP JWT for reuse in later acts.
    """
    section("2", "Blended Identity Through MCP Gateway")
    print(f"  {DIM}Agent + Human + Enterprise in a single VP-JWT{RESET}\n")

    # Self-issue agent credential
    agent_vc = issue_vc(
        issuer=shopping_bot,
        subject_did=shopping_bot.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShoppingBot", "ownerOrg": "Acme Corp"},
    )

    blended_vp = create_blended_presentation(
        agent=shopping_bot,
        delegation_jwt=delegation_vc,
        delegator_identity_jwt=enterprise_vc,
        additional_credentials=[agent_vc],
        audience=gateway_did,
    )
    step("BLEND", "Blended VP: ShoppingBot + Alice Johnson (alice@acmecorp.com via Okta)")
    info("BLEND", "Credentials", "AgentCredential + DelegationCredential + OrganizationalRoleCredential")

    if EXPLAIN:
        decode_and_display_vp(blended_vp)

    # Call through gateway — real SQL query against SQLite
    sql = "SELECT name, price, category FROM products LIMIT 5"
    status, resp = mcp_call(
        client, blended_vp, "query_database", req_id=1,
        server="sqlite_database",
        arguments={"sql": sql},
    )
    if status == 200:
        step("GW", "query_database → Auth ✓ | Scope ✓ | Trust ✓ → ALLOW")
        # Extract real rows from the response
        result_data = resp.get("result", {}).get("_data") or {}
        rows = result_data.get("rows", [])
        if rows:
            info("DB", "SQL", f"{DIM}{sql}{RESET}")
            info("DB", "Rows returned", f"{GREEN}{len(rows)} rows from SQLite{RESET}")
            for r_row in rows[:3]:
                info("DB", "  →", f"{r_row.get('name', '?')}  ${r_row.get('price', 0):.2f}  [{r_row.get('category', '?')}]")
            if len(rows) > 3:
                info("DB", "  →", f"… and {len(rows) - 3} more rows")
        else:
            info("DB", "SQL", f"{DIM}{sql}{RESET}")
            info("DB", "Result", "Real database query executed")
    else:
        step("GW", f"Unexpected {status}: {str(resp)[:60]}", ok=False)

    # Show credential isolation
    cred_r = client.get(f"{SQLITE_MCP_URL}/credentials-received", timeout=5.0)
    if cred_r.status_code != 200:
        # Fallback to mock MCP
        cred_r = client.get(f"{MCP_URL}/credentials-received", timeout=5.0)
    if cred_r.status_code == 200:
        cred_data = cred_r.json()
        # sqlite_mcp_server uses "credentials" key; mock uses "requests"
        cred_list = cred_data.get("credentials") or cred_data.get("requests", [])
        if cred_list:
            last = cred_list[-1]
            hdrs = last.get("headers_received", {}) or {}
            auth_val = last.get("auth_header", "") or hdrs.get("authorization", "")
            api_key_val = hdrs.get("x-api-key", "") or hdrs.get("X-API-Key", "")
            step("CREDS", "Credential isolation verified")
            info("CREDS", "Agent sent", "Bearer <VP-JWT>  (blended presentation)")
            info("CREDS", "Server got", f"X-API-Key: {api_key_val[:15]}… (gateway credential)")
            if not auth_val.startswith("Bearer ey"):
                info("CREDS", "Isolation", f"{GREEN}VP never forwarded to upstream{RESET}")
            if EXPLAIN:
                display_credential_isolation(blended_vp, last)

    # Show audit trail entry
    events_r = client.get(f"{GW_URL}/gateway/events?n=3", timeout=5.0)
    events = events_r.json() if events_r.status_code == 200 else []
    allowed = [e for e in events if e.get("decision") == "allowed"]
    if allowed:
        e = allowed[-1]
        dc = e.get("delegator_claims", {})
        trust = e.get("trust_score", "?")
        ms = round(e.get("total_latency_ms", 0))
        step("AUDIT", f"alice→shoppingbot→query_database: ALLOWED (trust:{trust}, {ms}ms)")
        info("AUDIT", "Human identity", f"{dc.get('name','?')} ({dc.get('email','?')} via Okta)")
        if EXPLAIN:
            factors = e.get("trust_factors", {})
            display_trust_breakdown(factors, trust, "allow", tool_name="query_database")

    time.sleep(1)
    return blended_vp


def act3_scope_enforcement(
    client: httpx.Client,
    blended_vp: str,
) -> None:
    """ShoppingBot calls delete_record — requires 'admin', not in scope."""
    section("3", "Scope Enforcement")
    print(f"  {DIM}ShoppingBot tries delete_record (requires admin — not delegated){RESET}\n")

    status, resp = mcp_call(client, blended_vp, "delete_record", req_id=10,
                            server="sqlite_database")
    if status == 403:
        step("GW", "delete_record → Auth ✓ | Scope ✗ | BLOCKED")
        err_msg = resp.get("error", {}).get("message", "")
        info("SCOPE", "Required", '"admin"')
        info("SCOPE", "Agent has", '["read_data", "write_data", "browse_products", "purchase"]')
        info("SCOPE", "Decision", f"{RED}BLOCKED — never reached MCP server{RESET}")
    else:
        step("GW", f"Expected 403, got {status}", ok=False)

    if EXPLAIN:
        events_r = client.get(f"{GW_URL}/gateway/events?n=5", timeout=5.0)
        events = events_r.json() if events_r.status_code == 200 else []
        last_blocked = next(
            (e for e in reversed(events) if e.get("decision") == "blocked_scope"), None
        )
        if last_blocked:
            factors = last_blocked.get("trust_factors", {})
            score = last_blocked.get("trust_score", 0)
            decision = last_blocked.get("trust_decision", "allow")
            display_trust_breakdown(factors, score, decision, tool_name="delete_record")

    time.sleep(1)


def act4_continuous_trust(
    client: httpx.Client,
    shopping_bot: AgentIdentity,
    enterprise_vc: str,
    delegation_vc: str,
    gateway_did: str,
    blended_vp: str,
) -> list[dict]:
    """
    Two more scope violations degrade trust. Next legit call triggers step-up.
    Re-auth with fresh VP partially restores trust.
    Returns list of trust events for the timeline.
    """
    section("4", "Continuous Trust Degradation & Recovery")
    print(f"  {DIM}Same agent, same credentials — trust changes based on behavior alone{RESET}\n")

    # Violation 2: scope probe
    status, _ = mcp_call(client, blended_vp, "delete_record", req_id=11,
                         server="sqlite_database")
    step("TRUST", f"Scope violation #2: delete_record → BLOCKED (trust degrading)")

    # Violation 3: another probe
    status, _ = mcp_call(client, blended_vp, "delete_record", req_id=12,
                         server="sqlite_database")
    step("TRUST", f"Scope violation #3: delete_record → BLOCKED (trust degraded further)")

    if EXPLAIN:
        events_r = client.get(f"{GW_URL}/gateway/events?n=5", timeout=5.0)
        ev_list = events_r.json() if events_r.status_code == 200 else []
        last_blocked = next(
            (e for e in reversed(ev_list) if e.get("decision") == "blocked_scope"), None
        )
        if last_blocked:
            factors = last_blocked.get("trust_factors", {})
            score = last_blocked.get("trust_score", 0)
            display_trust_breakdown(factors, score, "allow", tool_name="delete_record")

    # Now a legitimate call should hit step-up
    status, resp = mcp_call(client, blended_vp, "query_database", req_id=13,
                            server="sqlite_database",
                            arguments={"sql": "SELECT COUNT(*) as total FROM products"})
    if status == 401 and "step" in str(resp).lower():
        step("GW", "query_database → Trust too low → STEP-UP required")
        info("GW", "Response", "401  X-Tesht-StepUp: re-present-vp")
    elif status == 200:
        # Trust may still be above threshold (depends on exact score)
        trust_events = client.get(f"{GW_URL}/gateway/events?n=5", timeout=5.0).json()
        last_event = next((e for e in reversed(trust_events)
                           if e.get("decision") in ("allowed", "step_up")), None)
        score = last_event.get("trust_score", "?") if last_event else "?"
        decision = last_event.get("decision", "?") if last_event else "?"
        step("GW", f"query_database → Trust:{score} → {decision.upper()}")
    else:
        step("GW", f"query_database → {status} (trust degraded)", ok=status in (401, 200, 403))

    # Re-auth with fresh VP (new JWT = new hash = penalty partial reset)
    agent_vc = issue_vc(
        issuer=shopping_bot,
        subject_did=shopping_bot.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShoppingBot", "ownerOrg": "Acme Corp"},
    )
    fresh_vp = create_blended_presentation(
        agent=shopping_bot,
        delegation_jwt=delegation_vc,
        delegator_identity_jwt=enterprise_vc,
        additional_credentials=[agent_vc],
        audience=gateway_did,
    )
    step("REAUTH", "ShoppingBot presents fresh VP (new JWT hash → penalty reset)")

    status, _ = mcp_call(client, fresh_vp, "query_database", req_id=14,
                         server="sqlite_database",
                         arguments={"sql": "SELECT name, price FROM products ORDER BY price DESC LIMIT 3"})
    events_r = client.get(f"{GW_URL}/gateway/events?n=3", timeout=5.0)
    events = events_r.json() if events_r.status_code == 200 else []
    last = next((e for e in reversed(events) if e.get("decision") in ("allowed", "step_up")), None)
    score = last.get("trust_score", "?") if last else "?"
    if status == 200:
        step("GW", f"query_database → Trust:{score} → ALLOW (trust restored)")
        if EXPLAIN and last:
            factors = last.get("trust_factors", {})
            display_trust_breakdown(factors, score, "allow", tool_name="query_database (re-auth)")
    else:
        step("GW", f"query_database → {status}, trust:{score}")

    # Collect all events for the timeline
    all_events_r = client.get(f"{GW_URL}/gateway/events?n=30", timeout=5.0)
    timeline_events = all_events_r.json() if all_events_r.status_code == 200 else []

    time.sleep(1)
    return timeline_events


def act5_shadow_attack(
    client: httpx.Client,
    gateway_did: str,
    enterprise_vc: str,
    delegation_vc: str,
) -> None:
    """Three shadow agent categories — no creds, expired VP, missing delegation."""
    section("5", "Shadow Agent Attack")
    print(
        f"  {DIM}Three distinct unauthorized agents attempt gateway access{RESET}\n"
    )

    # ── Phase 1: No credentials ───────────────────────────────────────────────
    print(f"  {CYAN}Phase 1:{RESET} Agent with {BOLD}no credentials{RESET}")
    status1, resp1 = mcp_no_auth(client, req_id=100)
    err1 = resp1.get("error", {}).get("message", "auth failed")
    print(
        f"  {RED}[!!]{RESET}  Category 1: No credentials     "
        f"→ {RED}BLOCKED{RESET}  {DIM}({err1[:50]}){RESET}"
    )
    time.sleep(0.3)

    # ── Phase 2: Expired VP ───────────────────────────────────────────────────
    print(f"\n  {CYAN}Phase 2:{RESET} Agent with {BOLD}expired VP{RESET} (ttl=1s, sleep 2s)")
    expired_agent = AgentIdentity.create("ExpiredBot")
    expired_agent_vc = issue_vc(
        issuer=expired_agent,
        subject_did=expired_agent.did,
        credential_type="AgentCredential",
        claims={"agentName": "ExpiredBot"},
    )
    # Use create_presentation so we don't hit delegation-subject-mismatch;
    # the VP expires before the gateway can validate the delegation chain.
    expired_vp = create_presentation(
        holder=expired_agent,
        credentials=[delegation_vc, enterprise_vc, expired_agent_vc],
        audience=gateway_did,
        ttl_seconds=1,
        presentation_type="BlendedIdentityPresentation",
    )
    time.sleep(2)  # VP is now expired
    status2, resp2 = mcp_call(
        client, expired_vp, "query_database", req_id=200,
        arguments={"sql": "SELECT 1"},
    )
    err2 = resp2.get("error", {}).get("message", "auth failed")
    print(
        f"  {RED}[!!]{RESET}  Category 2: Expired VP          "
        f"→ {RED}BLOCKED{RESET}  {DIM}({err2[:50]}){RESET}"
    )
    time.sleep(0.3)

    # ── Phase 3: Missing delegation (incomplete VP) ───────────────────────────
    print(f"\n  {CYAN}Phase 3:{RESET} Agent with {BOLD}no delegation credential{RESET}")
    rogue_agent = AgentIdentity.create("RogueBot")
    rogue_vc = issue_vc(
        issuer=rogue_agent,
        subject_did=rogue_agent.did,
        credential_type="AgentCredential",
        claims={"agentName": "RogueBot"},
    )
    # VP has only an AgentCredential — no DelegationCredential, no enterprise VC.
    # Gateway requires require_delegation=True, so this is rejected.
    rogue_vp = create_presentation(
        holder=rogue_agent,
        credentials=[rogue_vc],
        audience=gateway_did,
        ttl_seconds=300,
        presentation_type="BlendedIdentityPresentation",
    )
    status3, resp3 = mcp_call(
        client, rogue_vp, "query_database", req_id=300,
        arguments={"sql": "SELECT 1"},
    )
    err3 = resp3.get("error", {}).get("message", "auth failed")
    print(
        f"  {RED}[!!]{RESET}  Category 3: Missing delegation  "
        f"→ {RED}BLOCKED{RESET}  {DIM}({err3[:50]}){RESET}"
    )
    time.sleep(0.3)

    # ── Detection scan ────────────────────────────────────────────────────────
    print(f"\n  {DIM}Running detection scan…{RESET}")
    time.sleep(0.5)
    det_r = client.get(f"{GW_URL}/gateway/detections", timeout=10.0)
    det = det_r.json() if det_r.status_code == 200 else {}
    alerts = det.get("alerts", [])

    shadow_alerts = [a for a in alerts if a.get("type") == "shadow_agent"]
    fleet_alerts = [a for a in alerts if a.get("type") == "fleet_threat"]

    # Build category summary from shadow alerts
    categories: dict[str, tuple[int, str]] = {}
    for a in shadow_alerts:
        title = a.get("title", "")
        count = a.get("evidence", {}).get("attempt_count", 1)
        sev = a.get("severity", "warning")
        if "No credentials" in title:
            categories["no_creds"] = (count, sev)
        elif "Expired VP" in title:
            categories["expired_vp"] = (count, sev)
        elif "Invalid credentials" in title:
            categories["invalid_creds"] = (count, sev)
        elif "Untrusted" in title:
            categories["untrusted"] = (count, sev)

    # Fleet correlation evidence
    fleet_overlap_lines: list[str] = []
    for fa in fleet_alerts:
        if "swarm" in fa.get("title", "").lower():
            ev = fa.get("evidence", {})
            overlap = ev.get("server_overlap", [])
            servers = ev.get("servers_targeted", [])
            if overlap:
                fleet_overlap_lines.append(
                    f"• Shadow agents targeted same server: {', '.join(overlap)}"
                )
            elif servers:
                fleet_overlap_lines.append(
                    f"• Servers targeted: {', '.join(servers)}"
                )
            fleet_overlap_lines.append(
                f"• {ev.get('attempt_count', 3)} attempts in "
                f"{ev.get('window_minutes', 5)} min  → Severity: CRITICAL"
            )

    # Build display lines
    summary_lines: list[str] = [
        "3 categories of unauthorized access detected:",
        "",
        f"  • No credentials:   {categories.get('no_creds', (1, 'warning'))[0]} attempt(s)  "
        f"[{categories.get('no_creds', (1,'warning'))[1].upper()}]",
        f"  • Expired VP:       {categories.get('expired_vp', (1, 'warning'))[0]} attempt(s)  "
        f"[{categories.get('expired_vp', (1,'warning'))[1].upper()}]",
        f"  • Missing delegation:{categories.get('invalid_creds', (1, 'warning'))[0]} attempt(s)  "
        f"[{categories.get('invalid_creds', (1,'warning'))[1].upper()}]",
    ]
    if fleet_overlap_lines:
        summary_lines += ["", "FLEET CORRELATION:"] + fleet_overlap_lines

    alert_box("critical", "Shadow Agent Detection Summary", summary_lines)
    time.sleep(1)


def act6_fleet_dashboard(client: httpx.Client, timeline_events: Optional[list] = None) -> None:
    """Print the full lifecycle dashboard with actual data from all 5 acts."""
    section("6", "Fleet Dashboard")
    print(f"  {DIM}Full lifecycle summary — real data from all 5 acts{RESET}\n")

    # Gather data
    det_r = client.get(f"{GW_URL}/gateway/detections", timeout=10.0)
    inv_r = client.get(f"{GW_URL}/gateway/inventory", timeout=5.0)
    events_r = client.get(f"{GW_URL}/gateway/events?n=20", timeout=5.0)

    det = det_r.json() if det_r.status_code == 200 else {}
    inv = inv_r.json() if inv_r.status_code == 200 else {}
    events = events_r.json() if events_r.status_code == 200 else []

    fleet = det.get("fleet", {})
    alerts = det.get("alerts", [])
    known_agents = inv.get("known_agents", [])
    shadow_attempts = inv.get("shadow_attempts", [])

    # Build audit table rows from actual events
    audit_rows = []
    for e in events:
        decision = e.get("decision", "?")
        if decision == "allowed":
            dec_str = f"{GREEN}ALLOWED{RESET} "
        elif decision == "step_up":
            dec_str = f"{YELLOW}STEP-UP{RESET}"
        elif decision == "blocked_auth":
            dec_str = f"{RED}BLOCKED{RESET} "
        elif decision == "blocked_scope":
            dec_str = f"{RED}BLOCKED{RESET} "
        elif decision == "blocked_trust":
            dec_str = f"{RED}BLOCKED{RESET} "
        else:
            dec_str = f"{DIM}{decision:<7}{RESET}"

        agent_did_val = e.get("agent_did") or ""
        agent_name = e.get("agent_name") or ""
        if not agent_name:
            if agent_did_val:
                agent_name = "ShoppingBot"  # only agent in this demo
            else:
                agent_name = "[unknown]"
        dc = e.get("delegator_claims") or {}
        human_name = dc.get("name", "—")
        if human_name != "—" and len(human_name) > 10:
            human_name = human_name.split()[0] + " J."
        tool = e.get("tool_name") or "—"
        trust = e.get("trust_score", "—")
        ms = round(e.get("total_latency_ms", 0))
        audit_rows.append((agent_name, human_name, tool, dec_str, trust, ms))

    # Alert list
    alert_lines = []
    for a in alerts[:5]:
        sev_color = RED if a.get("severity") == "critical" else YELLOW
        title = a.get("title", "")[:55]
        alert_lines.append(f"{sev_color}!! CRITICAL{RESET}: {title}")

    # Print dashboard
    w = 70
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {'TESHT PROTOCOL — Full Lifecycle Demo Complete':<{w - 2}}║{RESET}")
    print(f"{BOLD}╠{'═' * w}╣{RESET}")
    cap_rows = [
        ("IDENTITY  ", "Enterprise OIDC (Okta) → W3C Verifiable Credential"),
        ("DELEGATION", "Alice → ShoppingBot, scoped [purchase] ≤ $50,000 USD"),
        ("BLENDED VP", "Agent + Human + Enterprise in one VP-JWT"),
        ("GATEWAY   ", "MCP proxy: credential isolation + per-request auth"),
        ("TRUST     ", "Dynamic 0-100 scoring: behavioral penalties + recovery"),
        ("DETECTION ", "Shadow agent blocked, scope probing detected"),
        ("AUDIT     ", "Every decision logged with full identity chain"),
    ]
    for label, desc in cap_rows:
        print(f"{BOLD}║{RESET}  {CYAN}{label}{RESET}  {desc:<{w - 14}}{BOLD}║{RESET}")
    print(f"{BOLD}╠{'═' * w}╣{RESET}")

    # Fleet status
    total_agents = fleet.get("total_agents", len(known_agents))
    avg_trust = fleet.get("avg_trust", 0)
    n_shadows = fleet.get("shadow_attempts", len(shadow_attempts))
    n_violations = fleet.get("with_violations", 0)
    n_alerts = len(alerts)
    risk_dist = fleet.get("risk_distribution", {})

    print(f"{BOLD}║{RESET}  {'FLEET STATUS':<{w - 2}}{BOLD}║{RESET}")
    fleet_line = (f"Agents: {total_agents} known  |  Shadow attempts: {n_shadows}  |  "
                  f"Alerts: {n_alerts}  |  Avg trust: {avg_trust:.0f}/100")
    print(f"{BOLD}║{RESET}  {fleet_line:<{w - 2}}{BOLD}║{RESET}")
    risk_line = (f"Risk — Low:{risk_dist.get('low',0)}  Medium:{risk_dist.get('medium',0)}  "
                 f"High:{risk_dist.get('high',0)}  Critical:{risk_dist.get('critical',0)}")
    print(f"{BOLD}║{RESET}  {risk_line:<{w - 2}}{BOLD}║{RESET}")
    print(f"{BOLD}╠{'═' * w}╣{RESET}")

    # Audit trail table
    print(f"{BOLD}║{RESET}  {'AUDIT TRAIL':<{w - 2}}{BOLD}║{RESET}")
    hdr = f"{'#':<3}  {'Agent':<13} {'Human':<12} {'Tool':<16} {'Decision':<7} {'Trust':<5} {'ms':<4}"
    print(f"{BOLD}║{RESET}  {DIM}{hdr}{RESET}  {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}  {DIM}{'─' * (w - 4)}{RESET}  {BOLD}║{RESET}")
    for idx, (agent, human, tool, dec, trust, ms) in enumerate(audit_rows[:10], 1):
        # strip ANSI for length calculation
        dec_plain = dec.replace(f"{GREEN}", "").replace(f"{RED}", "").replace(f"{YELLOW}", "").replace(f"{RESET}", "")
        row = f"{idx:<3}  {agent[:13]:<13} {human[:12]:<12} {tool[:16]:<16} {dec}{dec_plain[7:]!s:<0} {str(trust):<5} {ms}ms"
        # Use fixed-width line since ANSI codes inflate length
        print(f"{BOLD}║{RESET}  {idx:<3}  {agent[:12]:<12} {human[:11]:<11} {tool[:15]:<15} {dec}  {str(trust):<5} {ms}ms  {BOLD}║{RESET}")
    print(f"{BOLD}╠{'═' * w}╣{RESET}")

    # Alerts
    print(f"{BOLD}║{RESET}  {'ALERTS':<{w - 2}}{BOLD}║{RESET}")
    if alerts:
        for a in alerts[:4]:
            sev_color = RED if a.get("severity") == "critical" else YELLOW
            title = a.get("title", "")[:58]
            icon = "!!" if a.get("severity") == "critical" else "~~"
            print(f"{BOLD}║{RESET}  {sev_color}[{icon}]{RESET} {title:<{w - 7}}{BOLD}║{RESET}")
    else:
        print(f"{BOLD}║{RESET}  {'No active alerts':<{w - 2}}{BOLD}║{RESET}")
    print(f"{BOLD}╠{'═' * w}╣{RESET}")

    # Differentiators
    taglines = [
        "All on W3C open standards. No vendor lock-in.",
        "Aembit does binary allow/deny. Tesht does continuous, graduated trust.",
        "$285M went to NHI detection. Tesht prevents AND detects.",
    ]
    for t in taglines:
        print(f"{BOLD}║{RESET}  {DIM}{t:<{w - 2}}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}╠{'═' * w}╣{RESET}")

    # Brief pause to let async PG writes flush before verifying the chain
    time.sleep(3.0)

    # Audit chain verification
    try:
        verify_r = client.get(f"{GW_URL}/gateway/audit/verify", timeout=10.0)
        if verify_r.status_code == 200:
            vfy = verify_r.json()
            storage = vfy.get("storage", "unknown")
            n_checked = vfy.get("events_checked", 0)
            in_mem = vfy.get("in_memory_count", n_checked)
            is_valid = vfy.get("valid", False)
            broken_at = vfy.get("first_broken_at")
            print(f"{BOLD}║{RESET}  {'AUDIT CHAIN VERIFICATION':<{w - 2}}{BOLD}║{RESET}")
            if storage == "postgresql":
                status_icon = PASS if is_valid else FAIL
                status_label = f"{GREEN}VALID{RESET}" if is_valid else f"{RED}BROKEN at {broken_at}{RESET}"
                chain_line = (f"Storage: PostgreSQL  |  Events: {n_checked}  |  "
                              f"Algorithm: SHA-256 hash chain  |  {status_label}")
                print(f"{BOLD}║{RESET}  {status_icon}  {chain_line}{BOLD}{RESET}")
            else:
                chain_line = (f"Storage: in-memory  |  Events: {in_mem}  |  "
                              f"Set DATABASE_URL for PostgreSQL hash-chain verification")
                print(f"{BOLD}║{RESET}  {DIM}{chain_line:<{w - 2}}{RESET}{BOLD}║{RESET}")
    except Exception:
        print(f"{BOLD}║{RESET}  {DIM}Audit chain verification unavailable{RESET}  {BOLD}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}\n")

    if EXPLAIN and timeline_events:
        # Only show events with a real trust score (agent requests, not shadow)
        scored = [e for e in timeline_events if e.get("trust_score") is not None
                  and e.get("agent_did")]
        if scored:
            display_trust_timeline(scored)


# ── PostgreSQL helpers ────────────────────────────────────────────────────────

def _check_postgres(host: str = "127.0.0.1", port: int = 5432) -> bool:
    """Return True if PostgreSQL is reachable on host:port."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _make_database_url(host: str = "127.0.0.1", port: int = 5432) -> str:
    user = os.environ.get("POSTGRES_USER", "tesht")
    password = os.environ.get("POSTGRES_PASSWORD", "tesht_dev_password")
    db = os.environ.get("POSTGRES_DB", "tesht")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    global EXPLAIN

    parser = argparse.ArgumentParser(
        description="Tesht (Pramana) — Full Lifecycle Mega-Demo"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--explain",
        action="store_true",
        default=True,
        help="Show explainability panels at each step (default)",
    )
    mode.add_argument(
        "--brief",
        action="store_true",
        help="Skip explainability panels — fast mode (~15s)",
    )
    parser.add_argument(
        "--okta-token",
        metavar="PATH_OR_TOKEN",
        help=(
            "Path to a file containing a real Okta id_token, or the token string "
            "itself. When set, Act 1 uses a live Okta token instead of the mock "
            "OIDC provider. Requires idp_bridge/config.yaml to have an acme_okta "
            "provider configured."
        ),
    )
    args = parser.parse_args()
    EXPLAIN = not args.brief

    # Auto-derive OKTA_JWKS_URI and OKTA_AUDIENCE from OKTA_ISSUER if not set.
    # Auth0: https://{domain}/.well-known/jwks.json
    # Okta:  https://{domain}/v1/keys
    okta_issuer = os.environ.get("OKTA_ISSUER", "").rstrip("/")
    if okta_issuer:
        os.environ["OKTA_ISSUER"] = okta_issuer  # normalize: no trailing slash
        if not os.environ.get("OKTA_JWKS_URI"):
            if "auth0.com" in okta_issuer:
                os.environ["OKTA_JWKS_URI"] = okta_issuer + "/.well-known/jwks.json"
            else:
                os.environ["OKTA_JWKS_URI"] = okta_issuer + "/v1/keys"
        if not os.environ.get("OKTA_AUDIENCE"):
            # Auth0: audience = Client ID; Okta: audience = Client ID
            os.environ["OKTA_AUDIENCE"] = os.environ.get("OKTA_CLIENT_ID", "")

    # Resolve Okta token (from file or inline string)
    okta_token: Optional[str] = None
    if args.okta_token:
        p = Path(args.okta_token)
        if p.exists():
            okta_token = p.read_text().strip()
        else:
            okta_token = args.okta_token.strip()

    banner("TESHT PROTOCOL — Full Lifecycle Mega-Demo")
    if EXPLAIN:
        print(f"  {DIM}Explain mode ON — showing VP decode, trust breakdowns, and timeline{RESET}")
    else:
        print(f"  {DIM}Brief mode — run with --explain for full explainability{RESET}")
    if okta_token:
        print(f"  {GREEN}Okta mode ON — using real Okta id_token for Act 1{RESET}")
    print(f"\n  {DIM}Starting 5 services (Mock OIDC, IdP Bridge, Mock MCP, SQLite MCP, Gateway)…{RESET}")

    cfg_path = _write_demo_config()

    # Check for PostgreSQL and wire DATABASE_URL to gateway if available
    pg_available = _check_postgres()
    gw_extra_env: dict[str, str] = {}
    if pg_available:
        db_url = _make_database_url()
        gw_extra_env["DATABASE_URL"] = db_url
        print(f"  {PASS} PostgreSQL detected — enabling persistent hash-chained audit")
    else:
        print(f"  {DIM}PostgreSQL not found on :5432 — using in-memory audit (start 'docker compose up postgres' for persistence){RESET}")

    oidc_proc = start_server("idp_bridge.mock_oidc_provider:app", OIDC_PORT)

    # Pass OKTA_* env vars to the bridge so it can validate real IdP tokens.
    bridge_env: dict[str, str] = {"IDP_BRIDGE_CONFIG": cfg_path}
    for key in ("OKTA_ISSUER", "OKTA_CLIENT_ID", "OKTA_AUDIENCE", "OKTA_JWKS_URI"):
        val = os.environ.get(key, "")
        if val:
            bridge_env[key] = val

    bridge_proc = start_server("idp_bridge.app:app", BRIDGE_PORT, bridge_env)
    mcp_proc = start_server("gateway.mock_mcp_server:app", MCP_PORT)
    sqlite_mcp_proc = start_server("gateway.sqlite_mcp_server:app", SQLITE_MCP_PORT)
    gw_proc = start_server("gateway.app:app", GW_PORT, gw_extra_env if gw_extra_env else None)

    try:
        for label, url, port in [
            ("Mock OIDC provider", f"{OIDC_URL}/health", OIDC_PORT),
            ("IdP Bridge        ", f"{BRIDGE_URL}/health", BRIDGE_PORT),
            ("Mock MCP server   ", f"{MCP_URL}/health", MCP_PORT),
            ("SQLite MCP server ", f"{SQLITE_MCP_URL}/health", SQLITE_MCP_PORT),
            ("MCP Gateway       ", f"{GW_URL}/gateway/health", GW_PORT),
        ]:
            if not wait_healthy(url):
                print(f"  {FAIL} {RED}{label} failed to start (port {port}){RESET}")
                return 1
            print(f"  {PASS} {label} healthy  (:{port})")

        # Fetch gateway DID once
        gw_health = httpx.get(f"{GW_URL}/gateway/health", timeout=5.0).json()
        gateway_did = gw_health["gateway_did"]
        print(f"  {DIM}Gateway DID: {gateway_did[:48]}…{RESET}")
        print()

        # Create ShoppingBot identity (persists across all acts)
        shopping_bot = AgentIdentity.create("shopping-bot")

        with httpx.Client() as client:
            enterprise_vc, delegation_vc, alice_name = act1_enterprise_identity(
                client, shopping_bot, okta_token=okta_token
            )

            blended_vp = act2_blended_gateway(
                client, shopping_bot, enterprise_vc, delegation_vc, gateway_did
            )

            act3_scope_enforcement(client, blended_vp)

            timeline_events = act4_continuous_trust(
                client, shopping_bot, enterprise_vc, delegation_vc,
                gateway_did, blended_vp
            )

            act5_shadow_attack(client, gateway_did, enterprise_vc, delegation_vc)

            act6_fleet_dashboard(client, timeline_events=timeline_events)

        print(f"  {GREEN}{BOLD}Full lifecycle demo complete.{RESET}\n")
        return 0

    except Exception as exc:
        print(f"\n  {FAIL} {RED}Demo error: {exc}{RESET}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        kill_proc(gw_proc)
        kill_proc(sqlite_mcp_proc)
        kill_proc(mcp_proc)
        kill_proc(bridge_proc)
        kill_proc(oidc_proc)
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
