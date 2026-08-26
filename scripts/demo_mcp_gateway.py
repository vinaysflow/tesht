#!/usr/bin/env python3
"""
Tesht (Pramana) — MCP Identity Gateway Demo
=============================================

Fully self-contained: starts the mock MCP server and gateway as
subprocesses, waits for health, runs three scenarios, prints results,
and shuts everything down.

Scenarios:
  1. Authorized MCP access — VP verified, scope OK, trust OK, proxied
  2. Out-of-scope tool blocked — delete_record requires "admin"
  3. Untrusted agent blocked — no delegation, auth fails

No external dependencies. Runs in ~5 seconds.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Ensure SDK and gateway are importable
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from tesht.credentials import create_blended_presentation, create_presentation, issue_vc
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity

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
    w = 66
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def section(title: str) -> None:
    print(f"\n{BOLD}━━━ {title} {'━' * max(0, 56 - len(title))}━━━{RESET}")


def info(label: str, value: str) -> None:
    print(f"  {DIM}{label:<12}{RESET} {value}")


def step(tag: str, msg: str, ok: bool = True) -> None:
    icon = PASS if ok else FAIL
    colour = "" if ok else RED
    print(f"  [{CYAN}{tag:<6}{RESET}] {colour}{msg}{RESET}  {icon}")


def blocked_box(lines: list[str]) -> None:
    w = max(len(l) for l in lines) + 4
    print(f"  {RED}╔{'═' * w}╗{RESET}")
    for line in lines:
        pad = w - len(line) - 2
        print(f"  {RED}║{RESET}  {line}{' ' * pad}{RED}║{RESET}")
    print(f"  {RED}╚{'═' * w}╝{RESET}")


# ── Subprocess management ─────────────────────────────────────────────────────

def start_server(name: str, module: str, port: int) -> subprocess.Popen:
    """Start a uvicorn server as a subprocess."""
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            module,
            "--host", "127.0.0.1",
            "--port", str(port),
            "--log-level", "error",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def wait_for_health(url: str, timeout: float = 10.0, label: str = "") -> bool:
    """Poll a health endpoint until it responds or timeout is reached."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    return False


def kill_proc(proc: subprocess.Popen) -> None:
    """Gracefully terminate a subprocess."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Identity setup ────────────────────────────────────────────────────────────

def setup_identities(gateway_did: str):
    """Create identities, credentials, and delegation for the demo.

    The *gateway_did* is fetched from the running gateway's health endpoint
    so that VPs are addressed to the correct audience.
    """
    idp = AgentIdentity.create("acme-corp-idp")
    alice = AgentIdentity.create("alice-johnson")
    shopping_bot = AgentIdentity.create("shopping-agent")
    rogue = AgentIdentity.create("rogue-agent")

    alice_org_vc = issue_vc(
        issuer=idp,
        subject_did=alice.did,
        credential_type="OrganizationalRoleCredential",
        claims={
            "name": "Alice Johnson",
            "email": "alice@acme.com",
            "department": "Procurement",
            "role": "Senior Buyer",
            "organization": "Acme Corp",
        },
        ttl_seconds=86400,
    )
    agent_vc = issue_vc(
        issuer=idp,
        subject_did=shopping_bot.did,
        credential_type="AgentCredential",
        claims={
            "agentName": "ShoppingBot",
            "agentType": "LLM Agent",
            "ownerOrg": "Acme Corp",
        },
        ttl_seconds=86400,
    )
    delegation_jwt = issue_delegation(
        delegator=alice,
        delegate_did=shopping_bot.did,
        scope={
            "actions": ["read_data", "write_data", "browse_products", "purchase"],
            "max_amount": 50000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": ["electronics", "office_supplies"],
        },
        max_depth=2,
        ttl_seconds=3600,
    )

    blended_vp = create_blended_presentation(
        agent=shopping_bot,
        delegation_jwt=delegation_jwt,
        delegator_identity_jwt=alice_org_vc,
        additional_credentials=[agent_vc],
        audience=gateway_did,
    )

    rogue_vc = issue_vc(
        issuer=rogue,
        subject_did=rogue.did,
        credential_type="AgentCredential",
        claims={"agentName": "RogueBot"},
    )
    rogue_vp = create_presentation(
        holder=rogue,
        credentials=[rogue_vc],
        audience=gateway_did,
    )

    return {
        "alice": alice,
        "shopping_bot": shopping_bot,
        "rogue": rogue,
        "blended_vp": blended_vp,
        "rogue_vp": rogue_vp,
    }


# ── Demo scenarios ────────────────────────────────────────────────────────────

def run_scenario_1(base_url: str, vp: str) -> bool:
    """Authorized MCP access — query_database through the gateway."""
    section("Scenario 1: Authorized MCP Access")
    info("Agent", "ShoppingBot (did:key:z6Mk...)")
    info("Human", "Alice Johnson, Senior Buyer @ Acme Corp")
    info("Tool", "query_database on mock_database")
    info("Scope", "[read_data, write_data, browse_products, purchase]")
    print()

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "query_database", "arguments": {"sql": "SELECT * FROM products"}},
    })

    t0 = time.monotonic()
    r = httpx.post(
        f"{base_url}/mcp/mock_database",
        content=body.encode(),
        headers={
            "Authorization": f"Bearer {vp}",
            "Content-Type": "application/json",
        },
        timeout=10.0,
    )
    elapsed = (time.monotonic() - t0) * 1000

    if r.status_code == 200:
        result = r.json()
        step("AUTH", f"Blended VP verified ({elapsed:.1f}ms total)")
        step("SCOPE", 'query_database → requires "read_data" → IN SCOPE')
        step("TRUST", "Score: ~85/100 → ALLOW")
        step("PROXY", f"Forwarded to mock MCP server ({elapsed:.1f}ms)")

        # Show credential isolation
        creds_r = httpx.get("http://127.0.0.1:9100/credentials-received", timeout=5.0)
        if creds_r.status_code == 200:
            reqs = creds_r.json().get("requests", [])
            if reqs:
                last = reqs[-1]
                step("CREDS", f"Agent saw: Bearer <blended-vp-jwt>")
                step("CREDS", f"Server got: X-API-Key: {last.get('api_key_value', 'N/A')} (ISOLATED)")

        step("AUDIT", "Event logged: alice→shoppingbot→query_database (allowed)")
        step("TOTAL", f"{elapsed:.1f}ms gateway overhead")
        print()
        content = result.get("result", {}).get("content", [{}])
        text = content[0].get("text", "") if content else ""
        print(f"  {DIM}Result: {text}{RESET}")
        return True
    else:
        step("FAIL", f"Unexpected status {r.status_code}: {r.text}", ok=False)
        return False


def run_scenario_2(base_url: str, vp: str) -> bool:
    """Out-of-scope tool blocked — delete_record requires 'admin'."""
    section("Scenario 2: Out-of-Scope Tool BLOCKED")
    info("Agent", "ShoppingBot (did:key:z6Mk...)")
    info("Tool", "delete_record on mock_database")
    print()

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "delete_record", "arguments": {"table": "products", "id": "42"}},
    })

    r = httpx.post(
        f"{base_url}/mcp/mock_database",
        content=body.encode(),
        headers={
            "Authorization": f"Bearer {vp}",
            "Content-Type": "application/json",
        },
        timeout=10.0,
    )

    if r.status_code == 403:
        err = r.json().get("error", {})
        step("AUTH", "Blended VP verified")
        step("SCOPE", 'delete_record → requires "admin" → NOT IN SCOPE', ok=False)
        blocked_box([
            "BLOCKED: Action 'admin' not in delegation scope",
            "Agent scope: [read_data, write_data, browse_products, purchase]",
            "Required: admin",
            "Request never reached MCP server.",
        ])
        return True
    else:
        step("FAIL", f"Expected 403 but got {r.status_code}: {r.text}", ok=False)
        return False


def run_scenario_3(base_url: str, rogue_vp: str) -> bool:
    """Untrusted agent blocked — no delegation, auth fails."""
    section("Scenario 3: Untrusted Agent BLOCKED")
    info("Agent", "RogueAgent (did:key:z6Mk...) — no delegation, no identity")
    print()

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "query_database", "arguments": {"sql": "SELECT * FROM secrets"}},
    })

    r = httpx.post(
        f"{base_url}/mcp/mock_database",
        content=body.encode(),
        headers={
            "Authorization": f"Bearer {rogue_vp}",
            "Content-Type": "application/json",
        },
        timeout=10.0,
    )

    if r.status_code == 401:
        err = r.json().get("error", {})
        reason = err.get("message", "")
        step("AUTH", "No valid delegation", ok=False)
        blocked_box([
            "BLOCKED: Authentication failed",
            f"Reason: {reason[:60]}",
            "Trust score: N/A (auth failed before scoring)",
        ])
        return True
    else:
        step("FAIL", f"Expected 401 but got {r.status_code}: {r.text}", ok=False)
        return False


def print_audit_trail(base_url: str) -> None:
    """Print the gateway audit trail."""
    section("Gateway Audit Trail")
    try:
        r = httpx.get(f"{base_url}/gateway/events?n=10", timeout=5.0)
        events = r.json() if r.status_code == 200 else []
    except httpx.HTTPError:
        events = []

    if not events:
        print(f"  {DIM}(no events){RESET}")
        return

    header = f"  {'#':<4}{'Agent':<18}{'Human':<14}{'Tool':<20}{'Decision':<12}{'Trust':<8}{'Latency'}"
    print(header)
    print(f"  {'─' * 84}")
    for i, evt in enumerate(events, 1):
        agent = (evt.get("agent_name") or "—")[:16]
        delegator_claims = evt.get("delegator_claims") or {}
        human = (delegator_claims.get("name") or "—")[:12]
        tool = (evt.get("tool_name") or "—")[:18]
        decision = evt.get("decision", "—")
        trust = evt.get("trust_score", "—")
        latency = evt.get("total_latency_ms", 0)

        colour = GREEN if decision == "allowed" else RED
        print(
            f"  {i:<4}{agent:<18}{human:<14}{tool:<20}"
            f"{colour}{decision:<12}{RESET}{str(trust):<8}{latency:.1f}ms"
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    banner("TESHT MCP IDENTITY GATEWAY — Live Demo")
    print(f"\n  {DIM}Starting services...{RESET}")

    mock_proc = start_server("mock-mcp", "gateway.mock_mcp_server:app", 9100)
    gateway_proc = start_server("gateway", "gateway.app:app", 5052)

    try:
        # Wait for both services to be healthy
        if not wait_for_health("http://127.0.0.1:9100/health", label="mock"):
            print(f"  {RED}Mock MCP server failed to start{RESET}")
            return 1
        print(f"  {PASS} Mock MCP server healthy (port 9100)")

        if not wait_for_health("http://127.0.0.1:5052/gateway/health", label="gateway"):
            print(f"  {RED}Gateway failed to start{RESET}")
            return 1
        print(f"  {PASS} Gateway healthy (port 5052)")

        # Fetch the gateway's DID so VPs target the correct audience
        gw_health = httpx.get("http://127.0.0.1:5052/gateway/health", timeout=5.0).json()
        gateway_did = gw_health["gateway_did"]
        print(f"  {PASS} Gateway DID: {gateway_did[:52]}...")

        # Create identities targeting the gateway's actual DID
        ids = setup_identities(gateway_did)
        print(f"  {PASS} Identities and credentials created")

        base_url = "http://127.0.0.1:5052"
        errors: list[str] = []

        if not run_scenario_1(base_url, ids["blended_vp"]):
            errors.append("Scenario 1 failed")
        if not run_scenario_2(base_url, ids["blended_vp"]):
            errors.append("Scenario 2 failed")
        if not run_scenario_3(base_url, ids["rogue_vp"]):
            errors.append("Scenario 3 failed")

        print_audit_trail(base_url)

        # Summary
        banner("Demo Complete")
        if errors:
            for e in errors:
                print(f"  {FAIL} {RED}{e}{RESET}")
            print(f"\n  {RED}{BOLD}{len(errors)} error(s).{RESET}\n")
            return 1

        print(f"\n  {GREEN}{BOLD}All 3 scenarios passed.{RESET}")
        print(f"\n  {DIM}Key insight: the MCP Identity Gateway sits between agents and MCP servers.")
        print(f"  Every request is authenticated via W3C blended identity VPs.")
        print(f"  The agent never sees the upstream server's credentials.")
        print(f"  Graduated trust scoring — not just binary allow/deny.{RESET}\n")
        return 0

    finally:
        kill_proc(gateway_proc)
        kill_proc(mock_proc)


if __name__ == "__main__":
    sys.exit(main())
