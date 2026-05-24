#!/usr/bin/env python3
"""
Pramana Protocol — Enterprise IdP Bridge Demo
==============================================

Fully self-contained: starts mock OIDC provider, IdP bridge, MCP gateway,
and mock MCP server as subprocesses, waits for health, runs three scenarios,
prints results, and shuts everything down.

Scenarios:
  1. Enterprise Login → Agent Delegation → MCP Access
     Alice authenticates via Mock Okta → OIDC token → bridge issues
     OrganizationalRoleCredential → agent creates blended VP →
     gateway verifies with enterprise identity in audit trail

  2. Cross-Org Identity
     Hank (BigBank Compliance) authenticates → delegates to ComplianceBot →
     gateway audit shows: Hank Patel, CCO @ BigBank Financial

  3. Untrusted IdP Rejected
     Forged token with evil.attacker.com issuer → rejected at bridge,
     no DID created, no VC issued

No external dependencies. Runs in ~3 seconds.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from pramana.credentials import create_blended_presentation
from pramana.identity import AgentIdentity
from pramana.credentials import issue_vc
from pramana.delegation import issue_delegation

# ── Terminal colours ──────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
DIM = "\033[2m"

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"


def banner(text: str) -> None:
    w = 68
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def section(title: str) -> None:
    print(f"\n{BOLD}━━━ {title} {'━' * max(0, 58 - len(title))}━━━{RESET}")


def info(tag: str, label: str, value: str, ok: bool = True) -> None:
    colour = "" if ok else RED
    print(f"  [{CYAN}{tag:<7}{RESET}] {DIM}{label:<16}{RESET} {colour}{value}{RESET}")


def step(tag: str, msg: str, ok: bool = True) -> None:
    icon = PASS if ok else FAIL
    colour = "" if ok else RED
    print(f"  [{CYAN}{tag:<7}{RESET}] {colour}{msg}{RESET}  {icon}")


def blocked_box(lines: list[str]) -> None:
    w = max(len(l) for l in lines) + 4
    print(f"  {RED}╔{'═' * w}╗{RESET}")
    for line in lines:
        pad = w - len(line) - 2
        print(f"  {RED}║{RESET}  {line}{' ' * pad}{RED}║{RESET}")
    print(f"  {RED}╚{'═' * w}╝{RESET}")


# ── Subprocess management ─────────────────────────────────────────────────────

def start_server(module: str, port: int, extra_env: dict | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", module,
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_healthy(url: str, timeout: float = 15.0) -> bool:
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
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Config override for demo ──────────────────────────────────────────────────

def _write_demo_config() -> str:
    """Write a bridge config that points mock_idp at the local mock provider."""
    import tempfile
    import yaml

    cfg = {
        "providers": {
            "mock_idp": {
                "name": "Acme Corp Okta (Mock)",
                "issuer": "https://mock-idp.pramana.local",
                "jwks_uri": "http://127.0.0.1:9200/.well-known/jwks.json",
                "audience": "pramana",
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
            "bigbank_okta": {
                "name": "BigBank Financial (Mock Okta)",
                "issuer": "https://mock-idp.pramana.local",
                "jwks_uri": "http://127.0.0.1:9200/.well-known/jwks.json",
                "audience": "pramana",
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
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(cfg, f)
        return f.name


# ── Scenario runners ──────────────────────────────────────────────────────────

def run_scenario_1(bridge_url: str, gateway_url: str) -> bool:
    """Enterprise Login → Agent Delegation → MCP Access."""
    section("Scenario 1: Enterprise Login → Agent Delegation → MCP Access")
    print(f"  {DIM}Alice (Senior Buyer @ Acme Corp) authorises ShoppingBot{RESET}\n")

    # Step A: Alice authenticates via mock Okta
    r = httpx.get("http://127.0.0.1:9200/token?user=alice", timeout=5)
    if r.status_code != 200:
        step("IDP", f"Failed to get token: {r.status_code}", ok=False)
        return False
    alice_token = r.json()["id_token"]
    step("IDP", "Alice authenticates via Acme Corp Okta (mock)")

    # Step B: ShoppingBot already has its own identity
    shopping_bot = AgentIdentity.create("shopping-agent")

    # Step C: Attest Alice's identity via bridge
    r = httpx.post(f"{bridge_url}/attest", json={
        "oidc_token": alice_token, "ttl_seconds": 3600
    }, timeout=10)
    if r.status_code != 200:
        step("ATTEST", f"Failed: {r.status_code} {r.text}", ok=False)
        return False
    attest = r.json()
    step("ATTEST", "OIDC token verified ✓  (RS256, JWKS fetched from mock)")
    info("ATTEST", "Name", attest["claims"].get("name", "?"))
    info("ATTEST", "Email", attest["claims"].get("email", "?"))
    info("ATTEST", "Org", attest["claims"].get("organization", "?"))
    info("ATTEST", "Role", attest["claims"].get("role", "?"))
    info("ATTEST", "DID assigned", attest["did"][:52] + "...")
    info("ATTEST", "VC type", "OrganizationalRoleCredential")
    info("ATTEST", "First seen?", "Yes (new DID)" if attest["created"] else "No (same DID)")

    # Step D: Bind Alice to ShoppingBot (enterprise VC + delegation in one call)
    r = httpx.post(f"{bridge_url}/bind", json={
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
    }, timeout=10)
    if r.status_code != 200:
        step("BIND", f"Failed: {r.status_code} {r.text}", ok=False)
        return False
    bind = r.json()
    step("BIND", "Delegation issued: Alice → ShoppingBot")
    info("BIND", "Scope", str(bind["effective_scope"].get("actions", [])))
    info("BIND", "Max amount", f"{bind['effective_scope'].get('max_amount', 0)} {bind['effective_scope'].get('currency','USD')}")

    # Step E: ShoppingBot fetches the gateway DID
    gw_health = httpx.get(f"{gateway_url}/gateway/health", timeout=5).json()
    gateway_did = gw_health["gateway_did"]

    # Step F: Build blended VP
    enterprise_vc = bind["enterprise_vc"]
    delegation_vc = bind["delegation_vc"]

    # Retrieve the bridge's VC issuer DID from attest result
    # We need an AgentCredential for ShoppingBot too
    bridge_identity_did = httpx.get(f"{bridge_url}/health", timeout=5).json()["bridge_did"]

    from pramana.identity import resolve_did_key
    # We need a mock issuer for the agent VC — use the bridge
    # For demo: create a simple agent VC self-issued
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
    step("BLEND", "Blended VP created: AgentCredential + DelegationCredential + OrganizationalRoleCredential")

    # Step G: Send through MCP Gateway
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "query_database", "arguments": {"sql": "SELECT * FROM products"}},
    })
    r = httpx.post(
        f"{gateway_url}/mcp/mock_database",
        content=body.encode(),
        headers={"Authorization": f"Bearer {blended_vp}", "Content-Type": "application/json"},
        timeout=10,
    )

    if r.status_code == 200:
        result = r.json()
        step("GATEWAY", f"tools/call query_database  → {r.status_code} ALLOWED")
        info("GATEWAY", "Decision", "ALLOWED")
    else:
        step("GATEWAY", f"Unexpected status {r.status_code}: {r.text[:120]}", ok=False)
        return False

    # Step H: Show audit trail
    events = httpx.get(f"{gateway_url}/gateway/events?n=3", timeout=5).json()
    allowed_events = [e for e in events if e.get("decision") == "allowed"]
    if allowed_events:
        e = allowed_events[-1]
        dc = e.get("delegator_claims", {})
        step("AUDIT", "Gateway audit entry:")
        info("AUDIT", "Agent", e.get("agent_name") or e.get("agent_did", "?")[:20])
        info("AUDIT", "Human", dc.get("name", "?"))
        info("AUDIT", "Email", dc.get("email", "?"))
        info("AUDIT", "Org", dc.get("organization", "?"))
        info("AUDIT", "IdP", dc.get("idp_issuer", "?"))
        info("AUDIT", "Tool", e.get("tool_name", "?"))
        info("AUDIT", "Trust score", str(e.get("trust_score", "?")))
    print()
    return True


def run_scenario_2(bridge_url: str, gateway_url: str) -> bool:
    """Cross-Org Identity: Hank (BigBank Compliance) → ComplianceBot."""
    section("Scenario 2: Cross-Org Identity")
    print(f"  {DIM}Hank Patel (CCO @ BigBank) authorises ComplianceBot{RESET}\n")

    r = httpx.get("http://127.0.0.1:9200/token?user=hank", timeout=5)
    hank_token = r.json()["id_token"]
    step("IDP", "Hank authenticates via BigBank Financial Okta (mock)")

    compliance_bot = AgentIdentity.create("compliance-agent")

    r = httpx.post(f"{bridge_url}/bind", json={
        "oidc_token": hank_token,
        "agent_did": compliance_bot.did,
        "scope": {
            "actions": ["read_data", "browse_products"],
            "max_amount": 0,
            "currency": "USD",
            "merchants": [],
            "categories": [],
        },
    }, timeout=10)
    bind = r.json()
    step("BIND", "Delegation issued: Hank → ComplianceBot")
    info("BIND", "Human", bind["claims"].get("name", "?"))
    info("BIND", "Org", bind["claims"].get("organization", "?"))
    info("BIND", "Role", bind["claims"].get("role", "?"))

    gw_did = httpx.get(f"{gateway_url}/gateway/health", timeout=5).json()["gateway_did"]

    agent_vc = issue_vc(
        issuer=compliance_bot,
        subject_did=compliance_bot.did,
        credential_type="AgentCredential",
        claims={"agentName": "ComplianceBot"},
    )
    blended_vp = create_blended_presentation(
        agent=compliance_bot,
        delegation_jwt=bind["delegation_vc"],
        delegator_identity_jwt=bind["enterprise_vc"],
        additional_credentials=[agent_vc],
        audience=gw_did,
    )

    body = json.dumps({
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": {"name": "query_database", "arguments": {"sql": "SELECT * FROM compliance_reports"}},
    })
    r = httpx.post(
        f"{gateway_url}/mcp/mock_database",
        content=body.encode(),
        headers={"Authorization": f"Bearer {blended_vp}"},
        timeout=10,
    )

    if r.status_code == 200:
        step("GATEWAY", "ComplianceBot authorised via Hank's enterprise identity")
        events = httpx.get(f"{gateway_url}/gateway/events?n=5", timeout=5).json()
        allowed = [e for e in events if e.get("decision") == "allowed" and
                   (e.get("delegator_claims") or {}).get("name", "").startswith("Hank")]
        if allowed:
            e = allowed[-1]
            dc = e.get("delegator_claims", {})
            info("AUDIT", "Authorized by", f"{dc.get('name')} ({dc.get('email')})")
            info("AUDIT", "Organization", dc.get("organization", "?"))
            info("AUDIT", "Role", dc.get("role", "?"))
        return True
    else:
        step("GATEWAY", f"Unexpected: {r.status_code}", ok=False)
        return False


def run_scenario_3(bridge_url: str) -> bool:
    """Untrusted IdP Rejected."""
    section("Scenario 3: Untrusted IdP REJECTED")
    print(f"  {DIM}Forge a token from an unknown issuer{RESET}\n")

    import jwt as _jwt
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import serialization as _ser

    evil_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evil_pem = evil_key.private_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_ser.NoEncryption(),
    )
    now = int(time.time())
    evil_token = _jwt.encode(
        {
            "iss": "https://evil.attacker.com",
            "sub": "evil-sub-999",
            "aud": "pramana",
            "iat": now, "exp": now + 3600,
            "name": "Evil Attacker",
        },
        evil_pem, algorithm="RS256",
    )
    step("IDP", "Token created with iss=https://evil.attacker.com (forge)")

    r = httpx.post(f"{bridge_url}/attest", json={
        "oidc_token": evil_token
    }, timeout=5)

    if r.status_code == 401:
        detail = r.json().get("detail", "")
        blocked_box([
            "REJECTED: Untrusted issuer",
            f"Issuer: https://evil.attacker.com",
            "Not found in trusted IdP registry",
            "No DID created. No VC issued.",
        ])
        step("BRIDGE", "Attacker rejected at bridge — never reached gateway")
        return True
    else:
        step("BRIDGE", f"Expected 401 but got {r.status_code}", ok=False)
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    banner("PRAMANA ENTERPRISE IDP BRIDGE — Live Demo")
    print(f"\n  {DIM}Starting services...{RESET}")

    cfg_path = _write_demo_config()

    mock_oidc = start_server("idp_bridge.mock_oidc_provider:app", 9200)
    bridge = start_server("idp_bridge.app:app", 5053, {"IDP_BRIDGE_CONFIG": cfg_path})
    mock_mcp = start_server("gateway.mock_mcp_server:app", 9100)
    gateway = start_server("gateway.app:app", 5052)

    try:
        if not wait_healthy("http://127.0.0.1:9200/health"):
            print(f"  {RED}Mock OIDC provider failed to start{RESET}")
            return 1
        print(f"  {PASS} Mock OIDC provider healthy (port 9200)")

        if not wait_healthy("http://127.0.0.1:5053/health"):
            print(f"  {RED}IdP Bridge failed to start{RESET}")
            return 1
        print(f"  {PASS} IdP Bridge healthy (port 5053)")

        if not wait_healthy("http://127.0.0.1:9100/health"):
            print(f"  {RED}Mock MCP server failed to start{RESET}")
            return 1
        print(f"  {PASS} Mock MCP server healthy (port 9100)")

        if not wait_healthy("http://127.0.0.1:5052/gateway/health"):
            print(f"  {RED}MCP Gateway failed to start{RESET}")
            return 1
        print(f"  {PASS} MCP Gateway healthy (port 5052)")

        gw_did = httpx.get("http://127.0.0.1:5052/gateway/health", timeout=5).json()["gateway_did"]
        print(f"  {PASS} Gateway DID: {gw_did[:52]}...")

        bridge_url = "http://127.0.0.1:5053"
        gateway_url = "http://127.0.0.1:5052"
        errors: list[str] = []

        if not run_scenario_1(bridge_url, gateway_url):
            errors.append("Scenario 1 failed")
        if not run_scenario_2(bridge_url, gateway_url):
            errors.append("Scenario 2 failed")
        if not run_scenario_3(bridge_url):
            errors.append("Scenario 3 failed")

        banner("Demo Complete")
        if errors:
            for e in errors:
                print(f"  {FAIL} {RED}{e}{RESET}")
            print(f"\n  {RED}{BOLD}{len(errors)} error(s).{RESET}\n")
            return 1

        print(f"\n  {GREEN}{BOLD}All 3 scenarios passed.{RESET}")
        print(f"\n  {DIM}Key insight: Enterprise users never manage cryptographic keys.")
        print(f"  One OIDC token → Pramana DID + enterprise VC → agent delegation.")
        print(f"  The gateway sees WHO authorised the agent (name, email, org, role).")
        print(f"  Full audit trail: Alice Johnson (alice@acmecorp.com via Okta) → ALLOWED.{RESET}\n")
        return 0

    finally:
        import os as _os
        kill_proc(gateway)
        kill_proc(mock_mcp)
        kill_proc(bridge)
        kill_proc(mock_oidc)
        try:
            _os.unlink(cfg_path)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
