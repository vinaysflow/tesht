#!/usr/bin/env python3
"""
Tesht (Pramana) — Multi-Hop Delegation Chain Demo
====================================================

Shows 2-hop delegation (Alice → Agent A → Agent B) through the MCP Gateway
where Agent B's out-of-scope request is caught, trust degrades, and the full
delegation chain is visible in the audit trail.

Narrative:
  1. Alice (compliance officer) authenticates via mock OIDC, binds to
     DataAnalyst (Agent A) with scope: read_data + write_data
  2. Agent A sub-delegates to KYBReviewer (Agent B) with narrowed scope:
     read_data only
  3. Agent B makes an in-scope request (query_database) → ALLOWED, trust ~75
  4. Agent B attempts out-of-scope insert_record → BLOCKED, trust drops
  5. Agent B tries again → further penalty / step-up
  6. Agent B re-presents a fresh VP → trust partially recovers
  7. Audit query shows the full Alice → Agent A → Agent B chain

Run:
    PYTHONPATH=".:sdk/python" python3 scripts/demo_delegation_chain.py
"""
from __future__ import annotations

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

from tesht.credentials import create_blended_presentation, issue_vc
from tesht.delegation import delegate_further, issue_delegation
from tesht.identity import AgentIdentity

# ── Ports ─────────────────────────────────────────────────────────────────────
OIDC_PORT = 9200
BRIDGE_PORT = 5053
SQLITE_MCP_PORT = 9102
GW_PORT = 5052

OIDC_URL = f"http://127.0.0.1:{OIDC_PORT}"
BRIDGE_URL = f"http://127.0.0.1:{BRIDGE_PORT}"
SQLITE_MCP_URL = f"http://127.0.0.1:{SQLITE_MCP_PORT}"
GW_URL = f"http://127.0.0.1:{GW_PORT}"

# ── Terminal colours ───────────────────────────────────────────────────────────
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


# ── Output helpers ─────────────────────────────────────────────────────────────

def banner(text: str) -> None:
    w = 70
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def section(num: str, title: str) -> None:
    line = f"Step {num}: {title}"
    pad = max(0, 64 - len(line))
    print(f"\n{BOLD}{CYAN}━━━ {line} {'━' * pad}━━━{RESET}")


def step(tag: str, msg: str, ok: bool = True) -> None:
    icon = PASS if ok else FAIL
    color = "" if ok else RED
    print(f"  [{CYAN}{tag:<7}{RESET}] {color}{msg}{RESET}  {icon}")


def info(tag: str, label: str, value: str) -> None:
    print(f"  [{CYAN}{tag:<7}{RESET}] {DIM}{label:<18}{RESET} {value}")


def chain_box(alice_did: str, agent_a_did: str, agent_b_did: str,
              alice_name: str, scope_a: dict, scope_b: dict) -> None:
    """Display the delegation chain as an ASCII tree."""
    acts_a = scope_a.get("actions", [])
    max_a = scope_a.get("max_amount", 0)
    acts_b = scope_b.get("actions", [])
    max_b = scope_b.get("max_amount", 0)
    w = 68
    print(f"\n  {BLUE}╔{'═' * w}╗{RESET}")
    print(f"  {BLUE}║{RESET}  {BOLD}DELEGATION CHAIN{RESET}{' ' * (w - 17)}{BLUE}║{RESET}")
    print(f"  {BLUE}║{RESET}  {'─' * (w - 2)}{BLUE}║{RESET}")
    alice_line = f"  {alice_name} (Compliance Officer @ Acme Corp)"
    print(f"  {BLUE}║{RESET}{BOLD}{GREEN}{alice_line:<{w}}{RESET}{BLUE}║{RESET}")
    print(f"  {BLUE}║{RESET}  {alice_did[:50]}...{' ' * (w - 55)}{BLUE}║{RESET}")
    sep_a = f"    → DataAnalyst  scope: {acts_a}  max: ${max_a:,}"
    print(f"  {BLUE}║{RESET}{CYAN}{sep_a:<{w}}{RESET}{BLUE}║{RESET}")
    print(f"  {BLUE}║{RESET}    {agent_a_did[:50]}...{' ' * (w - 56)}{BLUE}║{RESET}")
    sep_b = f"      → KYBReviewer  scope: {acts_b}  max: ${max_b:,}  {YELLOW}(NARROWED){RESET}"
    sep_b_plain = f"      → KYBReviewer  scope: {acts_b}  max: ${max_b:,}  (NARROWED)"
    print(f"  {BLUE}║{RESET}{CYAN}{sep_b_plain:<{w}}{RESET}{BLUE}║{RESET}")
    print(f"  {BLUE}║{RESET}      {agent_b_did[:48]}...{' ' * (w - 56)}{BLUE}║{RESET}")
    print(f"  {BLUE}║{RESET}  {'─' * (w - 2)}{BLUE}║{RESET}")
    eff_line = f"  Effective scope for KYBReviewer: {acts_b}, ${max_b:,} max"
    print(f"  {BLUE}║{RESET}  {BOLD}{eff_line:<{w - 2}}{RESET}{BLUE}║{RESET}")
    print(f"  {BLUE}╚{'═' * w}╝{RESET}")


def trust_bar(score: int) -> str:
    filled = int(score / 5)
    empty = 20 - filled
    color = GREEN if score >= 70 else (YELLOW if score >= 50 else RED)
    return f"{color}{'█' * filled}{'░' * empty}{RESET} {score:3d}/100"


def decision_label(status_code: int, body: dict) -> tuple[str, bool]:
    if status_code == 200:
        return f"{GREEN}ALLOWED{RESET}", True
    if status_code == 403:
        err_msg = body.get("error", {}).get("message", "")
        if "Scope denied" in err_msg:
            return f"{RED}BLOCKED (scope){RESET}", False
        return f"{RED}BLOCKED (trust){RESET}", False
    if status_code == 401:
        err_msg = body.get("error", {}).get("message", "")
        if "Step-up" in err_msg:
            return f"{YELLOW}STEP-UP required{RESET}", False
        return f"{RED}AUTH FAILED{RESET}", False
    return f"{RED}ERROR {status_code}{RESET}", False


# ── Service management ────────────────────────────────────────────────────────

def _write_demo_config() -> str:
    cfg = {
        "providers": {
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
            }
        }
    }
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump(cfg, f)
    f.close()
    return f.name


def start_server(module: str, port: int, extra_env: Optional[dict] = None) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", module,
         "--host", "127.0.0.1", "--port", str(port),
         "--log-level", "error"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_healthy(url: str, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    return False


def kill_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── MCP helpers ───────────────────────────────────────────────────────────────

def mcp_call(
    client: httpx.Client,
    vp: str,
    tool: str,
    arguments: Optional[dict] = None,
    req_id: int = 1,
) -> tuple[int, dict]:
    body = json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    })
    r = client.post(
        f"{GW_URL}/mcp/sqlite_database",
        content=body.encode(),
        headers={"Authorization": f"Bearer {vp}", "Content-Type": "application/json"},
        timeout=10.0,
    )
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {}


def build_vp(agent: AgentIdentity, agent_vc: str, delegation_jwt: str,
             enterprise_vc: str, gateway_did: str, ttl: int = 300) -> str:
    return create_blended_presentation(
        agent=agent,
        delegation_jwt=delegation_jwt,
        delegator_identity_jwt=enterprise_vc,
        additional_credentials=[agent_vc],
        audience=gateway_did,
        ttl_seconds=ttl,
    )


# ── Steps ─────────────────────────────────────────────────────────────────────

def step1_identity_setup(client: httpx.Client, agent_a: AgentIdentity) -> tuple[str, str, dict, str]:
    """Alice authenticates and binds to Agent A (DataAnalyst) with max_depth=2."""
    section("1", "Identity Setup — Alice binds to DataAnalyst (max_depth=2)")
    print(f"  {DIM}Alice Johnson, Compliance Officer @ Acme Corp authenticates via mock Okta{RESET}\n")

    r = client.get(f"{OIDC_URL}/token?user=alice", timeout=5.0)
    r.raise_for_status()
    alice_token = r.json()["id_token"]
    step("IDP", "Alice authenticates via Acme Corp Okta (mock RS256)")

    # Request max_depth=2 so Agent A can sub-delegate to Agent B
    r = client.post(f"{BRIDGE_URL}/bind", json={
        "oidc_token": alice_token,
        "agent_did": agent_a.did,
        "scope": {
            "actions": ["read_data", "write_data"],
            "max_amount": 50000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
        },
        "ttl_seconds": 3600,
        "max_depth": 2,
    }, timeout=10.0)
    r.raise_for_status()
    bind = r.json()

    claims = bind["claims"]
    alice_did = bind["did"]
    enterprise_vc = bind["enterprise_vc"]
    delegation_vc_a = bind["delegation_vc"]

    step("VC", "OrganizationalRoleCredential issued by IdP bridge")
    info("VC", "Name", claims.get("name", "?"))
    info("VC", "Email", claims.get("email", "?"))
    info("VC", "Org", claims.get("organization", "?"))
    info("VC", "Alice DID", alice_did[:52] + "...")
    step("DEL", f"Delegation issued: Alice → DataAnalyst (max_depth=2)")
    info("DEL", "Scope (actions)", str(bind["effective_scope"].get("actions", [])))
    info("DEL", "Max amount", f"${bind['effective_scope'].get('max_amount', 0):,} USD")

    return enterprise_vc, delegation_vc_a, claims, alice_did


def step2_sub_delegation(
    agent_a: AgentIdentity,
    agent_b: AgentIdentity,
    delegation_vc_a: str,
    gateway_did: str,
) -> tuple[str, str]:
    """Agent A narrows scope and sub-delegates to Agent B (KYBReviewer)."""
    section("2", "Sub-Delegation — DataAnalyst narrows scope for KYBReviewer")
    print(f"  {DIM}Agent A delegates to Agent B with read_data only (no write_data){RESET}\n")

    narrowed_scope = {
        "actions": ["read_data"],
        "max_amount": 10000,
        "currency": "USD",
        "merchants": ["*"],
        "categories": [],
    }

    delegation_vc_b = delegate_further(
        holder=agent_a,
        parent_delegation_jwt=delegation_vc_a,
        sub_delegate_did=agent_b.did,
        narrowed_scope=narrowed_scope,
        ttl_seconds=3600,
    )

    step("DEL", f"Sub-delegation: DataAnalyst → KYBReviewer")
    info("DEL", "Scope (actions)", str(narrowed_scope.get("actions", [])))
    info("DEL", "Max amount", f"${narrowed_scope.get('max_amount', 0):,} USD")
    info("DEL", "write_data", f"{RED}REMOVED — narrowed from parent{RESET}")

    return delegation_vc_b, narrowed_scope.get("actions", [])


def step3_normal_operation(
    client: httpx.Client,
    agent_b: AgentIdentity,
    agent_b_vc: str,
    delegation_vc_b: str,
    enterprise_vc: str,
    gateway_did: str,
) -> tuple[str, int]:
    """Agent B calls query_database (in scope) — should be ALLOWED."""
    section("3", "Normal Operation — Agent B reads data (in scope)")
    print(f"  {DIM}KYBReviewer calls query_database (requires read_data — in scope){RESET}\n")

    vp = build_vp(agent_b, agent_b_vc, delegation_vc_b, enterprise_vc, gateway_did)

    status, body = mcp_call(
        client, vp, "query_database",
        arguments={"sql": "SELECT id, name FROM products LIMIT 3"},
        req_id=10,
    )
    label, ok = decision_label(status, body)
    step("GW", f"query_database (read_data) → {label}", ok)

    if ok and "result" in body:
        try:
            content = body["result"].get("content", [])
            if content and isinstance(content, list):
                rows = json.loads(content[0].get("text", "[]"))
                info("GW", "Rows returned", str(len(rows)))
        except Exception:
            pass

    # Get trust score from next events
    time.sleep(0.3)
    events = _get_agent_events(client, agent_b.did, 3)
    last_trust = _last_trust(events)
    if last_trust is not None:
        print(f"\n  {CYAN}Trust score after in-scope call:{RESET}")
        print(f"  {trust_bar(last_trust)}")
        info("TRUST", "Delegation depth", "2 (Alice → Agent A → Agent B)")
        info("TRUST", "Depth penalty", "applied (-5 per level)")

    return vp, last_trust or 75


def step4_scope_violation(
    client: httpx.Client,
    agent_b: AgentIdentity,
    agent_b_vc: str,
    delegation_vc_b: str,
    enterprise_vc: str,
    gateway_did: str,
    vp: str,
) -> int:
    """Agent B tries insert_record (requires write_data — NOT in Agent B's scope)."""
    section("4", "Scope Violation — Agent B attempts write_data (out of scope!)")
    print(f"  {DIM}KYBReviewer tries insert_record (requires write_data — BLOCKED){RESET}\n")
    print(f"  {YELLOW}Alice authorized write_data for DataAnalyst, but DataAnalyst{RESET}")
    print(f"  {YELLOW}did NOT delegate write_data to KYBReviewer.{RESET}\n")

    # First violation
    status, body = mcp_call(
        client, vp, "insert_record",
        arguments={"table": "products", "data": {"name": "Unauthorized Entry"}},
        req_id=20,
    )
    label, ok = decision_label(status, body)
    step("GW", f"insert_record (write_data) → {label}", ok)
    err_msg = body.get("error", {}).get("message", "")
    if err_msg:
        info("GW", "Reason", err_msg[:65])

    time.sleep(0.3)

    # Second violation — trust should drop further
    status2, body2 = mcp_call(
        client, vp, "insert_record",
        arguments={"table": "orders", "data": {"amount": 9999}},
        req_id=21,
    )
    label2, ok2 = decision_label(status2, body2)
    step("GW", f"insert_record again → {label2} (penalty accumulates)", ok2)

    time.sleep(0.3)
    events = _get_agent_events(client, agent_b.did, 6)
    last_trust = _last_trust(events)

    if last_trust is not None:
        print(f"\n  {CYAN}Trust score after scope violations:{RESET}")
        print(f"  {trust_bar(last_trust)}")
        info("TRUST", "Scope violation penalty", "+15 per violation")

    # Third attempt — query_database (in scope) but trust may have dropped
    status3, body3 = mcp_call(
        client, vp, "query_database",
        arguments={"sql": "SELECT COUNT(*) FROM orders"},
        req_id=22,
    )
    label3, ok3 = decision_label(status3, body3)
    step("GW", f"query_database after violations → {label3}", ok3)
    if not ok3:
        info("GW", "Reason", body3.get("error", {}).get("message", "")[:65])

    return last_trust or 40


def step5_recovery(
    client: httpx.Client,
    agent_b: AgentIdentity,
    agent_b_vc: str,
    delegation_vc_b: str,
    enterprise_vc: str,
    gateway_did: str,
) -> None:
    """Agent B re-presents a fresh VP — penalty window resets."""
    section("5", "Recovery — Agent B re-presents fresh VP")
    print(f"  {DIM}Fresh VP (new JWT hash) resets penalty accumulation window{RESET}\n")

    fresh_vp = build_vp(agent_b, agent_b_vc, delegation_vc_b, enterprise_vc, gateway_did)
    step("VP", "Fresh blended VP issued (new VP hash)")

    status, body = mcp_call(
        client, fresh_vp, "query_database",
        arguments={"sql": "SELECT name FROM products LIMIT 2"},
        req_id=30,
    )
    label, ok = decision_label(status, body)
    step("GW", f"query_database with fresh VP → {label}", ok)

    time.sleep(0.3)
    events = _get_agent_events(client, agent_b.did, 8)
    last_trust = _last_trust(events)
    if last_trust is not None:
        print(f"\n  {CYAN}Trust score after fresh VP:{RESET}")
        print(f"  {trust_bar(last_trust)}")
        info("TRUST", "Recovery", "penalty window reset, base score restored")


def step6_audit_visibility(
    client: httpx.Client,
    agent_b: AgentIdentity,
    alice_did: str,
    agent_a: AgentIdentity,
    alice_claims: dict,
    scope_a: dict,
    scope_b_actions: list,
) -> None:
    """Query and display the full audit trail with delegation chain visible."""
    section("6", "Audit Visibility — Full delegation chain in every event")
    print(f"  {DIM}Querying /gateway/events for KYBReviewer (Agent B){RESET}\n")

    r = client.get(
        f"{GW_URL}/gateway/events",
        params={"agent_did": agent_b.did, "n": 20},
        timeout=10.0,
    )
    r.raise_for_status()
    raw = r.json()
    events = raw if isinstance(raw, list) else raw.get("events", [])

    if not events:
        print(f"  {WARN} No events found for Agent B")
        return

    # Display table header
    print(f"  {BOLD}{'#':<3} {'Tool':<18} {'Decision':<22} {'Trust':>5} {'Depth':>5} {'Chain visibility'}{RESET}")
    print(f"  {'─' * 72}")

    for i, ev in enumerate(events[:10], 1):
        tool = ev.get("tool_name") or ev.get("method", "—")[:17]
        decision = ev.get("decision", "—")
        trust = ev.get("trust_score", 0)
        depth = ev.get("delegation_depth")
        chain_dids = ev.get("delegation_chain_dids")

        d_color = GREEN if decision == "allowed" else (YELLOW if "step" in decision else RED)
        trust_color = GREEN if trust >= 70 else (YELLOW if trust >= 50 else RED)
        depth_str = str(depth) if depth is not None else "—"
        chain_str = f"{len(chain_dids)}-hop chain" if chain_dids else "—"

        print(f"  {i:<3} {tool:<18} {d_color}{decision:<22}{RESET} "
              f"{trust_color}{trust:>5}{RESET} {depth_str:>5}  {DIM}{chain_str}{RESET}")

    print(f"  {'─' * 72}")

    # Show chain DIDs from the most recent event with chain data
    chain_event = next(
        (e for e in events if e.get("delegation_chain_dids")), None
    )
    if chain_event:
        chain_dids = chain_event["delegation_chain_dids"]
        depth = chain_event.get("delegation_depth", len(chain_dids) - 1)
        eff_scope = chain_event.get("effective_scope") or {}
        print(f"\n  {BOLD}{CYAN}Delegation chain captured in audit:{RESET}")
        for idx, did in enumerate(chain_dids):
            label_name = (
                alice_claims.get("name", "Alice") if did == alice_did
                else ("DataAnalyst" if did == agent_a.did else "KYBReviewer")
            )
            arrow = "  " + ("  " * idx) + ("└→ " if idx > 0 else "   ")
            print(f"  {CYAN}{arrow}{RESET}{BOLD}{label_name}{RESET}  {DIM}{did[:50]}...{RESET}")

        if eff_scope:
            info("SCOPE", "Effective scope", str(eff_scope.get("actions", [])))
            info("SCOPE", "Max amount", f"${eff_scope.get('max_amount', 0):,} USD")
    else:
        print(f"\n  {YELLOW}Note: delegation chain fields populated for authenticated events.{RESET}")
        print(f"  {DIM}(blocked_auth events don't have chain data){RESET}")

    # Verify hash chain
    print(f"\n  {DIM}Verifying SHA-256 audit hash chain...{RESET}")
    time.sleep(1.0)
    try:
        r = client.get(f"{GW_URL}/gateway/audit/verify", timeout=10.0)
        verify = r.json()
        # Support both in-memory ("valid") and PostgreSQL ("verified") response shapes
        verified = verify.get("verified", verify.get("valid", False))
        storage = verify.get("storage", "postgresql")
        n_events = (
            verify.get("events_verified")
            or verify.get("in_memory_count")
            or verify.get("events_checked")
            or 0
        )
        if storage == "in-memory":
            step(
                "AUDIT",
                f"In-memory audit: {n_events} events captured (no PostgreSQL)",
                True,
            )
            info("AUDIT", "Note", "Run with DATABASE_URL for hash-chain verification")
        else:
            step(
                "AUDIT",
                f"Hash chain integrity: {'VERIFIED' if verified else 'BROKEN'} "
                f"({n_events} events)",
                verified,
            )
            if not verified:
                info("AUDIT", "Details", str(verify.get("reason", "unknown")))
    except Exception as exc:
        step("AUDIT", f"Hash chain verification error: {exc}", False)


# ── Event helpers ──────────────────────────────────────────────────────────────

def _get_agent_events(client: httpx.Client, agent_did: str, n: int = 20) -> list[dict]:
    try:
        r = client.get(
            f"{GW_URL}/gateway/events",
            params={"agent_did": agent_did, "n": n},
            timeout=5.0,
        )
        raw = r.json()
        return raw if isinstance(raw, list) else raw.get("events", [])
    except Exception:
        return []


def _last_trust(events: list[dict]) -> Optional[int]:
    """Return the trust score of the most recent event."""
    for ev in reversed(events):
        ts = ev.get("trust_score")
        if ts is not None:
            return int(ts)
    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Tesht Multi-Hop Delegation Demo")
    parser.add_argument("--skip-startup", action="store_true",
                        help="Skip service startup (assume services already running)")
    args = parser.parse_args()

    banner("Tesht (Pramana) — Multi-Hop Delegation Chain Demo")
    print(f"  {DIM}2-hop chain: Alice → DataAnalyst (Agent A) → KYBReviewer (Agent B){RESET}")
    print(f"  {DIM}Shows: scope narrowing, violation detection, trust degradation, audit visibility{RESET}")

    procs: list[subprocess.Popen] = []
    config_path: Optional[str] = None
    try:
        if not args.skip_startup:
            # ── Start services ────────────────────────────────────────────────────
            print(f"\n{BOLD}Starting services…{RESET}")

            config_path = _write_demo_config()

            oidc_proc = start_server("idp_bridge.mock_oidc_provider:app", OIDC_PORT)
            procs.append(oidc_proc)

            bridge_proc = start_server(
                "idp_bridge.app:app", BRIDGE_PORT,
                extra_env={"IDP_BRIDGE_CONFIG": config_path, "TESHT_CORS_ENABLED": "1"},
            )
            procs.append(bridge_proc)

            sqlite_proc = start_server("gateway.sqlite_mcp_server:app", SQLITE_MCP_PORT)
            procs.append(sqlite_proc)

            gw_proc = start_server(
                "gateway.app:app", GW_PORT,
                extra_env={
                    "TESHT_CORS_ENABLED": "1",
                    "PYTHONPATH": f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}",
                },
            )
            procs.append(gw_proc)
        else:
            print(f"\n{DIM}--skip-startup: using already-running services{RESET}")

        # ── Wait for health ───────────────────────────────────────────────────
        services = [
            ("Mock OIDC", f"{OIDC_URL}/health"),
            ("IdP Bridge", f"{BRIDGE_URL}/health"),
            ("SQLite MCP", f"{SQLITE_MCP_URL}/health"),
            ("Gateway", f"{GW_URL}/gateway/health"),
        ]
        all_up = True
        for name, url in services:
            ok = wait_healthy(url)
            step("SVC", f"{name:<14} {url}", ok)
            if not ok:
                all_up = False

        if not all_up:
            print(f"\n{RED}One or more services failed to start.{RESET}")
            return

        # ── Get gateway DID ───────────────────────────────────────────────────
        with httpx.Client() as client:
            gw_health = client.get(f"{GW_URL}/gateway/health", timeout=5.0).json()
            gateway_did = gw_health.get("gateway_did", "")
            info("GW", "Gateway DID", gateway_did[:52] + "...")

            # ── Create agent identities ───────────────────────────────────────
            agent_a = AgentIdentity.create("DataAnalyst")
            agent_b = AgentIdentity.create("KYBReviewer")

            # Issue agent credentials for both
            bridge_health = client.get(f"{BRIDGE_URL}/health", timeout=5.0).json()
            bridge_identity = AgentIdentity.create("bridge-issuer-local")

            agent_a_vc = issue_vc(
                issuer=bridge_identity,
                subject_did=agent_a.did,
                credential_type="AgentCredential",
                claims={
                    "agentName": "DataAnalyst",
                    "ownerOrg": "Acme Corp",
                    "agentType": "LLM",
                    "purpose": "Transaction data analysis",
                },
                ttl_seconds=3600,
            )

            agent_b_vc = issue_vc(
                issuer=bridge_identity,
                subject_did=agent_b.did,
                credential_type="AgentCredential",
                claims={
                    "agentName": "KYBReviewer",
                    "ownerOrg": "Acme Corp",
                    "agentType": "LLM",
                    "purpose": "Know-Your-Business counterparty review",
                },
                ttl_seconds=3600,
            )

            # ── Step 1: Identity setup ────────────────────────────────────────
            enterprise_vc, delegation_vc_a, alice_claims, alice_did = step1_identity_setup(
                client, agent_a
            )

            scope_a = {
                "actions": ["read_data", "write_data"],
                "max_amount": 50000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": [],
            }

            # ── Step 2: Sub-delegation ────────────────────────────────────────
            delegation_vc_b, scope_b_actions = step2_sub_delegation(
                agent_a, agent_b, delegation_vc_a, gateway_did
            )

            scope_b = {
                "actions": scope_b_actions,
                "max_amount": 10000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": [],
            }

            # Display the full chain before gateway calls
            chain_box(
                alice_did=alice_did,
                agent_a_did=agent_a.did,
                agent_b_did=agent_b.did,
                alice_name=alice_claims.get("name", "Alice Johnson"),
                scope_a=scope_a,
                scope_b=scope_b,
            )

            # ── Step 3: Normal operation ──────────────────────────────────────
            vp_b, trust_after_ok = step3_normal_operation(
                client, agent_b, agent_b_vc, delegation_vc_b,
                enterprise_vc, gateway_did,
            )

            time.sleep(0.5)

            # ── Step 4: Scope violation ───────────────────────────────────────
            trust_after_violation = step4_scope_violation(
                client, agent_b, agent_b_vc, delegation_vc_b,
                enterprise_vc, gateway_did, vp_b,
            )

            time.sleep(0.5)

            # ── Step 5: Recovery ──────────────────────────────────────────────
            step5_recovery(
                client, agent_b, agent_b_vc, delegation_vc_b,
                enterprise_vc, gateway_did,
            )

            time.sleep(0.5)

            # ── Step 6: Audit visibility ──────────────────────────────────────
            step6_audit_visibility(
                client, agent_b, alice_did, agent_a, alice_claims,
                scope_a, scope_b_actions,
            )

            # ── Summary ───────────────────────────────────────────────────────
            banner("Multi-Hop Delegation Chain — Summary")
            print(f"""
  {BOLD}What just happened:{RESET}

  {GREEN}1.{RESET} Alice authenticated via enterprise Okta (mock RS256)
     └→ IdP bridge issued OrganizationalRoleCredential + delegation (max_depth=2)

  {GREEN}2.{RESET} DataAnalyst (Agent A) sub-delegated to KYBReviewer (Agent B)
     └→ Scope narrowed: [read_data, write_data] → [read_data]
     └→ Max amount reduced: $50,000 → $10,000

  {GREEN}3.{RESET} Agent B's in-scope request (query_database) was ALLOWED
     └→ 2-hop delegation chain verified cryptographically at every hop
     └→ Trust scored with depth penalty (depth=2, factor=15)

  {RED}4.{RESET} Agent B's out-of-scope request (insert_record) was BLOCKED
     └→ Scope check: write_data not in [read_data]
     └→ Trust penalty accumulated for scope probing

  {GREEN}5.{RESET} Fresh VP presentation reset the penalty window
     └→ System adapts — no permanent lockout

  {CYAN}6.{RESET} Every audit event contains:
     └→ delegation_depth: 2 (Alice → Agent A → Agent B)
     └→ delegation_chain_dids: [Alice DID, Agent A DID, Agent B DID]
     └→ effective_scope: {{actions: [read_data], max_amount: 10000}}
     └→ SHA-256 hash chain verifiable by compliance team

  {BOLD}The guarantee:{RESET}
  {DIM}When opposing counsel asks what KYBReviewer did, who authorized it,{RESET}
  {DIM}and whether the audit trail is intact — you can answer all three.{RESET}
""")

    finally:
        if not args.skip_startup:
            if config_path:
                try:
                    Path(config_path).unlink(missing_ok=True)
                except Exception:
                    pass
            if procs:
                print(f"\n{BOLD}Shutting down services…{RESET}")
                for p in procs:
                    kill_proc(p)
                print(f"  {PASS} Done.")


if __name__ == "__main__":
    main()
