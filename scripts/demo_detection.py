#!/usr/bin/env python3
"""
Tesht (Pramana) — Detection Engine Demo
=========================================

Fully self-contained: starts the mock MCP server and gateway as subprocesses,
waits for health, then drives a 4-phase scenario showing real-time detection
of shadow agents, behavioral anomalies, and fleet-level threats.

Phase 1 — Normal Traffic (Baseline):
  Three agents make legitimate requests → inventory shows 3 known agents

Phase 2 — Shadow Agent Attack:
  Unknown entity (no VP) tries access 3 times → shadow agent alert fires

Phase 3 — Behavioral Anomaly (Scope Probing):
  ShoppingBot probes out-of-scope tools → scope probing alert fires

Phase 4 — Fleet Summary:
  Full detection scan showing all alerts + risk distribution
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

from tesht.credentials import create_blended_presentation, issue_vc
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity

# ── Terminal colours ──────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
DIM = "\033[2m"
MAGENTA = "\033[95m"

PASS = f"{GREEN}[OK]{RESET}"
FAIL = f"{RED}[!!]{RESET}"
WARN = f"{YELLOW}[~~]{RESET}"
ALERT_ICON = f"{RED}[ALERT]{RESET}"

GW_PORT = 5052
MCP_PORT = 9100
GW_BASE = f"http://127.0.0.1:{GW_PORT}"
MCP_BASE = f"http://127.0.0.1:{MCP_PORT}"


# ── Output helpers ────────────────────────────────────────────────────────────

def banner(text: str) -> None:
    w = 70
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}━━━ {title} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")


def alert_box(severity: str, title: str, lines: list[str]) -> None:
    """Print a bordered alert box."""
    color = RED if severity == "critical" else YELLOW
    w = 63
    print(f"\n  {color}╔{'═' * w}╗{RESET}")
    icon = "🚨" if severity == "critical" else "⚠️ "
    header = f"  {icon} {title}"
    print(f"  {color}║{RESET} {BOLD}{header:<{w - 1}}{RESET}{color}║{RESET}")
    print(f"  {color}║{RESET} {f'Severity: {severity.upper()}':<{w - 1}}{color}║{RESET}")
    for line in lines:
        for chunk in _wrap(line, w - 2):
            print(f"  {color}║{RESET} {chunk:<{w - 1}}{color}║{RESET}")
    print(f"  {color}╚{'═' * w}╝{RESET}")


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if current and len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines or [""]


def risk_bar(count: int, total: int, width: int = 14) -> str:
    if total == 0:
        return " " * width
    filled = int(count / total * width)
    return f"{GREEN}{'█' * filled}{'░' * (width - filled)}{RESET}"


# ── Subprocess management ─────────────────────────────────────────────────────

def start_server(module: str, port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
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


# ── Identity setup ────────────────────────────────────────────────────────────

def make_agent_vp(agent_name: str, actions: list[str], gw_did: str) -> tuple[str, str]:
    """Create a blended VP for an agent. Returns (vp_jwt, agent_did)."""
    idp = AgentIdentity.create("demo-idp")
    alice = AgentIdentity.create("alice")
    agent = AgentIdentity.create(agent_name.lower().replace(" ", "-"))

    alice_vc = issue_vc(
        issuer=idp,
        subject_did=alice.did,
        credential_type="OrganizationalRoleCredential",
        claims={"name": "Alice Demo", "role": "Manager", "organization": "DemoCorp"},
    )
    agent_vc = issue_vc(
        issuer=idp,
        subject_did=agent.did,
        credential_type="AgentCredential",
        claims={"agentName": agent_name, "ownerOrg": "DemoCorp"},
    )
    deleg = issue_delegation(
        delegator=alice,
        delegate_did=agent.did,
        scope={
            "actions": actions,
            "max_amount": 10000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
        },
        max_depth=2,
    )
    vp = create_blended_presentation(
        agent=agent,
        delegation_jwt=deleg,
        delegator_identity_jwt=alice_vc,
        additional_credentials=[agent_vc],
        audience=gw_did,
    )
    return vp, agent.did


def call_tool(client: httpx.Client, vp: str, tool: str, req_id: int = 1) -> dict:
    body = json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    })
    try:
        r = client.post(
            f"{GW_BASE}/mcp/mock_database",
            content=body.encode(),
            headers={"Authorization": f"Bearer {vp}", "Content-Type": "application/json"},
            timeout=10.0,
        )
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def call_no_auth(client: httpx.Client, tool: str, req_id: int = 1) -> dict:
    """Make a request without any Authorization header (shadow agent simulation)."""
    body = json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    })
    try:
        r = client.post(
            f"{GW_BASE}/mcp/mock_database",
            content=body.encode(),
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def get_gateway_did(client: httpx.Client) -> str:
    r = client.get(f"{GW_BASE}/gateway/health", timeout=5.0)
    return r.json().get("gateway_did", "")


def get_detections(client: httpx.Client) -> dict:
    r = client.get(f"{GW_BASE}/gateway/detections", timeout=10.0)
    return r.json()


def get_inventory(client: httpx.Client) -> dict:
    r = client.get(f"{GW_BASE}/gateway/inventory", timeout=10.0)
    return r.json()


# ── Demo phases ───────────────────────────────────────────────────────────────

def phase1_normal_traffic(client: httpx.Client, gw_did: str) -> None:
    """Phase 1: Establish baseline with 3 legitimate agents."""
    section("Phase 1: Normal Traffic (Baseline)")

    agents = [
        ("ShoppingBot", ["read_data", "write_data"], "query_database"),
        ("CodeReviewer", ["read_data"], "query_database"),
        ("ComplianceBot", ["read_data", "write_data"], "insert_record"),
    ]

    results = []
    for agent_name, actions, tool in agents:
        vp, agent_did = make_agent_vp(agent_name, actions, gw_did)
        resp = call_tool(client, vp, tool)
        success = "result" in resp and not resp.get("result", {}).get("isError", True)
        icon = PASS if success else FAIL
        status = "ALLOWED" if success else "BLOCKED"
        color = GREEN if success else RED
        results.append((agent_name, tool, status, agent_did[:24]))
        print(f"\n  {icon} {BOLD}{agent_name}{RESET} → {CYAN}{tool}{RESET} "
              f"→ {color}{status}{RESET}")

    inv = get_inventory(client)
    known = len(inv.get("known_agents", []))
    shadows = len(inv.get("shadow_attempts", []))
    print(f"\n  {DIM}Inventory: {known} known agents, {shadows} shadow attempts, 0 alerts{RESET}")


def phase2_shadow_attack(client: httpx.Client) -> dict:
    """Phase 2: Three unauthenticated requests to trigger shadow detection."""
    section("Phase 2: Shadow Agent Attack")

    for i in range(3):
        resp = call_no_auth(client, "query_database", req_id=100 + i)
        error_msg = resp.get("error", {})
        if isinstance(error_msg, dict):
            error_msg = error_msg.get("message", "auth failed")
        print(f"\n  {FAIL} {YELLOW}Unknown entity (no VP){RESET} → {RED}BLOCKED{RESET}  "
              f"{DIM}({error_msg[:50]}){RESET}")
        time.sleep(0.1)

    det = get_detections(client)
    shadow_alerts = [a for a in det.get("alerts", []) if a.get("type") == "shadow_agent"]

    if shadow_alerts:
        a = shadow_alerts[0]
        count = a.get("evidence", {}).get("attempt_count", 3)
        alert_box(
            a.get("severity", "warning"),
            a.get("title", "Shadow agent detected"),
            [
                f"{count} attempt(s) from unknown entity without credentials",
                f"Recommended: {a.get('action', 'Block source IP')}",
            ],
        )
    else:
        print(f"\n  {DIM}(No shadow alerts yet — scan after more attempts){RESET}")

    return det


def phase3_behavioral_anomaly(client: httpx.Client, gw_did: str) -> dict:
    """Phase 3: ShoppingBot probes out-of-scope tools."""
    section("Phase 3: Behavioral Anomaly (Scope Probing)")

    # Use the same ShoppingBot identity (with only read_data/write_data scope)
    shopping_vp, shopping_did = make_agent_vp(
        "ShoppingBot", ["read_data", "write_data"], gw_did
    )

    out_of_scope_tools = ["delete_record", "delete_record", "delete_record"]
    for i, tool in enumerate(out_of_scope_tools):
        resp = call_tool(client, shopping_vp, tool, req_id=200 + i)
        error = resp.get("error", {})
        msg = error.get("message", "scope denied") if isinstance(error, dict) else str(error)
        print(f"\n  {FAIL} {BOLD}ShoppingBot{RESET} → {CYAN}{tool}{RESET} "
              f"→ {RED}SCOPE BLOCKED{RESET}  {DIM}(violation #{i + 1}){RESET}")
        time.sleep(0.1)

    det = get_detections(client)
    scope_alerts = [a for a in det.get("alerts", [])
                    if a.get("type") in ("scope_probing", "behavioral_anomaly")]

    if scope_alerts:
        a = scope_alerts[0]
        evidence = a.get("evidence", {})
        violations = evidence.get("scope_violations", 3)
        tools_probed = evidence.get("tools_probed", ["delete_record"])
        alert_box(
            a.get("severity", "critical"),
            a.get("title", "Scope probing detected"),
            [
                f"Agent: ShoppingBot ({shopping_did[:20]}...)",
                f"{violations} out-of-scope tool(s) probed: {tools_probed}",
                f"Recommended: {a.get('action', 'Revoke delegation')}",
            ],
        )
    else:
        print(f"\n  {DIM}(Scope alerts pending — trust cache may have expired){RESET}")

    return det


def phase4_fleet_summary(client: httpx.Client) -> None:
    """Phase 4: Print full fleet status."""
    section("Phase 4: Fleet Summary")

    det = get_detections(client)
    inv = get_inventory(client)
    fleet = det.get("fleet", {})
    alerts = det.get("alerts", [])

    known = len(inv.get("known_agents", []))
    shadows = fleet.get("shadow_attempts", 0)
    violations = fleet.get("with_violations", 0)
    avg_trust = fleet.get("avg_trust", 0)
    risk = fleet.get("risk_distribution", {})
    alert_count = len(alerts)

    total_risk = sum(risk.values()) or 1

    print(f"""
  ┌──────────────────────────────────────────────────────────────┐
  │ {BOLD}FLEET STATUS{RESET}                                                  │
  │                                                              │
  │ Agents:    {BOLD}{known:>2} known{RESET}  │  Shadow attempts: {BOLD}{shadows}{RESET}             │
  │ Violations:{BOLD}{violations:>2} agent(s){RESET}│  Avg trust: {BOLD}{avg_trust:.0f}/100{RESET}               │
  │                                                              │
  │ Risk Distribution:                                           │
  │   Low     (≥75): {risk.get('low', 0):>2} agents  {risk_bar(risk.get('low', 0), total_risk)}  │
  │   Medium (50-74): {risk.get('medium', 0):>2} agents  {risk_bar(risk.get('medium', 0), total_risk)}  │
  │   High   (25-49): {risk.get('high', 0):>2} agents  {risk_bar(risk.get('high', 0), total_risk)}  │
  │   Critical (<25): {risk.get('critical', 0):>2} agents  {risk_bar(risk.get('critical', 0), total_risk)}  │
  │                                                              │
  │ Active Alerts: {BOLD}{alert_count}{RESET}                                            │""")

    for a in alerts[:5]:
        sev_color = RED if a.get("severity") == "critical" else YELLOW
        title = a.get("title", "")[:50]
        print(f"  │   {sev_color}▶ {a.get('severity', '').upper():8}{RESET} {title:<50}  │")

    print("  └──────────────────────────────────────────────────────────────┘")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    banner("TESHT DETECTION ENGINE — Live Demo")
    print(f"\n{DIM}Starting services…{RESET}")

    mcp_proc = start_server("gateway.mock_mcp_server:app", MCP_PORT)
    gw_proc = start_server("gateway.app:app", GW_PORT)

    try:
        if not wait_healthy(f"{MCP_BASE}/health"):
            print(f"{RED}Mock MCP server failed to start.{RESET}")
            sys.exit(1)
        if not wait_healthy(f"{GW_BASE}/gateway/health"):
            print(f"{RED}Gateway failed to start.{RESET}")
            sys.exit(1)

        print(f"  {PASS} Mock MCP server running on port {MCP_PORT}")
        print(f"  {PASS} Gateway running on port {GW_PORT}")

        with httpx.Client() as client:
            gw_did = get_gateway_did(client)
            if not gw_did:
                print(f"{RED}Could not retrieve gateway DID.{RESET}")
                sys.exit(1)
            print(f"  {DIM}Gateway DID: {gw_did[:40]}…{RESET}")

            phase1_normal_traffic(client, gw_did)
            time.sleep(0.5)

            phase2_shadow_attack(client)
            time.sleep(0.5)

            phase3_behavioral_anomaly(client, gw_did)
            time.sleep(0.5)

            phase4_fleet_summary(client)

        print(f"\n{BOLD}{GREEN}Detection demo complete.{RESET}\n")

    finally:
        kill_proc(gw_proc)
        kill_proc(mcp_proc)


if __name__ == "__main__":
    main()
