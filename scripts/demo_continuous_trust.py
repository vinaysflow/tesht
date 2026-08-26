#!/usr/bin/env python3
"""
Tesht (Pramana) — Continuous Trust Demo
=========================================

Fully self-contained: starts the mock MCP server and gateway as subprocesses,
waits for health, then drives a 13-step session showing the trust score
changing in real time based on behavioral signals.

Timeline:
  t=0-2:  Normal tool usage      → trust stable at base (~85)
  t=3:    Novel tool accessed     → mild penalty (-5)
  t=4-5:  Two scope violations    → significant penalty (~-25 total)
  t=6:    Normal tool             → step-up triggered (score ~60)
  t=7:    Re-auth with fresh VP   → penalty reduced, trust restored
  t=8-10: Velocity spike          → velocity penalty applied
  t=11:   Re-auth + normal pace   → trust restored again

Output: tabular timeline + ASCII trust-over-time chart.
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

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
WARN = f"{YELLOW}⚠{RESET}"

ALLOW_COLOR = GREEN
BLOCK_COLOR = RED
STEPUP_COLOR = YELLOW


def banner(text: str) -> None:
    w = 70
    print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
    print(f"{BOLD}║  {text:<{w - 2}}║{RESET}")
    print(f"{BOLD}╚{'═' * w}╝{RESET}")


def score_bar(score: int, width: int = 25) -> str:
    filled = int(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    color = GREEN if score >= 75 else (YELLOW if score >= 50 else RED)
    return f"{color}{bar}{RESET}"


def decision_badge(decision: str) -> str:
    if decision == "allow":
        return f"{GREEN}ALLOW  {RESET}"
    elif decision == "step_up":
        return f"{YELLOW}STEP-UP{RESET}"
    else:
        return f"{RED}BLOCK  {RESET}"


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


# ── MCP request helpers ───────────────────────────────────────────────────────

def call_tool(
    client: httpx.Client,
    gateway_url: str,
    vp: str,
    tool: str,
    req_id: int = 1,
) -> dict:
    body = json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    })
    r = client.post(
        f"{gateway_url}/mcp/mock_database",
        content=body.encode(),
        headers={"Authorization": f"Bearer {vp}", "Content-Type": "application/json"},
        timeout=10,
    )
    return {"status": r.status_code, "body": r.json()}


def get_last_trust_score(client: httpx.Client, gateway_url: str) -> tuple[int, str, dict]:
    """Return (score, decision, factors) from the most recent audit event."""
    events = client.get(f"{gateway_url}/gateway/events?n=5", timeout=5).json()
    if events:
        last = events[-1]
        return (
            last.get("trust_score", 0),
            last.get("trust_decision", "?"),
            last,
        )
    return 0, "?", {}


# ── Identity setup ────────────────────────────────────────────────────────────

def make_blended_vp(gateway_did: str, agent: AgentIdentity, delegator: AgentIdentity) -> str:
    """Build a fresh blended VP from Alice → ShoppingBot."""
    org_vc = issue_vc(
        issuer=delegator,
        subject_did=delegator.did,
        credential_type="OrganizationalRoleCredential",
        claims={
            "name": "Alice Johnson",
            "email": "alice@acmecorp.com",
            "organization": "Acme Corp",
            "role": "Senior Buyer",
        },
    )
    agent_vc = issue_vc(
        issuer=agent,
        subject_did=agent.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShoppingBot"},
    )
    delegation = issue_delegation(
        delegator=delegator,
        delegate_did=agent.did,
        scope={
            "actions": ["read_data", "write_data"],
            "max_amount": 50000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
        },
    )
    return create_blended_presentation(
        agent=agent,
        delegation_jwt=delegation,
        delegator_identity_jwt=org_vc,
        additional_credentials=[agent_vc],
        audience=gateway_did,
    )


# ── ASCII chart ───────────────────────────────────────────────────────────────

def print_trust_chart(scores: list[tuple[int, str, str]]) -> None:
    """Print an ASCII chart of the trust timeline.

    *scores* is a list of (score, decision, label).
    """
    print(f"\n  {BOLD}Trust Score Timeline{RESET}")
    print("  " + "─" * 68)

    # Header row
    print(f"  {'t':<4} {'Tool':<18} {'Score':>5}  {'Bar':<28} {'Decision':<10} {'Signal'}")
    print("  " + "─" * 68)

    for i, (score, decision, label, signal) in enumerate(scores):
        bar = score_bar(score, width=20)
        badge = decision_badge(decision)
        sig = f"{DIM}{signal}{RESET}" if signal else ""
        print(f"  {i:<4} {label:<18} {score:>5}  {bar}  {badge} {sig}")

    print("  " + "─" * 68)

    # ASCII sparkline
    heights = [s[0] for s in scores]
    min_h = min(heights)
    max_h = max(heights)
    range_h = max(1, max_h - min_h)

    rows = 5
    print()
    print(f"  {BOLD}Score{RESET}")
    for row in range(rows, 0, -1):
        threshold = min_h + (row / rows) * range_h
        line = f"  {int(threshold):>3}│"
        for score, decision, _, _ in scores:
            if score >= threshold:
                if score >= 75:
                    line += f"{GREEN}█{RESET}"
                elif score >= 50:
                    line += f"{YELLOW}█{RESET}"
                else:
                    line += f"{RED}█{RESET}"
            else:
                line += " "
        print(line)

    print(f"     └{'─' * len(scores)}")
    print(f"      {''.join(str(i % 10) for i in range(len(scores)))}")
    print(f"      {DIM}step →{RESET}")

    # Threshold annotations
    print(f"\n  {GREEN}■{RESET} {GREEN}≥75 ALLOW{RESET}    "
          f"{YELLOW}■{RESET} {YELLOW}50-74 STEP-UP{RESET}    "
          f"{RED}■{RESET} {RED}<50 BLOCK{RESET}")


# ── Main demo ─────────────────────────────────────────────────────────────────

def main() -> int:
    banner("TESHT CONTINUOUS TRUST — Live Trust Score Timeline")
    print(f"\n  {DIM}Starting gateway and mock MCP server...{RESET}")

    mock_proc = start_server("gateway.mock_mcp_server:app", 9100)
    gw_proc = start_server("gateway.app:app", 5052)

    try:
        if not wait_healthy("http://127.0.0.1:9100/health"):
            print(f"  {FAIL} Mock MCP server failed to start")
            return 1
        print(f"  {PASS} Mock MCP server healthy (port 9100)")

        if not wait_healthy("http://127.0.0.1:5052/gateway/health"):
            print(f"  {FAIL} Gateway failed to start")
            return 1
        print(f"  {PASS} Gateway healthy (port 5052)")

        gw_health = httpx.get("http://127.0.0.1:5052/gateway/health", timeout=5).json()
        gateway_did = gw_health["gateway_did"]
        print(f"  {PASS} Gateway DID: {gateway_did[:52]}...")

        gateway_url = "http://127.0.0.1:5052"

        # Create identities
        alice = AgentIdentity.create("alice-johnson")
        shopping_bot = AgentIdentity.create("shopping-agent")

        # Initial VP
        vp1 = make_blended_vp(gateway_did, shopping_bot, alice)
        print(f"\n  {DIM}Agent: ShoppingBot | Human: Alice Johnson @ Acme Corp{RESET}")
        print(f"  {DIM}Scope: [read_data, write_data] ≤ $50000 USD{RESET}\n")

        scores: list[tuple[int, str, str, str]] = []  # (score, decision, tool_label, signal)
        errors: list[str] = []

        with httpx.Client() as client:

            def step(label: str, tool: str, vp: str, signal: str = "") -> tuple[int, str]:
                result = call_tool(client, gateway_url, vp, tool, req_id=len(scores)+1)
                score, decision, _ = get_last_trust_score(client, gateway_url)
                badge = decision_badge(decision)
                bar = score_bar(score, width=20)
                sig_text = f"{DIM}{signal}{RESET}" if signal else ""
                print(f"  {badge} t={len(scores):<2} {label:<20} score={score:>3}/100  {bar}  {sig_text}")
                scores.append((score, decision, label, signal))
                return score, decision

            # ── t=0-2: Normal queries (establish baseline) ──────────────
            print(f"  {BOLD}Phase 1: Normal behavior{RESET}")
            for i in range(3):
                score, _ = step("query_database", "query_database", vp1)

            # ── t=3: Novel tool (send_email, not in history) ─────────────
            print(f"\n  {BOLD}Phase 2: Novel tool access{RESET}")
            score3, dec3 = step("send_email", "query_database", vp1, "Novel tool: send_email (-5)")
            # Note: send_email is not in the mock server's scope, so we use query_database
            # but trigger the novel-tool signal by calling a tools/call for a new tool name
            # We need to trick the gateway into seeing a new tool. Use a different tool name
            # that IS in scope for this demo. Since mock only has query_database, insert_record,
            # delete_record, let's do insert_record (which is in scope via write_data).

            # Re-do step t=3 with insert_record (novel tool, in scope)
            scores.pop()  # remove the placeholder
            result = call_tool(client, gateway_url, vp1, "insert_record", req_id=10)
            score, decision, _ = get_last_trust_score(client, gateway_url)
            badge = decision_badge(decision)
            bar = score_bar(score, width=20)
            print(f"  {badge} t=3  {'insert_record':<20} score={score:>3}/100  {bar}  "
                  f"{DIM}Novel tool: insert_record (-5){RESET}")
            scores.append((score, decision, "insert_record", "Novel tool (-5)"))

            # ── t=4-5: Scope violations ──────────────────────────────────
            print(f"\n  {BOLD}Phase 3: Scope boundary probing{RESET}")
            for i, req_num in enumerate([4, 5]):
                result = call_tool(client, gateway_url, vp1, "delete_record", req_id=20+i)
                score, decision, _ = get_last_trust_score(client, gateway_url)
                badge = decision_badge(decision)
                bar = score_bar(score, width=20)
                violation_num = i + 1
                penalty = 5 if violation_num == 1 else 15
                print(f"  {badge} t={req_num}  {'delete_record':<20} score={score:>3}/100  {bar}  "
                      f"{DIM}Scope violation #{violation_num} (-{penalty}){RESET}")
                scores.append((score, decision, "delete_record [BLOCKED]", f"Scope violation #{violation_num}"))
                time.sleep(0.1)

            # ── t=6: Normal tool — check if step-up triggered ───────────
            print(f"\n  {BOLD}Phase 4: Normal tool after violations{RESET}")
            result = call_tool(client, gateway_url, vp1, "query_database", req_id=30)
            score, decision, _ = get_last_trust_score(client, gateway_url)
            badge = decision_badge(decision)
            bar = score_bar(score, width=20)
            signal_text = "Score degraded from probing" if decision in ("step_up", "block") else ""
            print(f"  {badge} t=6  {'query_database':<20} score={score:>3}/100  {bar}  "
                  f"{DIM}{signal_text}{RESET}")
            scores.append((score, decision, "query_database", signal_text))

            # ── t=7: Re-authenticate with fresh VP ──────────────────────
            print(f"\n  {BOLD}Phase 5: Re-authentication (fresh VP){RESET}")
            vp2 = make_blended_vp(gateway_did, shopping_bot, alice)
            result = call_tool(client, gateway_url, vp2, "query_database", req_id=40)
            score, decision, _ = get_last_trust_score(client, gateway_url)
            badge = decision_badge(decision)
            bar = score_bar(score, width=20)
            print(f"  {badge} t=7  {'[RE-AUTH] query':<20} score={score:>3}/100  {bar}  "
                  f"{DIM}Fresh VP: penalty reduced by 20{RESET}")
            scores.append((score, decision, "[RE-AUTH] query", "Fresh VP (-20 penalty)"))

            # ── t=8-10: Velocity spike ───────────────────────────────────
            print(f"\n  {BOLD}Phase 6: Velocity spike{RESET}")
            print(f"  {DIM}Sending 20 rapid requests...{RESET}")
            for i in range(20):
                call_tool(client, gateway_url, vp2, "query_database", req_id=50+i)
            score, decision, _ = get_last_trust_score(client, gateway_url)
            badge = decision_badge(decision)
            bar = score_bar(score, width=20)
            print(f"  {badge} t=8-10 {'rapid ×20':<20} score={score:>3}/100  {bar}  "
                  f"{DIM}Velocity spike → penalty applied{RESET}")
            scores.append((score, decision, "rapid ×20", "Velocity spike"))

            # ── t=11: Re-auth again ──────────────────────────────────────
            print(f"\n  {BOLD}Phase 7: Final re-authentication{RESET}")
            vp3 = make_blended_vp(gateway_did, shopping_bot, alice)
            result = call_tool(client, gateway_url, vp3, "query_database", req_id=80)
            score, decision, _ = get_last_trust_score(client, gateway_url)
            badge = decision_badge(decision)
            bar = score_bar(score, width=20)
            print(f"  {badge} t=11 {'[RE-AUTH] query':<20} score={score:>3}/100  {bar}  "
                  f"{DIM}Trust partially restored{RESET}")
            scores.append((score, decision, "[RE-AUTH] final", "Trust restored"))

        # ── Print chart ──────────────────────────────────────────────────
        print()
        print_trust_chart(scores)

        # ── Key insight ──────────────────────────────────────────────────
        initial_score = scores[0][0]
        min_score = min(s[0] for s in scores)
        final_score = scores[-1][0]

        banner("Key Insight")
        print(f"""
  {BOLD}Same agent. Same credentials. Trust score changed from {initial_score} to {min_score}
  based on behavior alone — then partially recovered on re-auth.{RESET}

  {DIM}Signal breakdown:{RESET}
    Tool Pattern Deviation:   Novel tool access → -{YELLOW}5{RESET} points (1st), -{YELLOW}10{RESET} (2nd), -{YELLOW}15{RESET} (3rd+)
    Scope Boundary Probing:   Scope violations  → -{YELLOW}5{RESET} (1st), -{YELLOW}15{RESET} (2nd), -{YELLOW}25{RESET} (3rd+)
    Velocity Anomaly:         Request spike     → -{YELLOW}5{RESET}/{YELLOW}10{RESET}/{YELLOW}20{RESET} (15/30/60+ rpm)
    Fresh VP Re-auth:         Penalty recovery  → {GREEN}+20{RESET} on new VP

  {DIM}Competitors do binary allow/deny.{RESET}
  {BOLD}Tesht does continuous, graduated trust with behavioral recovery.{RESET}
""")

        return 0

    finally:
        kill_proc(gw_proc)
        kill_proc(mock_proc)


if __name__ == "__main__":
    sys.exit(main())
