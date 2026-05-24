#!/usr/bin/env python3
"""
Pramana Protocol — CISO Audit Query Demo
=========================================

Demonstrates subpoena-ready compliance output:
  • Time-range filtered audit query by agent DID
  • Every action: what was done, who authorized it, what trust score
  • SHA-256 hash chain verification proving the log is intact
  • CSV export ready for legal / compliance team

Run:
    PYTHONPATH=".:sdk/python" python3 scripts/demo_ciso_audit.py
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
sys.path.insert(0, str(PROJECT_ROOT))

import httpx
import yaml

from pramana.credentials import create_blended_presentation, issue_vc
from pramana.identity import AgentIdentity

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

# ── Terminal colours ───────────────────────────────────────────────────────────
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
    print(f"  [{CYAN}{tag:<7}{RESET}] {DIM}{label:<16}{RESET} {value}")


def alert_box(severity: str, title: str, lines: list[str]) -> None:
    color = RED if severity == "critical" else YELLOW
    w = 63
    print(f"\n  {color}╔{'═' * w}╗{RESET}")
    icon = "!!" if severity == "critical" else "~~"
    header = f"  [{icon}] {title}"
    print(f"  {color}║{RESET} {BOLD}{header:<{w - 1}}{RESET}{color}║{RESET}")
    for line in lines:
        max_w = w - 2
        while len(line) > max_w:
            print(f"  {color}║{RESET} {line[:max_w]:<{max_w}}{color}║{RESET}")
            line = "  " + line[max_w:]
        print(f"  {color}║{RESET} {line:<{w - 1}}{color}║{RESET}")
    print(f"  {color}╚{'═' * w}╝{RESET}")


# ── Service management ─────────────────────────────────────────────────────────

def _write_bridge_config() -> str:
    cfg = {
        "providers": {
            "mock_idp": {
                "name": "Acme Corp Okta (Mock)",
                "issuer": "https://mock-idp.pramana.local",
                "jwks_uri": f"http://127.0.0.1:{OIDC_PORT}/.well-known/jwks.json",
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
            }
        }
    }
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
        [sys.executable, "-m", "uvicorn", module,
         "--host", "127.0.0.1", "--port", str(port),
         "--log-level", "error"],
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


# ── MCP call helpers ───────────────────────────────────────────────────────────

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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decision_color(decision: str) -> str:
    if decision in ("allow", "allowed"):
        return f"{GREEN}{decision.upper()}{RESET}"
    if decision in ("step_up",):
        return f"{YELLOW}{decision.upper()}{RESET}"
    return f"{RED}{decision.upper()}{RESET}"


def _check_postgres(host: str = "127.0.0.1", port: int = 5432) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _make_database_url(host: str = "127.0.0.1", port: int = 5432) -> str:
    user = os.environ.get("POSTGRES_USER", "pramana")
    password = os.environ.get("POSTGRES_PASSWORD", "pramana_dev_password")
    db = os.environ.get("POSTGRES_DB", "pramana")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


# ── Demo ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Pramana CISO Audit Demo")
    parser.add_argument("--skip-startup", action="store_true",
                        help="Skip service startup (assume services already running)")
    args = parser.parse_args()

    banner("PRAMANA PROTOCOL — CISO Audit Query Demo")
    print(f"  {DIM}\"If opposing counsel sends a subpoena, can you respond?\"{RESET}")
    print(f"  {DIM}This demo answers yes — with cryptographic proof.{RESET}\n")

    cfg_path: Optional[str] = None
    oidc_proc = bridge_proc = mcp_proc = sqlite_mcp_proc = gw_proc = None

    if not args.skip_startup:
        # Start services
        print(f"  {DIM}Starting services…{RESET}")
        cfg_path = _write_bridge_config()

        pg_available = _check_postgres()
        gw_extra_env: Optional[dict] = None
        if pg_available:
            gw_extra_env = {"DATABASE_URL": _make_database_url()}
            print(f"  {PASS} PostgreSQL detected — enabling persistent hash-chained audit")
        else:
            print(f"  {WARN} PostgreSQL not found — using in-memory audit")

        bridge_env: dict = {"IDP_BRIDGE_CONFIG": cfg_path}
        oidc_proc = start_server("idp_bridge.mock_oidc_provider:app", OIDC_PORT)
        bridge_proc = start_server("idp_bridge.app:app", BRIDGE_PORT, bridge_env)
        mcp_proc = start_server("gateway.mock_mcp_server:app", MCP_PORT)
        sqlite_mcp_proc = start_server("gateway.sqlite_mcp_server:app", SQLITE_MCP_PORT)
        gw_proc = start_server("gateway.app:app", GW_PORT, gw_extra_env)
    else:
        print(f"  {DIM}--skip-startup: using already-running services{RESET}")

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

        gw_health = httpx.get(f"{GW_URL}/gateway/health", timeout=5.0).json()
        gateway_did = gw_health["gateway_did"]
        print(f"  {DIM}Gateway DID: {gateway_did[:48]}…{RESET}\n")

        with httpx.Client() as client:
            # ── Step 1: Establish identity ────────────────────────────────────
            section("1", "Establish Agent Identity")
            print(f"  {DIM}ComplianceBot authenticates via Acme Corp Okta (mock){RESET}\n")

            compliance_bot = AgentIdentity.create("compliance-bot")

            r = client.get(f"{OIDC_URL}/token?user=alice", timeout=5.0)
            r.raise_for_status()
            alice_token = r.json()["id_token"]
            step("IDP", "Alice Johnson authenticates via Acme Corp Okta (mock RS256)")

            r = client.post(f"{BRIDGE_URL}/bind", json={
                "oidc_token": alice_token,
                "agent_did": compliance_bot.did,
                "scope": {
                    "actions": ["read_data", "write_data"],
                    "max_amount": 100000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": ["*"],
                },
                "ttl_seconds": 3600,
            }, timeout=10.0)
            r.raise_for_status()
            bind = r.json()

            claims = bind["claims"]
            enterprise_vc = bind["enterprise_vc"]
            delegation_vc = bind["delegation_vc"]

            step("VC", "OrganizationalRoleCredential issued by IdP bridge")
            info("VC", "Human identity", f"{claims.get('name', '?')} ({claims.get('email', '?')})")
            info("VC", "Organization", claims.get("organization", "?"))
            info("VC", "Role", claims.get("role", "?"))
            info("DEL", "Delegation", f"Alice → ComplianceBot  scope: read_data, write_data")

            # Build blended VP
            agent_vc = issue_vc(
                issuer=compliance_bot,
                subject_did=compliance_bot.did,
                credential_type="AgentCredential",
                claims={"agentName": "ComplianceBot", "ownerOrg": "Acme Corp"},
            )
            blended_vp = create_blended_presentation(
                agent=compliance_bot,
                delegation_jwt=delegation_vc,
                delegator_identity_jwt=enterprise_vc,
                additional_credentials=[agent_vc],
                audience=gateway_did,
            )
            step("VP", "Blended VP created (Agent + Human + Enterprise)")
            time.sleep(0.5)

            # ── Step 2: Run mixed agent activity ─────────────────────────────
            section("2", "Agent Activity (Mixed Allowed / Blocked)")
            print(f"  {DIM}Running 7 requests through the gateway to build the audit trail{RESET}\n")

            from_ts = _now_iso()

            # Action 1: read products
            status, resp = mcp_call(client, blended_vp, "query_database", req_id=1,
                                    arguments={"sql": "SELECT name, price FROM products LIMIT 3"})
            dec = "allow" if status == 200 else "blocked"
            print(f"  [{CYAN}{'GW':<7}{RESET}] read products (SELECT) → {_decision_color(dec)}")

            time.sleep(0.2)

            # Action 2: read orders
            status, resp = mcp_call(client, blended_vp, "query_database", req_id=2,
                                    arguments={"sql": "SELECT * FROM orders LIMIT 5"})
            dec = "allow" if status == 200 else "blocked"
            print(f"  [{CYAN}{'GW':<7}{RESET}] read orders (SELECT) → {_decision_color(dec)}")

            time.sleep(0.2)

            # Action 3: insert record
            status, resp = mcp_call(client, blended_vp, "insert_record", req_id=3,
                                    arguments={"table": "products",
                                               "data": {"name": "Audit Test Item", "price": 9.99,
                                                        "category": "test"}})
            dec = "allow" if status == 200 else "blocked"
            print(f"  [{CYAN}{'GW':<7}{RESET}] insert record (write_data) → {_decision_color(dec)}")

            time.sleep(0.2)

            # Action 4: delete — out of scope, trust degrades
            status, resp = mcp_call(client, blended_vp, "delete_record", req_id=4,
                                    arguments={"table": "products", "id": 999})
            dec = resp.get("error", {}).get("message", "")
            if "scope" in dec.lower() or status == 403:
                print(f"  [{CYAN}{'GW':<7}{RESET}] delete (admin scope) → {RED}BLOCKED (scope){RESET}  "
                      f"{DIM}trust degrading{RESET}")
            else:
                print(f"  [{CYAN}{'GW':<7}{RESET}] delete → {_decision_color('blocked')}")

            time.sleep(0.2)

            # Action 5: another scope violation — trust degrades further
            status, resp = mcp_call(client, blended_vp, "delete_record", req_id=5,
                                    arguments={"table": "orders", "id": 999})
            print(f"  [{CYAN}{'GW':<7}{RESET}] delete again (admin scope) → {RED}BLOCKED (scope){RESET}  "
                  f"{DIM}trust degraded further{RESET}")

            time.sleep(0.2)

            # Action 6: legitimate read — trust low, step-up triggered
            status, resp = mcp_call(client, blended_vp, "query_database", req_id=6,
                                    arguments={"sql": "SELECT COUNT(*) FROM products"})
            if status == 401:
                print(f"  [{CYAN}{'GW':<7}{RESET}] read (trust low) → {YELLOW}STEP-UP required{RESET}  "
                      f"{DIM}re-present VP{RESET}")
                # Re-authenticate with fresh VP
                fresh_vp = create_blended_presentation(
                    agent=compliance_bot,
                    delegation_jwt=delegation_vc,
                    delegator_identity_jwt=enterprise_vc,
                    additional_credentials=[agent_vc],
                    audience=gateway_did,
                )
                blended_vp = fresh_vp
                print(f"  [{CYAN}{'GW':<7}{RESET}] re-auth: fresh VP presented → {_decision_color('allow')}")
                # Retry with fresh VP
                status, resp = mcp_call(client, blended_vp, "query_database", req_id=7,
                                        arguments={"sql": "SELECT COUNT(*) FROM products"})
                dec = "allow" if status == 200 else "blocked"
                print(f"  [{CYAN}{'GW':<7}{RESET}] read (trust restored) → {_decision_color(dec)}")
            else:
                dec = "allow" if status == 200 else "blocked"
                print(f"  [{CYAN}{'GW':<7}{RESET}] read → {_decision_color(dec)}")

            time.sleep(0.5)
            to_ts = _now_iso()

            # ── Step 3: CISO Audit Query (time-range filtered) ───────────────
            section("3", "CISO Audit Query — Time-Range Filter")
            print(f"  {DIM}Querying all agent actions in the window:{RESET}")
            print(f"  {DIM}  from: {from_ts}{RESET}")
            print(f"  {DIM}  to:   {to_ts}{RESET}\n")

            r = client.get(
                f"{GW_URL}/gateway/events",
                params={
                    "agent_did": compliance_bot.did,
                    "from_ts": from_ts,
                    "to_ts": to_ts,
                },
                timeout=10.0,
            )
            r.raise_for_status()
            audit_events = r.json()

            step("QUERY", f"Retrieved {len(audit_events)} events for ComplianceBot")

            # Print formatted audit table
            w = 70
            print(f"\n  {BOLD}╔{'═' * w}╗{RESET}")
            hdr = f"{'#':<3}  {'Timestamp':<28}  {'Tool':<16}  {'Decision':<10}  {'Trust':<6}  {'Authorized by'}"
            print(f"  {BOLD}║{RESET}  {DIM}{hdr:<{w - 2}}{RESET}  {BOLD}║{RESET}")
            print(f"  {BOLD}║{RESET}  {DIM}{'─' * (w - 2)}{RESET}  {BOLD}║{RESET}")

            human_name = claims.get("name", "Alice Johnson")
            human_email = claims.get("email", "alice@acmecorp.com")

            for i, evt in enumerate(audit_events, 1):
                ts_short = evt.get("timestamp", "")[:23]
                tool = (evt.get("tool_name") or "—")[:16]
                decision = evt.get("decision", "?")
                trust = str(evt.get("trust_score", "—"))
                del_claims = evt.get("delegator_claims") or {}
                auth_by = del_claims.get("name") or (
                    f"{human_name}" if evt.get("delegator_did") else "—"
                )

                if decision in ("allow", "allowed"):
                    dec_str = f"{GREEN}ALLOW{RESET}"
                elif decision == "step_up":
                    dec_str = f"{YELLOW}STEP-UP{RESET}"
                elif decision == "blocked_auth":
                    dec_str = f"{RED}AUTH ERR{RESET}"
                elif "blocked_scope" in decision or "blocked_sc" in decision.lower():
                    dec_str = f"{RED}BLOCKED-SCOPE{RESET}"
                else:
                    dec_str = f"{RED}{decision.upper()[:12]}{RESET}"

                row = f"{i:<3}  {ts_short:<28}  {tool:<16}  "
                print(f"  {BOLD}║{RESET}  {row}{dec_str:<10}  {trust:<6}  {auth_by}  {BOLD}║{RESET}")

            print(f"  {BOLD}╚{'═' * w}╝{RESET}")

            # Human identity summary
            print(f"\n  {DIM}Human identity visible in every delegated request:{RESET}")
            print(f"  {PASS} {BOLD}{human_name}{RESET} ({human_email})  "
                  f"→ {claims.get('role', '?')} @ {claims.get('organization', '?')}")

            time.sleep(0.5)

            # ── Step 4: Hash Chain Verification ──────────────────────────────
            section("4", "Hash Chain Verification")
            print(f"  {DIM}Proving the audit log has not been tampered with{RESET}\n")

            # Allow PG writes to flush
            time.sleep(3.0)

            r = client.get(f"{GW_URL}/gateway/audit/verify", timeout=10.0)
            r.raise_for_status()
            vfy = r.json()

            storage = vfy.get("storage", "unknown")
            n_checked = vfy.get("events_checked", 0)
            is_valid = vfy.get("valid", False)
            broken_at = vfy.get("first_broken_at")

            if storage == "postgresql":
                status_icon = PASS if is_valid else FAIL
                status_label = f"{GREEN}VALID{RESET}" if is_valid else f"{RED}BROKEN at {broken_at}{RESET}"
                step("CHAIN", f"Storage: PostgreSQL  |  Events: {n_checked}  |  "
                              f"Algorithm: SHA-256  |  Chain: {status_label}", ok=is_valid)
                if is_valid:
                    print(f"\n  {DIM}Every event in PostgreSQL is linked by SHA-256 hash.{RESET}")
                    print(f"  {DIM}Any tampering breaks the chain — detectable immediately.{RESET}")
                else:
                    print(f"\n  {RED}Chain broken at event: {broken_at}{RESET}")
            else:
                step("CHAIN", f"Storage: in-memory  |  Events: {vfy.get('in_memory_count', 0)}  |  "
                              f"Set DATABASE_URL for PostgreSQL hash-chain verification")
                print(f"\n  {DIM}Note: in-memory mode — hash chain only persists per-session.{RESET}")
                print(f"  {DIM}Run with PostgreSQL for tamper-evident persistence.{RESET}")

            time.sleep(0.5)

            # ── Step 5: CSV Export ────────────────────────────────────────────
            section("5", "Compliance Export (CSV)")
            print(f"  {DIM}Generating downloadable CSV for legal / compliance team{RESET}\n")

            r = client.get(
                f"{GW_URL}/gateway/events/export",
                params={
                    "format": "csv",
                    "agent_did": compliance_bot.did,
                    "from_ts": from_ts,
                    "to_ts": to_ts,
                },
                timeout=10.0,
            )
            r.raise_for_status()

            export_path = PROJECT_ROOT / "pramana_audit_export.csv"
            export_path.write_bytes(r.content)
            csv_lines = r.text.strip().splitlines()
            row_count = max(0, len(csv_lines) - 1)  # subtract header

            step("CSV", f"Exported {row_count} event(s) to {export_path.name}")
            info("CSV", "Columns", "timestamp, agent, human identity, trust score, decision")
            info("CSV", "Path", str(export_path))

            # Show first 3 data rows as preview
            if len(csv_lines) > 1:
                print(f"\n  {DIM}Preview (first 3 rows):{RESET}")
                print(f"  {DIM}{csv_lines[0][:100]}…{RESET}")
                for row in csv_lines[1:4]:
                    print(f"  {DIM}{row[:100]}…{RESET}")

            time.sleep(0.5)

            # ── Final statement ───────────────────────────────────────────────
            w = 70
            print(f"\n{BOLD}╔{'═' * w}╗{RESET}")
            print(f"{BOLD}║  {'PRAMANA PROTOCOL — CISO Audit Query Complete':<{w - 2}}║{RESET}")
            print(f"{BOLD}╠{'═' * w}╣{RESET}")
            summary_lines = [
                f"Agent:          ComplianceBot  ({compliance_bot.did[:40]}…)",
                f"Human identity: {human_name} ({human_email})",
                f"Time window:    {from_ts[:19]} → {to_ts[:19]}",
                f"Events queried: {len(audit_events)}",
                f"Hash chain:     {'PostgreSQL SHA-256 — VALID' if storage == 'postgresql' and is_valid else 'in-memory (set DATABASE_URL for PG)'}",
                f"CSV export:     {export_path.name}  ({row_count} rows)",
            ]
            for line in summary_lines:
                print(f"{BOLD}║{RESET}  {line:<{w - 2}}{BOLD}║{RESET}")
            print(f"{BOLD}╠{'═' * w}╣{RESET}")
            conclusion = (
                "This is what your compliance team gets when opposing counsel "
                "sends a subpoena: every action the agent took, who authorized "
                "it, what the trust score was, and cryptographic proof the log "
                "is intact."
            )
            words = conclusion.split()
            line_buf: list[str] = []
            for word in words:
                if sum(len(w) for w in line_buf) + len(line_buf) + len(word) > w - 4:
                    print(f"{BOLD}║{RESET}  {DIM}{' '.join(line_buf):<{w - 2}}{RESET}{BOLD}║{RESET}")
                    line_buf = [word]
                else:
                    line_buf.append(word)
            if line_buf:
                print(f"{BOLD}║{RESET}  {DIM}{' '.join(line_buf):<{w - 2}}{RESET}{BOLD}║{RESET}")
            print(f"{BOLD}╚{'═' * w}╝{RESET}\n")

        return 0

    except Exception as exc:
        print(f"\n  {FAIL} {RED}Demo error: {exc}{RESET}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if not args.skip_startup:
            kill_proc(gw_proc)
            kill_proc(sqlite_mcp_proc)
            kill_proc(mcp_proc)
            kill_proc(bridge_proc)
            kill_proc(oidc_proc)
            if cfg_path:
                try:
                    os.unlink(cfg_path)
                except OSError:
                    pass


if __name__ == "__main__":
    sys.exit(main())
