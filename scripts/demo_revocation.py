#!/usr/bin/env python3
"""
Pramana Protocol — Mid-Session Revocation Demo
================================================

Shows BitstringStatusList revocation wired end-to-end through the MCP Gateway:

  1. ProcurementBot authenticates and operates normally (trust 80+, all ALLOWED)
  2. CREDENTIAL REVOKED — one API call flips a bit in the bridge's status list
  3. ProcurementBot's very next request is REJECTED — zero latency between
     revocation and enforcement
  4. Audit trail shows the clean BEFORE / AFTER boundary with hash chain intact

Run:
    PYTHONPATH=".:sdk/python" python3 scripts/demo_revocation.py
"""
from __future__ import annotations

import base64
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


def revoke_banner() -> None:
    w = 68
    print(f"\n  {RED}{BOLD}╔{'═' * w}╗{RESET}")
    print(f"  {RED}{BOLD}║{'':^{w}}║{RESET}")
    line1 = "  ⚠  CREDENTIAL REVOKED  ⚠"
    print(f"  {RED}{BOLD}║{line1:^{w}}║{RESET}")
    line2 = "Simulating detected compromise / policy violation"
    print(f"  {RED}{BOLD}║{line2:^{w}}║{RESET}")
    print(f"  {RED}{BOLD}║{'':^{w}}║{RESET}")
    print(f"  {RED}{BOLD}╚{'═' * w}╝{RESET}")


def trust_bar(score: int) -> str:
    filled = int(score / 5)
    empty = 20 - filled
    color = GREEN if score >= 70 else (YELLOW if score >= 50 else RED)
    return f"{color}{'█' * filled}{'░' * empty}{RESET} {score:3d}/100"


def decision_label(status_code: int, body: dict) -> tuple[str, bool]:
    if status_code == 200:
        return f"{GREEN}ALLOWED{RESET}", True
    if status_code in (401, 403):
        err_msg = body.get("error", {}).get("message", "")
        if "revoked" in err_msg.lower():
            return f"{RED}BLOCKED (revoked){RESET}", False
        if "Step-up" in err_msg:
            return f"{YELLOW}STEP-UP{RESET}", False
        return f"{RED}BLOCKED{RESET}", False
    return f"{RED}ERROR {status_code}{RESET}", False


def _extract_jti(jwt_str: str) -> str:
    parts = jwt_str.split(".")
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    return payload.get("jti") or payload.get("id") or ""


# ── Service management ────────────────────────────────────────────────────────

def _write_demo_config() -> str:
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


# ── MCP call helper ───────────────────────────────────────────────────────────

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


def _get_agent_events(client: httpx.Client, agent_did: str) -> list[dict]:
    try:
        r = client.get(
            f"{GW_URL}/gateway/events",
            params={"agent_did": agent_did, "n": 50},
            timeout=5.0,
        )
        raw = r.json()
        return raw if isinstance(raw, list) else raw.get("events", [])
    except Exception:
        return []


def _get_all_recent_events(client: httpx.Client, n: int = 20) -> list[dict]:
    """Return all recent events (including blocked_auth where agent_did may be None)."""
    try:
        r = client.get(
            f"{GW_URL}/gateway/events",
            params={"n": n},
            timeout=5.0,
        )
        raw = r.json()
        return raw if isinstance(raw, list) else raw.get("events", [])
    except Exception:
        return []


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Pramana Mid-Session Revocation Demo")
    parser.add_argument("--skip-startup", action="store_true",
                        help="Skip service startup (assume services already running)")
    cli = parser.parse_args()
    skip_startup = cli.skip_startup

    banner("Pramana Protocol — Mid-Session Revocation Demo")
    print(f"  {DIM}Demonstrates: credential revoked → next request immediately rejected{RESET}")
    print(f"  {DIM}Zero latency between revocation and enforcement{RESET}")

    procs: list[subprocess.Popen] = []
    config_path: Optional[str] = None

    try:
        if not skip_startup:
            # ── Start services ────────────────────────────────────────────────────
            print(f"\n{BOLD}Starting services…{RESET}")
            config_path = _write_demo_config()

            oidc_proc = start_server("idp_bridge.mock_oidc_provider:app", OIDC_PORT)
            procs.append(oidc_proc)

            bridge_proc = start_server(
                "idp_bridge.app:app", BRIDGE_PORT,
                extra_env={
                    "IDP_BRIDGE_CONFIG": config_path,
                    "PRAMANA_CORS_ENABLED": "1",
                    "BRIDGE_PORT": str(BRIDGE_PORT),
                    "BRIDGE_STATUS_LIST_URL": f"http://127.0.0.1:{BRIDGE_PORT}/bridge/status-list",
                },
            )
            procs.append(bridge_proc)

            sqlite_proc = start_server("gateway.sqlite_mcp_server:app", SQLITE_MCP_PORT)
            procs.append(sqlite_proc)

            gw_proc = start_server(
                "gateway.app:app", GW_PORT,
                extra_env={"PRAMANA_CORS_ENABLED": "1"},
            )
            procs.append(gw_proc)
        else:
            print(f"\n{DIM}--skip-startup: using already-running services{RESET}")

        # ── Wait for health ───────────────────────────────────────────────────
        services = [
            ("Mock OIDC",  f"{OIDC_URL}/health"),
            ("IdP Bridge", f"{BRIDGE_URL}/health"),
            ("SQLite MCP", f"{SQLITE_MCP_URL}/health"),
            ("Gateway",    f"{GW_URL}/gateway/health"),
        ]
        all_up = True
        for name, url in services:
            ok = wait_healthy(url)
            step("SVC", f"{name:<14} {url}", ok)
            if not ok:
                all_up = False

        if not all_up:
            print(f"\n{RED}One or more services failed to start. Aborting.{RESET}")
            return

        with httpx.Client() as client:
            # ── Get gateway DID ───────────────────────────────────────────────
            gw_health = client.get(f"{GW_URL}/gateway/health", timeout=5.0).json()
            gateway_did = gw_health.get("gateway_did", "")
            info("GW", "Gateway DID", gateway_did[:52] + "...")

            # ── Step 1: Identity setup ────────────────────────────────────────
            section("1", "Identity Setup — ProcurementBot authenticates via Okta")
            print(f"  {DIM}Alice Johnson, Senior Buyer @ Acme Corp authenticates{RESET}\n")

            r = client.get(f"{OIDC_URL}/token?user=alice", timeout=5.0)
            r.raise_for_status()
            alice_token = r.json()["id_token"]
            step("IDP", "Alice authenticates via Acme Corp Okta (mock RS256)")

            bot = AgentIdentity.create("ProcurementBot")

            r = client.post(f"{BRIDGE_URL}/bind", json={
                "oidc_token": alice_token,
                "agent_did": bot.did,
                "scope": {
                    "actions": ["read_data", "write_data"],
                    "max_amount": 50000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": [],
                },
                "ttl_seconds": 3600,
            }, timeout=10.0)
            r.raise_for_status()
            bind = r.json()

            enterprise_vc = bind["enterprise_vc"]
            delegation_vc = bind["delegation_vc"]
            claims = bind["claims"]

            step("VC", "OrganizationalRoleCredential issued (with credentialStatus)")
            info("VC", "Name", claims.get("name", "?"))
            info("VC", "Org", claims.get("organization", "?"))
            step("DEL", "DelegationCredential issued (with credentialStatus)")

            # Extract delegation VC jti for later revocation
            del_jti = _extract_jti(delegation_vc)
            info("DEL", "Credential ID (jti)", del_jti[:40] + "...")

            # Verify status list is populated
            sl_r = client.get(f"{BRIDGE_URL}/bridge/status-list", timeout=5.0)
            sl_data = sl_r.json()
            step("SL", f"Status list initialised (list_id={sl_data['list_id'][:16]}...)")

            # Build agent VC
            bot_vc = issue_vc(
                issuer=bot,
                subject_did=bot.did,
                credential_type="AgentCredential",
                claims={
                    "agentName": "ProcurementBot",
                    "ownerOrg": claims.get("organization", "Acme Corp"),
                    "agentType": "LLM",
                    "purpose": "Procurement automation",
                },
            )

            # Build blended VP
            vp = create_blended_presentation(
                agent=bot,
                delegation_jwt=delegation_vc,
                delegator_identity_jwt=enterprise_vc,
                additional_credentials=[bot_vc],
                audience=gateway_did,
                ttl_seconds=3600,
            )
            step("VP", "Blended VP assembled (agent + delegation + enterprise identity)")

            # ── Step 2: Normal operation ──────────────────────────────────────
            section("2", "Normal Operation — Agent operates with valid credentials")
            print(f"  {DIM}ProcurementBot makes 3 requests. All should be ALLOWED.{RESET}\n")

            normal_calls = [
                ("query_database", {"sql": "SELECT id, name FROM products LIMIT 3"}, 10),
                ("insert_record",  {"table": "orders", "data": {"amount": 1500}}, 11),
                ("query_database", {"sql": "SELECT COUNT(*) FROM orders"}, 12),
            ]

            revocation_boundary_ts: Optional[str] = None
            trust_after_normal: int = 80

            for tool, args, req_id in normal_calls:
                status, body = mcp_call(client, vp, tool, arguments=args, req_id=req_id)
                label, ok = decision_label(status, body)
                step("GW", f"{tool:<18} → {label}", ok)

            time.sleep(0.4)
            events = _get_agent_events(client, bot.did)
            trust_scores = [e.get("trust_score", 0) for e in events if e.get("decision") == "allowed"]
            if trust_scores:
                trust_after_normal = trust_scores[-1]
            print(f"\n  {CYAN}Trust score after normal operation:{RESET}")
            print(f"  {trust_bar(trust_after_normal)}")
            print(f"\n  {BOLD}Agent operating normally. Trust score stable. Zero alerts.{RESET}")

            # ── Step 3: Revocation event ──────────────────────────────────────
            section("3", "Revocation Event — Security team detects compromise")
            print(f"  {DIM}Security alert: ProcurementBot credentials flagged{RESET}")
            print(f"  {DIM}Action: revoke delegation credential immediately{RESET}\n")

            time.sleep(0.5)
            revocation_boundary_ts = datetime.now(timezone.utc).isoformat()

            r = client.post(f"{BRIDGE_URL}/bridge/revoke", json={
                "credential_id": del_jti,
            }, timeout=5.0)
            r.raise_for_status()
            rev_result = r.json()

            revoke_banner()
            info("REV", "Credential ID", del_jti[:40] + "...")
            info("REV", "Status list index", str(rev_result.get("status_list_index")))
            info("REV", "Enforcement", "Instant — next request will be rejected")

            # Confirm the bit is set
            sl_r2 = client.get(f"{BRIDGE_URL}/bridge/status-list", timeout=5.0)
            sl_data2 = sl_r2.json()
            sl_bits = base64.urlsafe_b64decode(
                sl_data2["bitstring"] + "=" * ((4 - len(sl_data2["bitstring"]) % 4) % 4)
            )
            idx = rev_result["status_list_index"]
            bit_set = bool(sl_bits[idx // 8] & (1 << (idx % 8)))
            step("SL", f"Revocation bit confirmed set at index {idx}", bit_set)

            time.sleep(0.3)

            # ── Step 4: Post-revocation enforcement ───────────────────────────
            section("4", "Instant Enforcement — Same VP, same credentials, same agent")
            print(f"  {DIM}ProcurementBot makes another request with the SAME VP.{RESET}")
            print(f"  {DIM}The gateway fetches the status list and detects the revocation.{RESET}\n")

            post_rev_calls = [
                ("query_database", {"sql": "SELECT 1"}, 20),
                ("query_database", {"sql": "SELECT name FROM products LIMIT 1"}, 21),
            ]

            all_blocked = True
            for tool, args, req_id in post_rev_calls:
                status, body = mcp_call(client, vp, tool, arguments=args, req_id=req_id)
                label, ok = decision_label(status, body)
                step("GW", f"{tool:<18} → {label}", not ok)
                if ok:
                    all_blocked = False
                else:
                    err = body.get("error", {}).get("message", "")
                    info("GW", "Reason", err[:70])

            if all_blocked:
                print(f"\n  {BOLD}{RED}CONFIRMED: Agent immediately blocked after revocation.{RESET}")
                print(f"  {DIM}Zero latency between revocation and enforcement.{RESET}")
            else:
                print(f"\n  {WARN} Unexpected: some post-revocation requests were allowed")

            # ── Step 5: Audit visibility ──────────────────────────────────────
            section("5", "Audit Visibility — Before / After Revocation Boundary")
            print(f"  {DIM}Querying /gateway/events for ProcurementBot{RESET}\n")

            time.sleep(0.5)
            # Get all events (including blocked_auth where agent_did may be None)
            all_events = _get_all_recent_events(client, n=20)
            # Filter to bot's events or blocked_auth events that happened during demo
            relevant = [
                e for e in all_events
                if e.get("agent_did") == bot.did or e.get("decision") == "blocked_auth"
            ]

            if relevant:
                print(f"  {BOLD}{'#':<3} {'Tool':<20} {'Decision':<26} {'Trust':>5}{RESET}")
                print(f"  {'─' * 58}")

                revocation_shown = False
                for i, ev in enumerate(relevant[:12], 1):
                    tool = ev.get("tool_name") or ev.get("method", "—")
                    decision = ev.get("decision", "—")
                    trust = ev.get("trust_score", 0)
                    ts = ev.get("timestamp", "")

                    # Show the revocation boundary marker once before the first blocked event
                    if (
                        not revocation_shown
                        and revocation_boundary_ts
                        and ts >= revocation_boundary_ts
                        and decision != "allowed"
                    ):
                        print(f"\n  {RED}{'─ ' * 16}CREDENTIAL REVOKED {'─ ' * 6}{RESET}\n")
                        revocation_shown = True

                    d_color = GREEN if decision == "allowed" else RED
                    trust_color = GREEN if trust >= 70 else (YELLOW if trust >= 50 else RED)
                    print(f"  {i:<3} {tool:<20} {d_color}{decision:<26}{RESET} "
                          f"{trust_color}{trust:>5}{RESET}")

                print(f"  {'─' * 58}")
                info("AUDIT", "Events shown", str(len(relevant)))
            else:
                print(f"  {WARN} No events found")

            # Hash chain verification
            print(f"\n  {DIM}Verifying SHA-256 audit hash chain across the revocation boundary…{RESET}")
            time.sleep(1.0)
            try:
                r = client.get(f"{GW_URL}/gateway/audit/verify", timeout=10.0)
                verify = r.json()
                verified = verify.get("verified", verify.get("valid", False))
                storage = verify.get("storage", "postgresql")
                n_events = (
                    verify.get("events_verified")
                    or verify.get("in_memory_count")
                    or verify.get("events_checked")
                    or 0
                )
                if storage == "in-memory":
                    step("AUDIT", f"In-memory audit: {n_events} events captured", True)
                    info("AUDIT", "Note", "Run with DATABASE_URL for SHA-256 hash-chain verification")
                else:
                    step(
                        "AUDIT",
                        f"Hash chain: {'VERIFIED' if verified else 'BROKEN'} ({n_events} events)",
                        verified,
                    )
            except Exception as exc:
                step("AUDIT", f"Verification error: {exc}", False)

            # ── Summary ───────────────────────────────────────────────────────
            banner("Mid-Session Revocation — Summary")
            print(f"""
  {BOLD}What just happened:{RESET}

  {GREEN}1.{RESET} ProcurementBot received credentials with BitstringStatusListEntry
     └→ Enterprise VC + Delegation VC both include credentialStatus fields
     └→ Status list index allocated per credential at issuance time

  {GREEN}2.{RESET} Agent operated normally — 3 requests ALLOWED, trust stable at {trust_after_normal}

  {RED}3.{RESET} Security team revoked the delegation credential
     └→ Single API call: POST /bridge/revoke (credential_id = delegation jti)
     └→ Bit flipped in-memory — takes effect on the very next request

  {RED}4.{RESET} Agent's next request was IMMEDIATELY rejected
     └→ Gateway's status_checker fetched {BRIDGE_URL}/bridge/status-list
     └→ Decoded the bitstring, found the revocation bit set
     └→ verify_vc() returned reason="revoked" → 401 Unauthorized
     └→ No TTL expiry required — enforcement is instant

  {CYAN}5.{RESET} Audit trail shows the clean before/after boundary
     └→ Allowed events: normal operations
     └→ Blocked events: post-revocation attempts
     └→ Hash chain verifiable by compliance team

  {BOLD}The answer to "can you block a compromised agent instantly?"{RESET}
  {DIM}Yes. One API call. Zero waiting for token expiry.{RESET}
  {DIM}The audit trail proves exactly which actions occurred before{RESET}
  {DIM}and which were blocked after revocation.{RESET}
""")

    finally:
        if not skip_startup:
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
