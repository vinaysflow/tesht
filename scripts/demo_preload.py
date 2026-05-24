#!/usr/bin/env python3
"""
scripts/demo_preload.py
~~~~~~~~~~~~~~~~~~~~~~~
Pre-populate the Pramana gateway with realistic traffic data then run all
4 demo scenarios on top, leaving services running for the React demo app.

Flow:
  1. Start all 5 services (unless --skip-startup)
  2. Run load generator: 500 events across 5 orgs
  3. Print pre-load summary
  4. Run CISO Audit, Multi-Hop Delegation, Revocation demo in sequence
  5. Print final summary + detection alert count
  6. Leave services running → React app at http://localhost:5052

Run:
    PYTHONPATH=".:sdk/python" python3 scripts/demo_preload.py
    PYTHONPATH=".:sdk/python" python3 scripts/demo_preload.py --skip-startup
    PYTHONPATH=".:sdk/python" python3 scripts/demo_preload.py --no-demo-scripts
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

# ── Ports ──────────────────────────────────────────────────────────────────────
OIDC_PORT       = 9200
BRIDGE_PORT     = 5053
MCP_PORT        = 9100
SQLITE_MCP_PORT = 9102
GW_PORT         = 5052

OIDC_URL       = f"http://127.0.0.1:{OIDC_PORT}"
BRIDGE_URL     = f"http://127.0.0.1:{BRIDGE_PORT}"
MCP_URL        = f"http://127.0.0.1:{MCP_PORT}"
SQLITE_MCP_URL = f"http://127.0.0.1:{SQLITE_MCP_PORT}"
GW_URL         = f"http://127.0.0.1:{GW_PORT}"

# ── Terminal colours ────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
DIM    = "\033[2m"

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
WARN = f"{YELLOW}⚠{RESET}"


def _p(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"  [{DIM}{ts}{RESET}] {msg}")


def _section(title: str) -> None:
    pad = max(0, 60 - len(title))
    print(f"\n{BOLD}{CYAN}━━━ {title} {'━' * pad}━━━{RESET}")


def _banner(text: str) -> None:
    w = 72
    print(f"\n{BOLD}{'═' * w}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{'═' * w}{RESET}")


# ── Service management ──────────────────────────────────────────────────────────

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


def start_server(module: str, port: int, extra_env: Optional[dict] = None) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
    env["PRAMANA_CORS_ENABLED"] = "true"
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


def kill_proc(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Gateway query helpers ───────────────────────────────────────────────────────

def _get_event_count() -> int:
    try:
        r = httpx.get(f"{GW_URL}/gateway/events?n=2000", timeout=10.0)
        if r.status_code == 200:
            return len(r.json())
    except Exception:
        pass
    return 0


def _get_agent_count() -> int:
    try:
        r = httpx.get(f"{GW_URL}/gateway/inventory", timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            known = data.get("known_agents", [])
            # known_agents is a list; total_agents may be an int summary field
            if isinstance(known, list):
                return len(known)
            return int(known)
    except Exception:
        pass
    return 0


def _get_detection_count() -> int:
    try:
        r = httpx.get(f"{GW_URL}/gateway/detections", timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            alerts = data.get("alerts", [])
            return len(alerts)
    except Exception:
        pass
    return 0


def _get_org_count() -> int:
    try:
        r = httpx.get(f"{GW_URL}/gateway/events?n=2000", timeout=10.0)
        if r.status_code == 200:
            events = r.json()
            orgs = set()
            for e in events:
                delegator = e.get("delegator_claims", {}) or {}
                org = delegator.get("organization") or delegator.get("org")
                if org:
                    orgs.add(org)
            return len(orgs) if orgs else 5  # default 5 orgs from load gen
    except Exception:
        pass
    return 5


def _verify_chain() -> dict:
    try:
        r = httpx.get(f"{GW_URL}/gateway/audit/verify", timeout=10.0)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ── Run sub-scripts ─────────────────────────────────────────────────────────────

def _run_script(script: str, extra_args: list[str] | None = None) -> int:
    """Run a demo script as a subprocess with --skip-startup."""
    cmd = [
        sys.executable, str(PROJECT_ROOT / "scripts" / script),
        "--skip-startup",
    ]
    if extra_args:
        cmd.extend(extra_args)
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
    result = subprocess.run(cmd, env=env)
    return result.returncode


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pre-populate Pramana gateway with 500+ events then run all 4 demo scenarios"
    )
    parser.add_argument(
        "--skip-startup", action="store_true",
        help="Skip service startup (assume services already running on default ports)",
    )
    parser.add_argument(
        "--no-demo-scripts", action="store_true",
        help="Skip the 4 demo scenarios — only run the load generator",
    )
    parser.add_argument(
        "--events", type=int, default=500,
        help="Number of load-generator events to pre-populate (default: 500)",
    )
    parser.add_argument(
        "--duration", type=int, default=120,
        help="Load generator max duration in seconds (default: 120)",
    )
    args = parser.parse_args()

    _banner("Pramana Protocol — Pre-load Script")
    print(f"  Target pre-load events:  {args.events}")
    print(f"  Duration cap:            {args.duration}s")
    print(f"  Skip service startup:    {args.skip_startup}")
    print(f"  Run demo scenarios:      {not args.no_demo_scripts}")

    procs: list[subprocess.Popen] = []
    cfg_path: Optional[str] = None

    try:
        # ── Phase 1: Start services ─────────────────────────────────────────────
        if not args.skip_startup:
            _section("Starting services")
            cfg_path = _write_bridge_config()

            procs = [
                start_server("idp_bridge.mock_oidc_provider:app", OIDC_PORT),
                start_server("idp_bridge.app:app", BRIDGE_PORT, {"IDP_BRIDGE_CONFIG": cfg_path}),
                start_server("gateway.mock_mcp_server:app", MCP_PORT),
                start_server("gateway.sqlite_mcp_server:app", SQLITE_MCP_PORT),
                start_server("gateway.app:app", GW_PORT),
            ]

            for label, url in [
                ("Mock OIDC",  f"{OIDC_URL}/health"),
                ("IdP Bridge", f"{BRIDGE_URL}/health"),
                ("Mock MCP",   f"{MCP_URL}/health"),
                ("SQLite MCP", f"{SQLITE_MCP_URL}/health"),
                ("Gateway",    f"{GW_URL}/gateway/health"),
            ]:
                if wait_healthy(url):
                    _p(f"{PASS} {label} healthy")
                else:
                    _p(f"{FAIL} {label} failed to start")
                    return 1
        else:
            _p("Skipping service startup (--skip-startup)")
            # Verify services are actually reachable
            for label, url in [
                ("Mock OIDC",  f"{OIDC_URL}/health"),
                ("IdP Bridge", f"{BRIDGE_URL}/health"),
                ("Gateway",    f"{GW_URL}/gateway/health"),
            ]:
                if wait_healthy(url, timeout=5.0):
                    _p(f"{PASS} {label} reachable")
                else:
                    _p(f"{WARN} {label} not reachable at {url} — services may need starting")

        # ── Phase 2: Load generator ─────────────────────────────────────────────
        _section(f"Pre-loading {args.events} events via load generator")

        load_env = os.environ.copy()
        load_env["PYTHONPATH"] = f"{PROJECT_ROOT / 'sdk' / 'python'}:{PROJECT_ROOT}"
        load_env["PYTHONUNBUFFERED"] = "1"

        load_cmd = [
            sys.executable, "-u",
            str(PROJECT_ROOT / "scripts" / "load_generator.py"),
            "--skip-startup",
            "--events", str(args.events),
            "--duration", str(args.duration),
        ]

        _p(f"Running: {' '.join(load_cmd[-5:])}")
        t0 = time.time()
        load_result = subprocess.run(load_cmd, env=load_env)
        load_elapsed = time.time() - t0

        if load_result.returncode == 0:
            _p(f"{PASS} Load generator completed in {load_elapsed:.0f}s")
        else:
            _p(f"{WARN} Load generator exited with code {load_result.returncode} (partial results may exist)")

        # ── Phase 3: Pre-load summary ───────────────────────────────────────────
        _section("Pre-load Summary")

        event_count = _get_event_count()
        agent_count = _get_agent_count()
        alert_count = _get_detection_count()
        org_count   = _get_org_count()
        chain_v     = _verify_chain()

        chain_storage = chain_v.get("storage", "in-memory")
        chain_count   = chain_v.get("events_checked") or chain_v.get("in_memory_count", event_count)
        chain_valid   = chain_v.get("valid", None)

        if chain_storage == "postgresql":
            chain_str = f"PostgreSQL — {chain_count} events — {'VALID' if chain_valid else 'BROKEN'}"
            chain_color = GREEN if chain_valid else RED
        else:
            chain_str = f"in-memory — {chain_count} events"
            chain_color = CYAN

        print(f"""
  {BOLD}Pre-loaded {event_count} events from {agent_count} agents across {org_count} orgs.{RESET}
  {BOLD}{alert_count} detection alerts.{RESET}
  Hash chain: {chain_color}{chain_str}{RESET}
""")

        if event_count < 100:
            _p(f"{WARN} Only {event_count} events loaded — load generator may have had issues")

        # ── Phase 4: Demo scenarios ─────────────────────────────────────────────
        if not args.no_demo_scripts:
            _section("Running demo scenarios on top of pre-loaded data")

            demo_scripts = [
                ("demo_ciso_audit.py",       "CISO Audit Query"),
                ("demo_delegation_chain.py", "Multi-Hop Delegation"),
                ("demo_revocation.py",       "Mid-Session Revocation"),
            ]

            demo_results: dict[str, bool] = {}
            for script, label in demo_scripts:
                _section(f"Demo: {label}")
                rc = _run_script(script)
                demo_results[label] = rc == 0
                if rc == 0:
                    _p(f"{PASS} {label} completed")
                else:
                    _p(f"{WARN} {label} exited with code {rc}")

            # Detection summary after all demos
            _section("Detection Alerts (after all scenarios)")
            try:
                r = httpx.get(f"{GW_URL}/gateway/detections", timeout=5.0)
                if r.status_code == 200:
                    data = r.json()
                    alerts = data.get("alerts", [])
                    fleet  = data.get("fleet", {})
                    print(f"  Total alerts:    {len(alerts)}")
                    print(f"  Fleet agents:    {fleet.get('total_agents', '?')}")
                    print(f"  Shadow attempts: {fleet.get('shadow_attempts', '?')}")
                    # Print top 5 alerts
                    for a in alerts[:5]:
                        sev = a.get("severity", "?")
                        color = RED if sev == "critical" else YELLOW
                        print(f"  {color}[{sev}]{RESET}  {a.get('title', '?')}")
            except Exception as exc:
                _p(f"{WARN} Could not fetch detections: {exc}")

        # ── Phase 5: Final summary ──────────────────────────────────────────────
        _section("Final State")

        final_events = _get_event_count()
        final_alerts = _get_detection_count()
        final_chain  = _verify_chain()

        final_storage = final_chain.get("storage", "in-memory")
        final_count   = final_chain.get("events_checked") or final_chain.get("in_memory_count", final_events)
        final_valid   = final_chain.get("valid", None)

        if final_storage == "postgresql":
            final_chain_str = f"PostgreSQL — {final_count} events — {'VALID ✓' if final_valid else 'BROKEN ✗'}"
            fcolor = GREEN if final_valid else RED
        else:
            final_chain_str = f"in-memory — {final_count} events"
            fcolor = CYAN

        print(f"""
  {BOLD}Total audit events:   {final_events}{RESET}
  {BOLD}Detection alerts:     {final_alerts}{RESET}
  Hash chain:           {fcolor}{final_chain_str}{RESET}
""")

        if not args.no_demo_scripts:
            all_passed = all(demo_results.values())
            passed_count = sum(demo_results.values())
            total_count = len(demo_results)
            status = f"{GREEN}{passed_count}/{total_count} passed{RESET}" if all_passed else f"{YELLOW}{passed_count}/{total_count} passed{RESET}"
            print(f"  Demo scenarios:       {status}")

        print(f"""
  {BOLD}{GREEN}Services are running and ready for the React demo app.{RESET}

  React app:    {CYAN}http://localhost:5174{RESET}  (or wherever Vite is running)
  Gateway API:  {CYAN}http://localhost:{GW_PORT}{RESET}

  The React app will auto-populate with the {final_events} pre-loaded events.
  Press Ctrl+C to stop services.
""")

        # Keep services running — wait for Ctrl+C
        if not args.skip_startup and procs:
            print(f"  {DIM}Waiting for Ctrl+C to stop services…{RESET}")
            try:
                signal.pause()
            except (KeyboardInterrupt, AttributeError):
                pass

        return 0

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Interrupted by user{RESET}")
        return 0

    finally:
        # Only kill services if we started them
        if not args.skip_startup and procs:
            _section("Shutting down services")
            for p in reversed(procs):
                kill_proc(p)
            if cfg_path:
                try:
                    os.unlink(cfg_path)
                except OSError:
                    pass
            _p(f"{PASS} All services stopped")


if __name__ == "__main__":
    sys.exit(main())
