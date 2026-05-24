#!/usr/bin/env python3
"""
scripts/lib/format_output.py
─────────────────────────────
Shared formatted output helper for Pramana demo scripts.

Usage from bash (pipe JSON via stdin):
    echo "$CREDENTIAL_JSON" | python3 scripts/lib/format_output.py issued
    echo "$VERIFY_JSON"     | python3 scripts/lib/format_output.py verify
    echo "$REVOKE_JSON"     | python3 scripts/lib/format_output.py revoked

Usage from Python:
    from scripts.lib.format_output import format_credential_issued, ...
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_W = 14  # label column width


def _label(name: str) -> str:
    return f"{DIM}{name:<{_W}}{RESET}"


def _ts(epoch: Optional[int]) -> str:
    if not epoch:
        return "n/a"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short_did(did: str, chars: int = 20) -> str:
    """Abbreviate a long DID: keep prefix + last N chars."""
    if len(did) <= 40:
        return did
    prefix = did[:16]
    return f"{prefix}...{did[-chars:]}"


# ── decode VC-JWT without verifying signature ─────────────────────────────────

def _decode_jwt_payload(token: str) -> dict[str, Any]:
    import base64
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


# ── public API ────────────────────────────────────────────────────────────────

def format_credential_issued(json_str: str, elapsed_ms: Optional[float] = None) -> None:
    """
    Print a formatted CREDENTIAL ISSUED block.

    json_str: JSON from POST /v1/credentials/issue
    elapsed_ms: optional milliseconds to include in header
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        print(f"{RED}  [format_output] Could not parse issue response: {exc}{RESET}")
        return

    jwt_str   = data.get("jwt", "")
    payload   = _decode_jwt_payload(jwt_str)
    vc        = payload.get("vc", {})
    cs        = vc.get("credentialSubject", {})
    cr_status = vc.get("credentialStatus", {})
    vc_types  = [t for t in vc.get("type", []) if t != "VerifiableCredential"]
    cred_type = vc_types[0] if vc_types else data.get("credential_type", "VerifiableCredential")

    subject_did   = payload.get("sub", cs.get("id", ""))
    issuer_did    = payload.get("iss", "")
    exp_epoch     = payload.get("exp")
    iat_epoch     = payload.get("iat", int(time.time()))
    ttl_secs      = (exp_epoch - iat_epoch) if exp_epoch else None
    status_index  = data.get("status_list_index", cr_status.get("statusListIndex", "?"))

    # extra claims in credentialSubject (strip 'id')
    extra = {k: v for k, v in cs.items() if k != "id"}

    timing = f" ({elapsed_ms:.1f}ms)" if elapsed_ms is not None else ""

    print()
    print(f"  {BOLD}{GREEN}CREDENTIAL ISSUED{timing}{RESET}")
    print(f"  {_label('Subject:')}  {CYAN}{_short_did(subject_did)}{RESET}")
    print(f"  {_label('Issuer:')}   {DIM}{_short_did(issuer_did)}{RESET}")
    print(f"  {_label('Type:')}     {cred_type}")

    # print every extra claim in credentialSubject
    for key, val in extra.items():
        label = f"{key.replace('_', ' ').capitalize()}:"
        if isinstance(val, list):
            val_str = ", ".join(str(v) for v in val)
        elif isinstance(val, (int, float)) and key in ("max_amount",):
            val_str = f"${val:,}"
        else:
            val_str = str(val)
        print(f"  {_label(label)}  {val_str}")

    if ttl_secs is not None:
        print(f"  {_label('TTL:')}      {ttl_secs}s (expires {_ts(exp_epoch)})")
    else:
        print(f"  {_label('TTL:')}      no expiry")

    print(f"  {_label('Status:')}   {GREEN}ACTIVE{RESET} (bitstring index: {status_index})")
    print(f"  {_label('JTI:')}      {DIM}{payload.get('jti','?')}{RESET}")
    print()


def format_verification_result(
    json_str: str,
    elapsed_ms: Optional[float] = None,
    revoked_at: Optional[str] = None,
) -> None:
    """
    Print a formatted VERIFICATION PASSED / FAILED block.

    json_str: JSON from POST /v1/credentials/verify
    elapsed_ms: optional milliseconds
    revoked_at: optional ISO timestamp (from revocation response)
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        print(f"{RED}  [format_output] Could not parse verify response: {exc}{RESET}")
        return

    verified = data.get("verified", False)
    reason   = data.get("reason", "")
    payload  = data.get("payload", {})
    status   = data.get("status", {})

    exp_epoch    = payload.get("exp")
    now_epoch    = int(time.time())
    remaining    = (exp_epoch - now_epoch) if exp_epoch else None
    vc           = payload.get("vc", {})
    cr_status    = vc.get("credentialStatus", {})
    status_index = cr_status.get("statusListIndex", "?")

    timing = f" ({elapsed_ms:.1f}ms)" if elapsed_ms is not None else ""

    print()
    if verified:
        print(f"  {BOLD}{GREEN}VERIFICATION: PASSED{timing}{RESET}")
        print(f"  {_label('Signature:')}  Valid (Ed25519)")
        if remaining is not None:
            print(f"  {_label('Expiry:')}     Valid ({remaining}s remaining)")
        else:
            print(f"  {_label('Expiry:')}     No expiry set")
        print(f"  {_label('Revocation:')} Not revoked (bitstring index {status_index} = 0, no network call)")
    else:
        print(f"  {BOLD}{RED}VERIFICATION: FAILED{timing}{RESET}")
        if reason == "revoked":
            rev_at = revoked_at or _ts(now_epoch)
            print(f"  {_label('Reason:')}     Credential revoked (bitstring index {status_index} = 1)")
            print(f"  {_label('Revoked at:')} {rev_at}")
        elif reason == "expired":
            print(f"  {_label('Reason:')}     Credential expired")
        else:
            print(f"  {_label('Reason:')}     {reason or 'unknown'}")
    print()


def format_revocation(json_str: str) -> Optional[str]:
    """
    Print a formatted CREDENTIAL REVOKED block.
    Returns the revoked_at ISO timestamp string (for use in subsequent verify print).

    json_str: JSON from POST /v1/credentials/{id}/revoke
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        print(f"{RED}  [format_output] Could not parse revoke response: {exc}{RESET}")
        return None

    revoked     = data.get("revoked", False)
    cred_id     = data.get("credential_id", "?")
    revoked_at  = _ts(int(time.time()))

    print()
    if revoked:
        print(f"  {BOLD}{YELLOW}CREDENTIAL REVOKED{RESET}")
        print(f"  {_label('Credential:')} {DIM}{cred_id}{RESET}")
        print(f"  {_label('Revoked at:')} {revoked_at}")
        print(f"  {_label('Mechanism:')}  W3C Bitstring Status List (bit flip, no network broadcast)")
    else:
        print(f"  {RED}REVOCATION FAILED{RESET}")
        print(f"  {_label('Response:')}   {data}")
    print()
    return revoked_at


# ── CLI entrypoint ─────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: format_output.py <issued|verify|revoked> [elapsed_ms] [revoked_at]", file=sys.stderr)
        sys.exit(1)

    cmd       = sys.argv[1]
    elapsed   = float(sys.argv[2]) if len(sys.argv) > 2 else None
    revoked_at = sys.argv[3] if len(sys.argv) > 3 else None
    json_str  = sys.stdin.read()

    if cmd == "issued":
        format_credential_issued(json_str, elapsed_ms=elapsed)
    elif cmd == "verify":
        format_verification_result(json_str, elapsed_ms=elapsed, revoked_at=revoked_at)
    elif cmd == "revoked":
        format_revocation(json_str)
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
