#!/usr/bin/env python3
"""Re-sign the hand-crafted e2e fixtures so committed JWTs stay valid.

The E2E suite in tests/e2e/ is written against ecosystem.json,
expected_results.json, and delegation_chains.json. tests/synthetic/generate.py
emits a different dataset (no mandate ids, no expected_results) and must not
overwrite these files.

This script keeps agent identities and JTIs stable, and only refreshes
iat/exp (and nested parent JWTs) using the private keys already stored in
ecosystem.json.
"""
from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path
from typing import Any, Literal

import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from tesht.identity import AgentIdentity

DATA_DIR = Path(__file__).parent / "data"
TTL_SECONDS = 365 * 24 * 3600
JWT_FIELDS = ("jwt", "intent_jwt", "cart_jwt")
NESTED_CLAIM_KEYS = ("parentIntentMandate", "parentDelegation")

ResignMode = Literal["fresh", "expired", "immature"]


def _load_identities() -> dict[str, AgentIdentity]:
    ecosystem = json.loads((DATA_DIR / "ecosystem.json").read_text())
    identities: dict[str, AgentIdentity] = {}
    for agent in ecosystem["agents"]:
        identity = AgentIdentity.from_dict(agent["identity_dict"])
        identities[identity.did] = identity
    return identities


def _valid_from(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def resign_token(
    token: str,
    identities: dict[str, AgentIdentity],
    mode: ResignMode,
    now: int,
    memo: dict[tuple[str, ResignMode], str],
) -> str:
    cached = memo.get((token, mode))
    if cached is not None:
        return cached

    payload = copy.deepcopy(
        pyjwt.decode(token, options={"verify_signature": False})
    )
    header = pyjwt.get_unverified_header(token)
    issuer_did = payload.get("iss", "")
    issuer = identities.get(issuer_did)
    if issuer is None:
        # Ephemeral issuers (expired/future/revoked fixtures) were never stored
        # in ecosystem.json. Leave those tokens as-is.
        memo[(token, mode)] = token
        print(f"[refresh] skip (no issuer key): {issuer_did}")
        return token

    vc = payload.get("vc") or {}
    subject = vc.get("credentialSubject") or {}
    for key in NESTED_CLAIM_KEYS:
        nested = subject.get(key)
        if isinstance(nested, str) and nested.count(".") == 2:
            refreshed = resign_token(nested, identities, mode, now, memo)
            if refreshed != nested:
                subject[key] = refreshed

    if mode == "expired":
        iat = now - 3600
        exp = now - 60
        payload.pop("nbf", None)
    elif mode == "immature":
        iat = now + 3600
        exp = now + 7200
        payload["nbf"] = iat
    else:
        iat = now
        exp = now + TTL_SECONDS
        payload.pop("nbf", None)

    payload["iat"] = iat
    payload["exp"] = exp
    if "validFrom" in vc:
        vc["validFrom"] = _valid_from(iat)

    new_token = pyjwt.encode(
        payload,
        key=issuer.private_key,
        algorithm="EdDSA",
        headers={"kid": header.get("kid") or issuer.kid, "typ": "JWT"},
    )
    memo[(token, mode)] = new_token
    return new_token


def _mode_for(entry: dict[str, Any]) -> ResignMode | None:
    if entry.get("tampered"):
        return None
    if entry.get("immature"):
        return "immature"
    if entry.get("expired") or entry.get("ttl_seconds") == 1:
        return "expired"
    return "fresh"


def refresh_tree(
    obj: Any,
    identities: dict[str, AgentIdentity],
    now: int,
    memo: dict[tuple[str, ResignMode], str],
    inherited_mode: ResignMode | None = "fresh",
) -> None:
    if isinstance(obj, list):
        for item in obj:
            refresh_tree(item, identities, now, memo, inherited_mode)
        return
    if not isinstance(obj, dict):
        return

    mode = _mode_for(obj)
    if mode is None and obj.get("tampered"):
        for value in obj.values():
            refresh_tree(value, identities, now, memo, None)
        return
    active_mode = mode if mode is not None else inherited_mode

    for key, value in obj.items():
        if key in JWT_FIELDS and isinstance(value, str) and active_mode is not None:
            obj[key] = resign_token(value, identities, active_mode, now, memo)
        elif isinstance(value, (dict, list)):
            refresh_tree(value, identities, now, memo, active_mode)


def _rewrite(filename: str, identities: dict[str, AgentIdentity], now: int, memo) -> None:
    path = DATA_DIR / filename
    data = json.loads(path.read_text())
    refresh_tree(data, identities, now, memo)
    path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"[refresh] wrote {path}")


def main() -> None:
    identities = _load_identities()
    now = int(time.time())
    memo: dict[tuple[str, ResignMode], str] = {}
    for filename in (
        "credentials.json",
        "mandates.json",
        "delegation_chains.json",
        "scenarios.json",
    ):
        _rewrite(filename, identities, now, memo)
    print(f"[refresh] re-signed {len(memo)} tokens")


if __name__ == "__main__":
    main()
