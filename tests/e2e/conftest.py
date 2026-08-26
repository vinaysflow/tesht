"""
Conftest for tests/e2e — ensures synthetic data is fresh before E2E tests run.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[1] / "synthetic" / "data"
REFRESH_SCRIPT = Path(__file__).resolve().parents[1] / "synthetic" / "refresh_jwts.py"


def _data_is_fresh() -> bool:
    """Return True if all credentials in the dataset have at least 60s remaining."""
    creds_file = DATA_DIR / "credentials.json"
    if not creds_file.exists():
        return False
    try:
        data = json.loads(creds_file.read_text())
    except (json.JSONDecodeError, OSError):
        return False

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    if str(sdk_path) not in sys.path:
        sys.path.insert(0, str(sdk_path))

    try:
        import jwt as pyjwt

        now = int(time.time())
        min_remaining = 9999999
        for cred in data.get("credentials", []):
            jwt_str = cred.get("jwt")
            if not jwt_str or cred.get("tampered") or cred.get("immature"):
                continue
            if cred.get("ttl_seconds") == 1 or cred.get("expired"):
                continue
            # These issuers were never stored in ecosystem.json, so refresh
            # leaves their JWTs as-is (already expired / future / revoked).
            if cred.get("issuer_name") in {
                "expired-issuer",
                "revoked-issuer",
                "future-issuer",
            }:
                continue
            try:
                payload = pyjwt.decode(jwt_str, options={"verify_signature": False})
                exp = payload.get("exp")
                if exp is not None:
                    remaining = exp - now
                    min_remaining = min(min_remaining, remaining)
            except Exception:
                pass
        return min_remaining > 60
    except ImportError:
        return False


@pytest.fixture(scope="session", autouse=True)
def ensure_fresh_synthetic_data():
    """Re-sign hand-crafted e2e JWTs if they are expired or close to expiring.

    Do not run generate.py here: it overwrites the fixture set these tests
    expect (mandate ids, expected_results.json, named agents).
    """
    if not _data_is_fresh():
        result = subprocess.run(
            [sys.executable, str(REFRESH_SCRIPT)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.fail(
                f"refresh_jwts.py failed:\n{result.stdout}\n{result.stderr}"
            )
