import base64
import os
import sys
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk_from_public_key(pub, kid: str) -> dict:
    nums = pub.public_numbers()
    n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64u(n),
        "e": _b64u(e),
    }


def _issue_rs256(private_key, *, issuer: str, audience: str, scopes: list[str], groups: list[str]) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "user-123",
        "iat": now,
        "exp": now + 3600,
        # Keycloak-ish
        "realm_access": {"roles": scopes},
        "groups": groups,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-kid"})


def test_oidc_mode_enforces_token_and_scopes(tmp_path):
    # Snapshot global interpreter state
    orig_env = os.environ.copy()
    orig_modules = sys.modules.copy()
    orig_sys_path = list(sys.path)

    try:
        # Generate RSA keypair and JWKS
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = key.public_key()
        jwks = {"keys": [_jwk_from_public_key(pub, kid="test-kid")]}

        db_file = tmp_path / "oidc.db"
        os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

        os.environ["AUTH_MODE"] = "oidc"
        os.environ["OIDC_ISSUER"] = "https://example-issuer/realms/tesht"
        os.environ["OIDC_AUDIENCE"] = "tesht-api"
        os.environ["OIDC_JWKS_JSON"] = __import__("json").dumps(jwks)

        # Reload backend
        for name in list(sys.modules.keys()):
            if name == "main" or name.startswith("core.") or name == "core" or name.startswith("models.") or name == "models" or name.startswith("api.") or name == "api":
                del sys.modules[name]

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

        import main  # noqa

        with TestClient(main.app) as c:
            # Missing token -> 401
            r0 = c.post("/v1/agents", json={"name": "x"})
            assert r0.status_code == 401

            # Valid token but missing scope -> 403
            t1 = _issue_rs256(
                key,
                issuer=os.environ["OIDC_ISSUER"],
                audience=os.environ["OIDC_AUDIENCE"],
                scopes=["credentials:issue"],
                groups=["/tenants/demo"],
            )
            r1 = c.post("/v1/agents", json={"name": "x"}, headers={"Authorization": f"Bearer {t1}"})
            assert r1.status_code == 403

            # Valid token + required scope -> 200
            t2 = _issue_rs256(
                key,
                issuer=os.environ["OIDC_ISSUER"],
                audience=os.environ["OIDC_AUDIENCE"],
                scopes=["agents:create"],
                groups=["/tenants/demo"],
            )
            r2 = c.post("/v1/agents", json={"name": "ok"}, headers={"Authorization": f"Bearer {t2}"})
            assert r2.status_code == 200

    finally:
        os.environ.clear()
        os.environ.update(orig_env)
        sys.modules.clear()
        sys.modules.update(orig_modules)
        sys.path[:] = orig_sys_path
