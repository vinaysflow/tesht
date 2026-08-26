from __future__ import annotations

import secrets
import time
from typing import Any

import jwt

from core.settings import settings

DEMO_ISSUER = "tesht-demo"


def issue_demo_token(*, tenant_id: str, ttl_seconds: int) -> tuple[str, int]:
    now = int(time.time())
    exp = now + ttl_seconds
    payload: dict[str, Any] = {
        "iss": DEMO_ISSUER,
        "sub": "demo",
        "iat": now,
        "exp": exp,
        "tenant": tenant_id,
        # demo scopes — full access for interactive demo
        "scope": [
            "agents:create", "agents:read",
            "credentials:issue", "credentials:verify", "credentials:revoke",
            "delegations:verify", "delegations:read",
            "commerce:verify", "commerce:read",
            "trust:read", "compliance:read", "marketplace:read",
            "tenant:admin",
        ],
        "demo": True,
        "jti": secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, settings.demo_jwt_secret, algorithm="HS256")
    return token, exp


def verify_demo_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.demo_jwt_secret,
        algorithms=["HS256"],
        issuer=DEMO_ISSUER,
        options={"require": ["iss", "sub", "iat", "exp", "tenant"]},
    )
