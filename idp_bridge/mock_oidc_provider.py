"""
idp_bridge.mock_oidc_provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Minimal mock OIDC provider for demo and testing.

Generates a fresh RSA-2048 keypair at startup, publishes it at
``/.well-known/jwks.json``, and issues signed RS256 id_tokens for
pre-configured enterprise users.

Run standalone:
    uvicorn idp_bridge.mock_oidc_provider:app --host 0.0.0.0 --port 9200
"""
from __future__ import annotations

import base64
import os
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ISSUER = "https://mock-idp.pramana.local"
AUDIENCE = "pramana"

# ---------------------------------------------------------------------------
# Pre-configured demo users matching the synthetic data population
# ---------------------------------------------------------------------------
MOCK_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "sub": "okta-alice-001",
        "name": "Alice Johnson",
        "email": "alice@acmecorp.com",
        "org": "Acme Corp",
        "department": "Procurement",
        "role": "Senior Buyer",
    },
    "bob": {
        "sub": "okta-bob-002",
        "name": "Bob Martinez",
        "email": "bob@acmecorp.com",
        "org": "Acme Corp",
        "department": "Engineering",
        "role": "VP Engineering",
    },
    "hank": {
        "sub": "okta-hank-008",
        "name": "Hank Patel",
        "email": "hank@bigbank.com",
        "org": "BigBank Financial",
        "department": "Compliance",
        "role": "Chief Compliance Officer",
    },
    "karen": {
        "sub": "okta-karen-011",
        "name": "Karen Wu",
        "email": "karen@healthco.com",
        "org": "HealthCo",
        "department": "Medical",
        "role": "Chief Medical Officer",
    },
    "charlie": {
        "sub": "okta-charlie-003",
        "name": "Charlie Kim",
        "email": "charlie@techcorp.io",
        "org": "TechCorp",
        "department": "Security",
        "role": "CISO",
    },
}

# ---------------------------------------------------------------------------
# RSA keypair — generated once at import time so all tests share the same key
# ---------------------------------------------------------------------------
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_KID = f"mock-idp-key-{uuid.uuid4().hex[:8]}"


def _b64url(n: int, byte_length: int) -> str:
    return base64.urlsafe_b64encode(
        n.to_bytes(byte_length, "big")
    ).rstrip(b"=").decode("ascii")


def _build_jwk() -> dict[str, Any]:
    pub_numbers = _PUBLIC_KEY.public_key() if hasattr(_PUBLIC_KEY, "public_key") else _PUBLIC_KEY
    pub_numbers = _PUBLIC_KEY.public_numbers()
    byte_length = (_PUBLIC_KEY.key_size + 7) // 8
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": _KID,
        "n": _b64url(pub_numbers.n, byte_length),
        "e": _b64url(pub_numbers.e, 4),
    }


app = FastAPI(title="Mock OIDC Provider", version="1.0.0")

if os.getenv("PRAMANA_CORS_ENABLED", "").lower() in ("1", "true", "yes"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.get("/.well-known/jwks.json")
def jwks() -> dict[str, Any]:
    """Serve the public key set for RS256 verification."""
    return {"keys": [_build_jwk()]}


@app.get("/token")
def get_token(user: str = Query(..., description="User key (alice, bob, hank, karen, charlie)")) -> dict[str, str]:
    """Issue an RS256-signed OIDC id_token for a pre-configured demo user."""
    user_data = MOCK_USERS.get(user)
    if user_data is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown user: {user!r}. Available: {list(MOCK_USERS.keys())}",
        )

    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": user_data["sub"],
        "iat": now,
        "exp": now + 3600,
        "jti": uuid.uuid4().hex,
        **{k: v for k, v in user_data.items() if k != "sub"},
    }

    private_pem = _PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": _KID},
    )
    return {"id_token": token}


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "issuer": ISSUER,
        "users": list(MOCK_USERS.keys()),
        "kid": _KID,
    }


@app.get("/users")
def list_users() -> dict[str, Any]:
    """List all pre-configured demo users."""
    return {
        username: {k: v for k, v in data.items() if k != "sub"}
        for username, data in MOCK_USERS.items()
    }
