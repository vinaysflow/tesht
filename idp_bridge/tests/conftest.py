"""Shared fixtures for IdP bridge tests."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from tesht.identity import AgentIdentity

from idp_bridge.config import IdPRegistryConfig, TrustedIdP
from idp_bridge.identity_store import HumanIdentityStore
from idp_bridge.validator import MultiIssuerOIDCValidator

# ── In-process RSA keypair for mock IdP ────────────────────────────────────

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_ISSUER = "https://mock-idp.tesht.local"


def make_id_token(
    user_data: dict[str, Any],
    sub: str,
    issuer: str = _ISSUER,
    audience: str = "tesht",
    exp_offset: int = 3600,
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "iat": now,
        "exp": now + exp_offset,
        **user_data,
    }
    pem = _PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem, algorithm="RS256")


def _jwks_callback(uri: str) -> jwt.PyJWKSet:
    """Return a PyJWKSet containing our test public key."""
    pub = _PUBLIC_KEY.public_numbers()
    import base64
    byte_length = (_PUBLIC_KEY.key_size + 7) // 8

    def b64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode()

    jwk_dict = {
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
        "n": b64url(pub.n), "e": base64.urlsafe_b64encode(pub.e.to_bytes(4, "big")).rstrip(b"=").decode(),
    }
    return jwt.PyJWKSet.from_dict({"keys": [jwk_dict]})


@pytest.fixture(scope="module")
def mock_idp_registry() -> IdPRegistryConfig:
    """Registry with a single mock_idp provider wired to our in-process key."""
    provider = TrustedIdP(
        name="Mock IdP",
        issuer=_ISSUER,
        jwks_uri="https://mock-idp.tesht.local/.well-known/jwks.json",
        audience="tesht",
        claim_mapping={
            "name": "name",
            "email": "email",
            "organization": "org",
            "department": "department",
            "role": "role",
        },
        default_credential_type="OrganizationalRoleCredential",
        allowed_algorithms=["RS256"],
    )
    return IdPRegistryConfig(providers={"mock_idp": provider})


@pytest.fixture(scope="module")
def validator_with_mock_key(mock_idp_registry) -> MultiIssuerOIDCValidator:
    """Validator whose PyJWKClient is pre-seeded with our test public key."""
    v = MultiIssuerOIDCValidator(mock_idp_registry)

    class _FakeClient:
        def get_signing_key_from_jwt(self, token: str):
            from unittest.mock import MagicMock
            m = MagicMock()
            m.key = _PUBLIC_KEY
            return m

    v._jwks_clients["mock_idp"] = _FakeClient()
    return v


@pytest.fixture(scope="module")
def alice_token() -> str:
    return make_id_token(
        {"name": "Alice Johnson", "email": "alice@acmecorp.com",
         "org": "Acme Corp", "department": "Procurement", "role": "Senior Buyer"},
        sub="okta-alice-001",
    )


@pytest.fixture(scope="module")
def hank_token() -> str:
    return make_id_token(
        {"name": "Hank Patel", "email": "hank@bigbank.com",
         "org": "BigBank Financial", "department": "Compliance", "role": "CCO"},
        sub="okta-hank-008",
    )


@pytest.fixture(scope="module")
def expired_token() -> str:
    return make_id_token(
        {"name": "Expired User", "email": "expired@test.com", "org": "TestCo"},
        sub="expired-001",
        exp_offset=-1,
    )


@pytest.fixture(scope="module")
def bridge_identity() -> AgentIdentity:
    return AgentIdentity.create("test-bridge")


@pytest.fixture(scope="function")
def fresh_app(mock_idp_registry, bridge_identity):
    """A TestClient wrapping the bridge app with all state pre-seeded.

    We bypass the lifespan by setting app.state directly before creating the
    client (TestClient with raise_server_exceptions=True skips lifespan when
    we don't use it as a context manager with ``__enter__``).
    """
    from idp_bridge.app import app as bridge_app

    # Wire state directly — mirrors what lifespan() would do but uses
    # in-process mock JWKS instead of a live HTTP endpoint
    validator = MultiIssuerOIDCValidator(mock_idp_registry)

    class _FakeClient:
        def get_signing_key_from_jwt(self, token: str):
            from unittest.mock import MagicMock
            m = MagicMock()
            m.key = _PUBLIC_KEY
            return m

    validator._jwks_clients["mock_idp"] = _FakeClient()

    bridge_app.state.registry = mock_idp_registry
    bridge_app.state.validator = validator
    bridge_app.state.identity_store = HumanIdentityStore()
    bridge_app.state.bridge_identity = bridge_identity

    # Use TestClient WITHOUT context manager so lifespan doesn't overwrite state
    client = TestClient(bridge_app, raise_server_exceptions=True)
    yield client
