"""
End-to-end tests for the IdP Bridge:
- Full flow: mock IdP token → attest → bind → blended VP → verify
- Enterprise identity visible in blended identity result
- Untrusted issuer blocked at bridge
"""
from __future__ import annotations

import pytest

import jwt as _jwt
from fastapi.testclient import TestClient

from tesht.credentials import (
    create_blended_presentation,
    issue_vc,
    verify_blended_presentation,
)
from tesht.delegation import verify_delegation_chain
from tesht.identity import AgentIdentity


class TestE2EFullFlow:
    """Full enterprise attestation → blended VP → verification."""

    def test_enterprise_login_to_blended_vp_verifies(
        self, fresh_app, alice_token, bridge_identity
    ):
        """Alice authenticates via OIDC → bind to agent → blended VP verifies."""
        # 1. Create agent identity
        agent = AgentIdentity.create("e2e-shopping-bot")

        # 2. Bind Alice to the agent via bridge
        r = fresh_app.post("/bind", json={
            "oidc_token": alice_token,
            "agent_did": agent.did,
            "scope": {
                "actions": ["read_data", "browse_products"],
                "max_amount": 10000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": [],
            },
        })
        assert r.status_code == 200
        bind_data = r.json()

        # 3. Verify enterprise VC was issued
        enterprise_vc_jwt = bind_data["enterprise_vc"]
        enterprise_payload = _jwt.decode(enterprise_vc_jwt, options={"verify_signature": False})
        vc_types = enterprise_payload.get("vc", {}).get("type", [])
        assert "OrganizationalRoleCredential" in vc_types

        # 4. Build blended VP with enterprise VC + delegation + agent VC
        agent_vc = issue_vc(
            issuer=agent,
            subject_did=agent.did,
            credential_type="AgentCredential",
            claims={"agentName": "E2EShoppingBot"},
        )
        gateway_identity = AgentIdentity.create("e2e-gateway")
        blended_vp = create_blended_presentation(
            agent=agent,
            delegation_jwt=bind_data["delegation_vc"],
            delegator_identity_jwt=enterprise_vc_jwt,
            additional_credentials=[agent_vc],
            audience=gateway_identity.did,
        )

        # 5. Verify blended VP
        from tesht.identity import resolve_did_key
        result = verify_blended_presentation(
            token=blended_vp,
            expected_audience=gateway_identity.did,
            resolver=resolve_did_key,
        )
        assert result.verified is True
        assert result.blended is True
        assert result.agent_did == agent.did

    def test_enterprise_identity_visible_in_blended_result(
        self, fresh_app, alice_token
    ):
        """delegator_claims should carry enterprise identity attributes."""
        agent = AgentIdentity.create("e2e-bot-claims-check")

        r = fresh_app.post("/bind", json={
            "oidc_token": alice_token,
            "agent_did": agent.did,
            "scope": {"actions": ["read_data"], "max_amount": 0, "currency": "USD"},
        })
        assert r.status_code == 200
        bind_data = r.json()

        agent_vc = issue_vc(
            issuer=agent, subject_did=agent.did,
            credential_type="AgentCredential",
            claims={"agentName": "ClaimsBot"},
        )
        verifier = AgentIdentity.create("e2e-verifier")
        blended_vp = create_blended_presentation(
            agent=agent,
            delegation_jwt=bind_data["delegation_vc"],
            delegator_identity_jwt=bind_data["enterprise_vc"],
            additional_credentials=[agent_vc],
            audience=verifier.did,
        )

        from tesht.identity import resolve_did_key
        result = verify_blended_presentation(
            token=blended_vp,
            expected_audience=verifier.did,
            resolver=resolve_did_key,
        )
        assert result.verified is True

        dc = result.delegator_claims
        assert dc.get("name") == "Alice Johnson"
        assert dc.get("email") == "alice@acmecorp.com"
        assert "idp_issuer" in dc

    def test_untrusted_issuer_blocked_at_bridge(self, fresh_app):
        """Forged OIDC token from unknown issuer → 401, no VC issued."""
        import time
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives import serialization as _ser

        evil_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        evil_pem = evil_key.private_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=_ser.NoEncryption(),
        )
        now = int(time.time())
        evil_token = _jwt.encode(
            {"iss": "https://evil.attacker.com", "sub": "evil-999",
             "aud": "tesht", "iat": now, "exp": now + 3600, "name": "Attacker"},
            evil_pem, algorithm="RS256",
        )

        r = fresh_app.post("/attest", json={"oidc_token": evil_token})
        assert r.status_code == 401
        assert "Untrusted" in r.json().get("detail", "")

        # Confirm no identity was created for the attacker
        r_health = fresh_app.get("/health")
        assert r_health.json()["identity_count"] == 0
