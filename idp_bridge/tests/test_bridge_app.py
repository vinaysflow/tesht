"""Tests for the IdP Bridge FastAPI app endpoints."""
from __future__ import annotations

import pytest

import jwt as _jwt

from pramana.credentials import verify_vc
from pramana.identity import resolve_did_key


class TestHealth:
    def test_health_returns_200(self, fresh_app):
        r = fresh_app.get("/health")
        assert r.status_code == 200

    def test_health_includes_provider_count(self, fresh_app):
        data = fresh_app.get("/health").json()
        assert data["provider_count"] >= 1
        assert "mock_idp" in data["providers"]

    def test_health_includes_bridge_did(self, fresh_app):
        data = fresh_app.get("/health").json()
        assert data["bridge_did"].startswith("did:key:")


class TestAttest:
    def test_attest_creates_did(self, fresh_app, alice_token):
        r = fresh_app.post("/attest", json={"oidc_token": alice_token})
        assert r.status_code == 200
        data = r.json()
        assert data["did"].startswith("did:key:")
        assert data["created"] is True

    def test_attest_is_idempotent_same_did(self, fresh_app, alice_token):
        r1 = fresh_app.post("/attest", json={"oidc_token": alice_token})
        r2 = fresh_app.post("/attest", json={"oidc_token": alice_token})
        assert r1.status_code == r2.status_code == 200
        assert r1.json()["did"] == r2.json()["did"]
        assert r1.json()["created"] is True
        assert r2.json()["created"] is False

    def test_attest_vc_contains_enterprise_claims(self, fresh_app, alice_token):
        r = fresh_app.post("/attest", json={"oidc_token": alice_token})
        assert r.status_code == 200
        data = r.json()
        vc_jwt = data["credential"]
        payload = _jwt.decode(vc_jwt, options={"verify_signature": False})
        vc = payload.get("vc", {})
        subject_claims = vc.get("credentialSubject", {})
        assert subject_claims.get("name") == "Alice Johnson"
        assert subject_claims.get("email") == "alice@acmecorp.com"
        assert subject_claims.get("organization") == "Acme Corp"

    def test_attest_vc_contains_idp_provenance(self, fresh_app, alice_token):
        r = fresh_app.post("/attest", json={"oidc_token": alice_token})
        data = r.json()
        vc_jwt = data["credential"]
        payload = _jwt.decode(vc_jwt, options={"verify_signature": False})
        subject = payload.get("vc", {}).get("credentialSubject", {})
        assert "idp_issuer" in subject
        assert "idp_subject" in subject

    def test_attest_returns_correct_provider(self, fresh_app, alice_token):
        r = fresh_app.post("/attest", json={"oidc_token": alice_token})
        data = r.json()
        assert data["provider"] == "Mock IdP"
        assert data["provider_id"] == "mock_idp"

    def test_attest_with_untrusted_issuer_returns_401(self, fresh_app):
        import time
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        evil_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        evil_pem = evil_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        now = int(time.time())
        evil_token = _jwt.encode(
            {"iss": "https://evil.attacker.com", "sub": "evil-001",
             "aud": "pramana", "iat": now, "exp": now + 3600},
            evil_pem, algorithm="RS256",
        )
        r = fresh_app.post("/attest", json={"oidc_token": evil_token})
        assert r.status_code == 401
        assert "Untrusted" in r.json().get("detail", "")

    def test_attest_with_expired_token_returns_401(self, fresh_app, expired_token):
        r = fresh_app.post("/attest", json={"oidc_token": expired_token})
        assert r.status_code == 401

    def test_attest_vc_type_is_organizational_role(self, fresh_app, alice_token):
        r = fresh_app.post("/attest", json={"oidc_token": alice_token})
        vc_jwt = r.json()["credential"]
        payload = _jwt.decode(vc_jwt, options={"verify_signature": False})
        vc_types = payload.get("vc", {}).get("type", [])
        assert "OrganizationalRoleCredential" in vc_types


class TestBind:
    def test_bind_returns_both_vcs(self, fresh_app, alice_token):
        from pramana.identity import AgentIdentity
        agent = AgentIdentity.create("test-agent")
        r = fresh_app.post("/bind", json={
            "oidc_token": alice_token,
            "agent_did": agent.did,
            "scope": {"actions": ["read_data"], "max_amount": 1000, "currency": "USD"},
        })
        assert r.status_code == 200
        data = r.json()
        assert data["enterprise_vc"]
        assert data["delegation_vc"]
        assert data["agent_did"] == agent.did

    def test_bind_delegation_scope_matches_request(self, fresh_app, alice_token):
        from pramana.identity import AgentIdentity
        agent = AgentIdentity.create("scope-test-agent")
        scope = {"actions": ["read_data", "write_data"], "max_amount": 5000, "currency": "USD"}
        r = fresh_app.post("/bind", json={
            "oidc_token": alice_token,
            "agent_did": agent.did,
            "scope": scope,
        })
        assert r.status_code == 200
        data = r.json()
        assert set(data["effective_scope"]["actions"]) == set(scope["actions"])
        assert data["effective_scope"]["max_amount"] == 5000

    def test_bind_with_invalid_token_returns_401(self, fresh_app):
        from pramana.identity import AgentIdentity
        agent = AgentIdentity.create("bind-invalid-agent")
        r = fresh_app.post("/bind", json={
            "oidc_token": "not.a.valid.jwt.at.all",
            "agent_did": agent.did,
        })
        assert r.status_code == 401

    def test_bind_delegation_signed_by_human_did(self, fresh_app, alice_token):
        from pramana.identity import AgentIdentity
        agent = AgentIdentity.create("delegation-sig-test")
        r = fresh_app.post("/bind", json={
            "oidc_token": alice_token,
            "agent_did": agent.did,
        })
        assert r.status_code == 200
        data = r.json()
        # The delegation issuer should be the human's DID
        delegation_payload = _jwt.decode(
            data["delegation_vc"], options={"verify_signature": False}
        )
        assert delegation_payload.get("iss") == data["did"]
        assert delegation_payload.get("sub") == agent.did
