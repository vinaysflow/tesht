"""Tests for MultiIssuerOIDCValidator."""
from __future__ import annotations

import time

import pytest

from idp_bridge.config import IdPRegistryConfig, TrustedIdP
from idp_bridge.validator import MultiIssuerOIDCValidator, _map_claims
from idp_bridge.tests.conftest import make_id_token, _ISSUER


class TestMapClaims:
    def test_maps_present_claims(self):
        raw = {"name": "Alice", "email": "a@b.com", "org": "Acme"}
        mapping = {"name": "name", "email": "email", "organization": "org"}
        result = _map_claims(raw, mapping)
        assert result == {"name": "Alice", "email": "a@b.com", "organization": "Acme"}

    def test_skips_missing_claims(self):
        raw = {"name": "Alice"}
        mapping = {"name": "name", "organization": "org"}
        result = _map_claims(raw, mapping)
        assert result == {"name": "Alice"}

    def test_empty_mapping(self):
        assert _map_claims({"x": 1}, {}) == {}


class TestMultiIssuerOIDCValidator:
    def test_valid_token_accepted(self, validator_with_mock_key, alice_token):
        result = validator_with_mock_key.validate_token(alice_token)
        assert result.valid is True
        assert result.provider_id == "mock_idp"
        assert result.subject == "okta-alice-001"
        assert result.issuer == _ISSUER

    def test_claims_mapped_correctly(self, validator_with_mock_key, alice_token):
        result = validator_with_mock_key.validate_token(alice_token)
        assert result.valid
        m = result.mapped_claims
        assert m["name"] == "Alice Johnson"
        assert m["email"] == "alice@acmecorp.com"
        assert m["organization"] == "Acme Corp"
        assert m["department"] == "Procurement"
        assert m["role"] == "Senior Buyer"

    def test_untrusted_issuer_rejected(self, validator_with_mock_key):
        token = make_id_token(
            {"name": "Evil"}, sub="evil-001", issuer="https://evil.attacker.com"
        )
        result = validator_with_mock_key.validate_token(token)
        assert result.valid is False
        assert "Untrusted issuer" in (result.reason or "")

    def test_expired_token_rejected(self, validator_with_mock_key, expired_token):
        result = validator_with_mock_key.validate_token(expired_token)
        assert result.valid is False
        assert "expired" in (result.reason or "").lower()

    def test_malformed_token_rejected(self, validator_with_mock_key):
        result = validator_with_mock_key.validate_token("not.a.jwt")
        assert result.valid is False

    def test_different_users_have_different_subjects(
        self, validator_with_mock_key, alice_token, hank_token
    ):
        r_alice = validator_with_mock_key.validate_token(alice_token)
        r_hank = validator_with_mock_key.validate_token(hank_token)
        assert r_alice.valid and r_hank.valid
        assert r_alice.subject != r_hank.subject

    def test_raw_claims_accessible(self, validator_with_mock_key, alice_token):
        result = validator_with_mock_key.validate_token(alice_token)
        assert "iss" in result.raw_claims
        assert "exp" in result.raw_claims

    def test_provider_name_populated(self, validator_with_mock_key, alice_token):
        result = validator_with_mock_key.validate_token(alice_token)
        assert result.provider_name == "Mock IdP"

    def test_multiple_providers_distinguished(self):
        provider_a = TrustedIdP(
            name="ProvA", issuer="https://prov-a.example.com",
            jwks_uri="https://prov-a.example.com/jwks",
            claim_mapping={"name": "name"},
        )
        provider_b = TrustedIdP(
            name="ProvB", issuer="https://prov-b.example.com",
            jwks_uri="https://prov-b.example.com/jwks",
            claim_mapping={"email": "email"},
        )
        registry = IdPRegistryConfig(providers={"prov_a": provider_a, "prov_b": provider_b})
        v = MultiIssuerOIDCValidator(registry)

        # Untrusted issuer — no provider matches
        token = make_id_token({"name": "X"}, sub="x", issuer="https://prov-c.example.com")
        r = v.validate_token(token)
        assert r.valid is False
        assert "prov-c" in (r.reason or "")
