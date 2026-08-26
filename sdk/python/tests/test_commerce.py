"""Tests for AP2 commerce mandate issuance and verification.

Uses did:key identities throughout — no server dependency.
"""
from __future__ import annotations

import time
import pytest
import jwt as pyjwt

from tesht.identity import AgentIdentity
from tesht.commerce import (
    issue_intent_mandate,
    issue_cart_mandate,
    verify_mandate,
    MandateVerification,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def delegator() -> AgentIdentity:
    return AgentIdentity.create("delegator-user", method="key")


@pytest.fixture
def agent() -> AgentIdentity:
    return AgentIdentity.create("shopping-agent", method="key")


@pytest.fixture
def sample_intent() -> dict:
    return {
        "description": "Find running shoes under $120",
        "max_amount": 12000,
        "currency": "USD",
        "merchants": ["*"],
        "categories": ["footwear"],
        "requires_refundability": True,
        "user_cart_confirmation_required": True,
    }


@pytest.fixture
def sample_cart() -> dict:
    return {
        "items": [
            {"name": "Nike Air Max", "sku": "NK-AM-001", "quantity": 1, "price": 8999}
        ],
        "total": {"currency": "USD", "value": 8999},
        "merchant_did": "did:web:merchant.example",
        "shipping_address_hash": "sha256-abc123",
        "payment_method_type": "CARD",
    }


@pytest.fixture
def intent_jwt(delegator: AgentIdentity, agent: AgentIdentity, sample_intent: dict) -> str:
    return issue_intent_mandate(delegator, agent.did, sample_intent)


# ---------------------------------------------------------------------------
# TestIntentMandate
# ---------------------------------------------------------------------------

class TestIntentMandate:
    def test_intent_mandate_structure(
        self, delegator: AgentIdentity, agent: AgentIdentity, sample_intent: dict
    ) -> None:
        """Issued intent mandate JWT has expected header, payload, and vc structure."""
        token = issue_intent_mandate(delegator, agent.did, sample_intent)
        header = pyjwt.get_unverified_header(token)
        payload = pyjwt.decode(token, options={"verify_signature": False})

        # JWT header
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "JWT"
        assert header["kid"] == delegator.kid

        # JWT claims
        assert payload["iss"] == delegator.did
        assert payload["sub"] == agent.did
        assert "jti" in payload

        # VC structure
        vc = payload["vc"]
        assert "AP2IntentMandate" in vc["type"]
        cs = vc["credentialSubject"]
        assert cs["max_amount"] == 12000
        assert cs["currency"] == "USD"
        assert cs["merchants"] == ["*"]
        assert cs["categories"] == ["footwear"]
        assert cs["delegatedBy"] == delegator.did
        assert cs["mandateType"] == "AP2IntentMandate"

    def test_intent_validation_errors(
        self, delegator: AgentIdentity, agent: AgentIdentity
    ) -> None:
        """Missing or invalid intent fields raise ValueError."""
        with pytest.raises(ValueError, match="max_amount"):
            issue_intent_mandate(delegator, agent.did, {"currency": "USD"})

        with pytest.raises(ValueError, match="positive"):
            issue_intent_mandate(delegator, agent.did, {"max_amount": 0, "currency": "USD"})

        with pytest.raises(ValueError, match="ISO 4217"):
            issue_intent_mandate(delegator, agent.did, {"max_amount": 100, "currency": "USDD"})

        with pytest.raises(ValueError, match="ISO 8601"):
            issue_intent_mandate(
                delegator, agent.did,
                {"max_amount": 100, "currency": "USD", "intent_expiry": "not-a-date"},
            )


# ---------------------------------------------------------------------------
# TestCartMandate
# ---------------------------------------------------------------------------

class TestCartMandate:
    def test_cart_mandate_references_intent(
        self,
        delegator: AgentIdentity,
        agent: AgentIdentity,
        sample_intent: dict,
        sample_cart: dict,
    ) -> None:
        """Cart mandate JWT claims contain parentIntentMandate field."""
        intent_jwt = issue_intent_mandate(delegator, agent.did, sample_intent)
        cart_jwt = issue_cart_mandate(delegator, agent.did, sample_cart, intent_jwt)

        payload = pyjwt.decode(cart_jwt, options={"verify_signature": False})
        vc = payload["vc"]
        assert "AP2CartMandate" in vc["type"]
        cs = vc["credentialSubject"]
        assert "parentIntentMandate" in cs
        assert cs["parentIntentMandate"] == intent_jwt

    def test_cart_within_budget(
        self,
        delegator: AgentIdentity,
        agent: AgentIdentity,
        sample_intent: dict,
        sample_cart: dict,
    ) -> None:
        """Cart total 8999 <= intent max 12000 → issues successfully."""
        intent_jwt = issue_intent_mandate(delegator, agent.did, sample_intent)
        # sample_cart total is 8999, intent max is 12000
        cart_jwt = issue_cart_mandate(delegator, agent.did, sample_cart, intent_jwt)
        assert cart_jwt.count(".") == 2  # valid JWT

    def test_cart_exceeds_budget(
        self,
        delegator: AgentIdentity,
        agent: AgentIdentity,
        sample_intent: dict,
    ) -> None:
        """Cart total 15000 > intent max 12000 → raises ValueError."""
        intent_jwt = issue_intent_mandate(delegator, agent.did, sample_intent)
        expensive_cart = {
            "total": {"currency": "USD", "value": 15000},
            "merchant_did": "did:web:merchant.example",
        }
        with pytest.raises(ValueError, match="exceeds"):
            issue_cart_mandate(delegator, agent.did, expensive_cart, intent_jwt)

    def test_cart_mandate_short_ttl(
        self,
        delegator: AgentIdentity,
        agent: AgentIdentity,
        sample_intent: dict,
        sample_cart: dict,
    ) -> None:
        """Default TTL for cart mandate is 300 seconds."""
        intent_jwt = issue_intent_mandate(delegator, agent.did, sample_intent)
        cart_jwt = issue_cart_mandate(delegator, agent.did, sample_cart, intent_jwt)
        payload = pyjwt.decode(cart_jwt, options={"verify_signature": False})
        assert "exp" in payload
        assert payload["exp"] - payload["iat"] == 300


# ---------------------------------------------------------------------------
# TestVerifyMandate
# ---------------------------------------------------------------------------

class TestVerifyMandate:
    def test_verify_intent_mandate(
        self, delegator: AgentIdentity, agent: AgentIdentity, intent_jwt: str
    ) -> None:
        """Verify a valid intent mandate."""
        result = verify_mandate(intent_jwt)
        assert result.verified is True
        assert result.mandate_type == "AP2IntentMandate"
        assert result.delegator_did == delegator.did
        assert result.agent_did == agent.did
        assert result.scope["max_amount"] == 12000
        assert result.scope["currency"] == "USD"
        assert result.reason is None

    def test_verify_cart_mandate(
        self,
        delegator: AgentIdentity,
        agent: AgentIdentity,
        intent_jwt: str,
        sample_cart: dict,
    ) -> None:
        """Verify a valid cart mandate with parent intent check."""
        cart_jwt = issue_cart_mandate(delegator, agent.did, sample_cart, intent_jwt)
        result = verify_mandate(cart_jwt, mandate_type="AP2CartMandate")
        assert result.verified is True
        assert result.mandate_type == "AP2CartMandate"
        assert result.delegator_did == delegator.did
        assert result.agent_did == agent.did
        assert result.reason is None

    def test_verify_wrong_type(
        self, delegator: AgentIdentity, agent: AgentIdentity, intent_jwt: str
    ) -> None:
        """Issuing intent mandate, verifying as cart → type mismatch."""
        result = verify_mandate(intent_jwt, mandate_type="AP2CartMandate")
        assert result.verified is False
        assert "mismatch" in (result.reason or "").lower()
        assert "AP2CartMandate" in (result.reason or "")
