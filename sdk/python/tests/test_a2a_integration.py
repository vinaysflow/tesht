"""
Tests for tesht.integrations.a2a — A2A Agent Card integration.

6 tests matching the spec:
  1. test_extend_card_adds_tesht_section
  2. test_extend_card_preserves_existing
  3. test_extend_card_adds_security_scheme
  4. test_verify_card_did_key
  5. test_verify_card_missing_tesht
  6. test_task_token_structure
"""
import jwt as pyjwt
import pytest

from tesht.identity import AgentIdentity
from tesht.integrations.a2a import (
    create_a2a_task_token,
    extend_agent_card,
    verify_agent_card_identity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CARD: dict = {
    "name": "Shopping Assistant",
    "description": "Finds and purchases products",
    "url": "https://agent.example.com",
    "version": "1.0",
    "capabilities": {"streaming": True, "pushNotifications": True},
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
    "skills": [
        {"id": "product-search", "name": "Product Search"},
        {"id": "checkout", "name": "Checkout"},
    ],
    "securitySchemes": {
        "bearer": {"type": "http", "scheme": "bearer"},
    },
}


@pytest.fixture()
def identity() -> AgentIdentity:
    return AgentIdentity.create("test-agent")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_extend_card_adds_tesht_section(identity: AgentIdentity) -> None:
    """Card has 'tesht' with did, kid, credentialTypes."""
    extended = extend_agent_card(SAMPLE_CARD, identity)

    assert "tesht" in extended
    p = extended["tesht"]
    assert p["did"] == identity.did
    assert p["kid"] == identity.kid
    assert isinstance(p["credentialTypes"], list)
    assert "AgentCredential" in p["credentialTypes"]
    assert p["trustScore"] is None


def test_extend_card_preserves_existing(identity: AgentIdentity) -> None:
    """Original card is not mutated; existing fields intact in result."""
    original_name = SAMPLE_CARD["name"]
    original_skills_count = len(SAMPLE_CARD["skills"])

    extended = extend_agent_card(SAMPLE_CARD, identity)

    # Original dict untouched
    assert "tesht" not in SAMPLE_CARD
    assert SAMPLE_CARD["name"] == original_name
    assert len(SAMPLE_CARD["skills"]) == original_skills_count

    # Extended copy keeps originals
    assert extended["name"] == original_name
    assert len(extended["skills"]) == original_skills_count
    assert extended["url"] == "https://agent.example.com"


def test_extend_card_adds_security_scheme(identity: AgentIdentity) -> None:
    """securitySchemes has 'tesht-vp' entry with correct shape."""
    extended = extend_agent_card(SAMPLE_CARD, identity)

    schemes = extended["securitySchemes"]
    assert "tesht-vp" in schemes

    vp_scheme = schemes["tesht-vp"]
    assert vp_scheme["type"] == "http"
    assert vp_scheme["scheme"] == "bearer"
    assert "description" in vp_scheme

    # Original bearer scheme still present
    assert "bearer" in schemes


def test_verify_card_did_key(identity: AgentIdentity) -> None:
    """Card with did:key identity verifies successfully."""
    extended = extend_agent_card(SAMPLE_CARD, identity)
    result = verify_agent_card_identity(extended)

    assert result.verified is True
    assert result.did == identity.did
    assert result.reason is None


def test_verify_card_missing_tesht() -> None:
    """Card without 'tesht' section fails with appropriate reason."""
    result = verify_agent_card_identity(SAMPLE_CARD)

    assert result.verified is False
    assert result.reason == "No tesht section"


def test_task_token_structure(identity: AgentIdentity) -> None:
    """Decode token; verify iss, aud, task_id, purpose, exp within 5 min of iat."""
    target_did = "did:key:z6MkTargetAgent"
    task_id = "task-abc-123"

    token = create_a2a_task_token(identity, target_did, task_id)

    # Decode without signature verification to inspect claims
    payload = pyjwt.decode(token, options={"verify_signature": False})

    assert payload["iss"] == identity.did
    assert payload["aud"] == target_did
    assert payload["task_id"] == task_id
    assert payload["purpose"] == "a2a_task"

    # exp must be exactly 300 seconds (5 min) after iat
    assert payload["exp"] - payload["iat"] == 300
