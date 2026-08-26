"""Integration tests for the Trust Score API endpoints."""
from __future__ import annotations

import uuid

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_agent(client, authz_headers, name: str = None) -> dict:
    """Create an agent via the API and return the response JSON."""
    r = client.post(
        "/v1/agents",
        json={"name": name or f"test-agent-{uuid.uuid4().hex[:6]}"},
        headers=authz_headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


def _issue_vc(client, authz_headers, issuer_agent_id: str, subject_did: str,
              credential_type: str = "AgentCredential",
              subject_claims: dict | None = None) -> dict:
    """Issue a credential and return the response JSON."""
    body = {
        "issuer_agent_id": issuer_agent_id,
        "subject_did": subject_did,
        "credential_type": credential_type,
        "ttl_seconds": 3600,
    }
    if subject_claims:
        body["subject_claims"] = subject_claims
    r = client.post("/v1/credentials/issue", json=body, headers=authz_headers)
    assert r.status_code == 200, r.text
    return r.json()


def _revoke_vc(client, authz_headers, credential_id: str) -> None:
    r = client.post(f"/v1/credentials/{credential_id}/revoke", headers=authz_headers)
    assert r.status_code == 200, r.text


def _score(client, authz_headers, jwt: str) -> dict:
    r = client.post("/v1/trust/score", json={"jwt": jwt}, headers=authz_headers)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_valid_credential_high_score(client, authz_headers):
    """Fresh valid VC from new issuer -> total >= 60 (validity=25, issuer>=10, agent=10, depth=25)."""
    issuer = _create_agent(client, authz_headers, "issuer-high-score")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"

    vc = _issue_vc(client, authz_headers, issuer["id"], subject_did)
    result = _score(client, authz_headers, vc["jwt"])

    assert result["factors"]["credential_validity"] == 25
    # New issuer with 1 issued, 0 revoked: rate < 0.05 -> 25 (excellent)
    # OR if issuer happens to have no credentials at score time: 10 (neutral)
    # Either way it must be >= 10
    assert result["factors"]["issuer_reputation"] >= 10
    assert result["factors"]["agent_history"] == 10        # new agent — neutral
    assert result["factors"]["delegation_depth"] == 25     # direct credential
    assert result["total"] >= 60
    assert result["risk_level"] in ("low", "medium")
    assert "computed_at" in result


def test_revoked_credential_zero_validity(client, authz_headers):
    """Revoked VC -> factors['credential_validity'] == 0."""
    issuer = _create_agent(client, authz_headers, "issuer-revoke-test")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"

    vc = _issue_vc(client, authz_headers, issuer["id"], subject_did)
    _revoke_vc(client, authz_headers, vc["credential_id"])

    result = _score(client, authz_headers, vc["jwt"])

    assert result["factors"]["credential_validity"] == 0
    assert result["total"] < 75  # overall score must drop significantly


def test_issuer_with_no_revocations_scores_high(client, authz_headers):
    """Issuer with 10 issued VCs and 0 revocations -> issuer_reputation == 25."""
    issuer = _create_agent(client, authz_headers, "issuer-no-revocations")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"

    # Issue 10 credentials from the same issuer
    last_vc = None
    for _ in range(10):
        last_vc = _issue_vc(client, authz_headers, issuer["id"], subject_did)

    result = _score(client, authz_headers, last_vc["jwt"])

    assert result["factors"]["issuer_reputation"] == 25


def test_issuer_with_high_revocation_rate(client, authz_headers):
    """Issuer with 10 issued, 6 revoked -> revocation_rate=0.6 >= 0.5 -> issuer_reputation == 5."""
    issuer = _create_agent(client, authz_headers, "issuer-high-revocation")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"

    vcs = []
    for _ in range(10):
        vcs.append(_issue_vc(client, authz_headers, issuer["id"], subject_did))

    # Revoke 6
    for vc in vcs[:6]:
        _revoke_vc(client, authz_headers, vc["credential_id"])

    # Score the last non-revoked VC (index 9 — not revoked)
    result = _score(client, authz_headers, vcs[9]["jwt"])

    assert result["factors"]["issuer_reputation"] == 5


def test_agent_with_successful_history(client, authz_headers):
    """Agent with 10 successful verifications -> agent_history >= 20."""
    from core.trust_score import record_trust_event

    agent_did = f"did:key:z6Mk{uuid.uuid4().hex}"
    issuer = _create_agent(client, authz_headers, "issuer-for-good-agent")
    vc = _issue_vc(client, authz_headers, issuer["id"], agent_did)

    # Directly seed 10 success events for this agent
    for _ in range(10):
        record_trust_event(
            tenant_id="default",
            agent_did=agent_did,
            event_type="verification_success",
            credential_jti=vc["jti"],
            score_delta=70,
        )

    result = _score(client, authz_headers, vc["jwt"])

    # total >= 10 and success_rate >= 0.95 (all success) -> 25; at minimum >= 20
    assert result["factors"]["agent_history"] >= 20


def test_agent_with_mixed_history(client, authz_headers):
    """Agent with 5 success + 5 failures -> success_rate=0.50 -> agent_history == 10."""
    from core.trust_score import record_trust_event

    agent_did = f"did:key:z6Mk{uuid.uuid4().hex}"
    issuer = _create_agent(client, authz_headers, "issuer-for-mixed-agent")
    vc = _issue_vc(client, authz_headers, issuer["id"], agent_did)

    for _ in range(5):
        record_trust_event(
            tenant_id="default",
            agent_did=agent_did,
            event_type="verification_success",
            score_delta=70,
        )
    for _ in range(5):
        record_trust_event(
            tenant_id="default",
            agent_did=agent_did,
            event_type="verification_failure",
            score_delta=0,
        )

    result = _score(client, authz_headers, vc["jwt"])

    # success_rate == 0.50 -> score == 10
    assert result["factors"]["agent_history"] == 10


def test_deep_delegation_reduces_score(client, authz_headers):
    """VC credentialSubject with depth=3 -> delegation_depth == 10."""
    issuer = _create_agent(client, authz_headers, "issuer-delegation-depth")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"

    # Issue VC with depth=3 in credentialSubject
    vc = _issue_vc(
        client, authz_headers,
        issuer["id"], subject_did,
        subject_claims={"depth": 3, "delegatedAction": "purchase"},
    )

    result = _score(client, authz_headers, vc["jwt"])

    assert result["factors"]["delegation_depth"] == 10


def test_risk_level_thresholds(client, authz_headers):
    """Verify risk_level string is computed correctly from total score."""
    from core.trust_score import _risk_level

    assert _risk_level(80) == "low"
    assert _risk_level(75) == "low"
    assert _risk_level(74) == "medium"
    assert _risk_level(60) == "medium"
    assert _risk_level(50) == "medium"
    assert _risk_level(49) == "high"
    assert _risk_level(30) == "high"
    assert _risk_level(25) == "high"
    assert _risk_level(24) == "critical"
    assert _risk_level(15) == "critical"
    assert _risk_level(0) == "critical"


def test_trust_event_recorded(client, authz_headers):
    """POST /v1/trust/score records a trust_event row in the DB."""
    from core.db import db_session
    from models import TrustEvent

    issuer = _create_agent(client, authz_headers, "issuer-event-record")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"
    vc = _issue_vc(client, authz_headers, issuer["id"], subject_did)

    _score(client, authz_headers, vc["jwt"])

    with db_session() as db:
        event = (
            db.query(TrustEvent)
            .filter(TrustEvent.agent_did == subject_did)
            .first()
        )

    assert event is not None
    assert event.event_type == "verification_success"
    assert event.credential_jti == vc["jti"]
    assert event.score_delta >= 60
    assert event.tenant_id == "default"


def test_agent_profile_endpoint(client, authz_headers):
    """GET /v1/trust/agent/{did} returns correct aggregate profile."""
    from core.trust_score import record_trust_event
    import urllib.parse

    agent_did = f"did:key:z6Mk{uuid.uuid4().hex}"

    # Seed some events
    for _ in range(3):
        record_trust_event(
            tenant_id="default",
            agent_did=agent_did,
            event_type="verification_success",
            score_delta=70,
        )
    record_trust_event(
        tenant_id="default",
        agent_did=agent_did,
        event_type="verification_failure",
        score_delta=0,
    )

    encoded_did = urllib.parse.quote(agent_did, safe="")
    r = client.get(f"/v1/trust/agent/{encoded_did}", headers=authz_headers)
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["did"] == agent_did
    assert data["total_events"] == 4
    assert data["success_rate"] == pytest.approx(0.75, abs=0.01)
    assert data["average_score"] is not None
    assert data["last_scored_at"] is not None
    assert isinstance(data["history"], list)
    assert len(data["history"]) == 4

    # Verify history entry structure
    entry = data["history"][0]
    assert "event_type" in entry
    assert "created_at" in entry
    assert "score_delta" in entry
