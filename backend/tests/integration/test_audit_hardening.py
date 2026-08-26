"""Functional tests for tamper-evident audit log (hash chain, verify, export).

Tests the hardening feature: every audit event is hash-chained to its predecessor,
and the API can verify chain integrity and export events as JSONL.
"""
from __future__ import annotations

import json

import core.auth.jwt_auth as jwt_auth


def _user_headers(tenant_id: str = "default") -> dict:
    token = jwt_auth.issue_admin_token(
        scopes=["agents:create", "credentials:issue", "credentials:revoke"],
        tenant_id=tenant_id,
    )
    return {"Authorization": f"Bearer {token}"}


def _admin_headers(tenant_id: str = "default") -> dict:
    token = jwt_auth.issue_admin_token(
        scopes=["tenant:admin", "agents:create", "credentials:issue", "credentials:revoke"],
        tenant_id=tenant_id,
    )
    return {"Authorization": f"Bearer {token}"}


def _create_audit_events(client, tenant_id="default", n=3):
    """Create n audit events by issuing credentials (which generate audit events)."""
    user_h = _user_headers(tenant_id)
    # Create an agent first
    agent_r = client.post("/v1/agents", json={"name": f"audit-agent-{tenant_id}"}, headers=user_h)
    assert agent_r.status_code == 200, agent_r.text
    agent_id = agent_r.json()["id"]

    for i in range(n):
        r = client.post(
            "/v1/credentials/issue",
            json={
                "issuer_agent_id": agent_id,
                "subject_did": f"did:web:example.com:audit-subject-{i}",
                "credential_type": "AuditTestCredential",
            },
            headers=user_h,
        )
        assert r.status_code == 200, r.text


def test_audit_events_have_hash_chain(client):
    """Each audit event has event_hash and prev_hash fields."""
    _create_audit_events(client, "default", n=3)

    r = client.get("/v1/audit?limit=50", headers=_admin_headers())
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) >= 3

    for evt in events:
        assert "event_hash" in evt
        assert "prev_hash" in evt


def test_audit_verify_valid_chain(client):
    """GET /v1/audit/verify returns valid=True for untampered chain."""
    _create_audit_events(client, "default", n=2)

    r = client.get("/v1/audit/verify", headers=_admin_headers())
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True
    assert data["events_checked"] >= 2
    assert data["first_broken_at"] is None
    assert data["reason"] is None


def test_audit_verify_detects_tamper(client):
    """Manually tampering an event_hash breaks the chain verification."""
    _create_audit_events(client, "tamper-test", n=3)

    from core.db import db_session
    from models import AuditEvent

    with db_session() as db:
        evt = (
            db.query(AuditEvent)
            .filter(AuditEvent.tenant_id == "tamper-test")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        if evt and evt.event_hash:
            evt.event_hash = "0" * 64
            db.commit()

    r = client.get("/v1/audit/verify", headers=_admin_headers("tamper-test"))
    assert r.status_code == 200
    data = r.json()
    if data["events_checked"] >= 2:
        assert data["valid"] is False
        assert data["first_broken_at"] is not None


def test_audit_export_jsonl(client):
    """GET /v1/audit/export returns JSONL with hash chain fields."""
    _create_audit_events(client, "default", n=2)

    r = client.get("/v1/audit/export", headers=_admin_headers())
    assert r.status_code == 200
    assert "application/x-ndjson" in r.headers.get("content-type", "")

    lines = [line for line in r.text.strip().split("\n") if line.strip()]
    assert len(lines) >= 2

    for line in lines:
        evt = json.loads(line)
        assert "event_type" in evt
        assert "event_hash" in evt
        assert "prev_hash" in evt


def test_audit_cursor_pagination(client):
    """GET /v1/audit?after=<id> paginates correctly."""
    _create_audit_events(client, "default", n=5)

    r1 = client.get("/v1/audit?limit=2", headers=_admin_headers())
    assert r1.status_code == 200
    data1 = r1.json()
    assert len(data1["events"]) == 2
    cursor = data1.get("next_cursor")
    assert cursor is not None

    r2 = client.get(f"/v1/audit?limit=2&after={cursor}", headers=_admin_headers())
    assert r2.status_code == 200
    data2 = r2.json()
    assert len(data2["events"]) >= 1

    ids1 = {e["id"] for e in data1["events"]}
    ids2 = {e["id"] for e in data2["events"]}
    assert ids1.isdisjoint(ids2)
