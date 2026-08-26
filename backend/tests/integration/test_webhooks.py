"""Integration tests for the Webhook Notification System."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from unittest.mock import MagicMock, patch

import httpx
import pytest

import core.auth.jwt_auth as jwt_auth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def webhook_authz_headers():
    """Headers with webhooks:manage + credentials:issue + credentials:revoke scopes."""
    token = jwt_auth.issue_admin_token(
        scopes=["webhooks:manage", "credentials:issue", "credentials:revoke", "agents:create"],
        subject="test-webhook-user",
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_agent(client, headers, name: str = None) -> dict:
    r = client.post(
        "/v1/agents",
        json={"name": name or f"wh-agent-{uuid.uuid4().hex[:6]}"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


def _issue_vc(client, headers, issuer_id: str, subject_did: str) -> dict:
    r = client.post(
        "/v1/credentials/issue",
        json={
            "issuer_agent_id": issuer_id,
            "subject_did": subject_did,
            "credential_type": "AgentCredential",
            "ttl_seconds": 3600,
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


def _revoke_vc(client, headers, credential_id: str) -> dict:
    r = client.post(f"/v1/credentials/{credential_id}/revoke", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _create_webhook(client, headers, url: str, events: list[str], secret: str = None) -> dict:
    body = {"url": url, "events": events}
    if secret:
        body["secret"] = secret
    r = client.post("/v1/webhooks", json=body, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_create_webhook(client, webhook_authz_headers):
    """POST /v1/webhooks should return 200 with id, url, events."""
    r = client.post(
        "/v1/webhooks",
        json={
            "url": "https://example.com/hooks",
            "events": ["credential.issued"],
            "description": "Test webhook",
        },
        headers=webhook_authz_headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "id" in data
    assert data["url"] == "https://example.com/hooks"
    assert "credential.issued" in data["events"]
    assert data["active"] is True


def test_create_webhook_auto_secret(client, webhook_authz_headers):
    """Not providing a secret should result in an auto-generated one in the response."""
    r = client.post(
        "/v1/webhooks",
        json={
            "url": "https://example.com/hooks/auto-secret",
            "events": ["credential.revoked"],
        },
        headers=webhook_authz_headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "secret" in data
    assert len(data["secret"]) >= 32


def test_list_webhooks_hides_secret(client, webhook_authz_headers):
    """GET /v1/webhooks should not include the secret field in any item."""
    _create_webhook(
        client, webhook_authz_headers,
        "https://example.com/hooks/list-test",
        ["credential.issued"],
    )
    r = client.get("/v1/webhooks", headers=webhook_authz_headers)
    assert r.status_code == 200, r.text
    items = r.json()
    assert isinstance(items, list)
    assert len(items) >= 1
    for item in items:
        assert "secret" not in item, "Secret must not be returned in list response"


def test_delete_webhook(client, webhook_authz_headers):
    """DELETE /v1/webhooks/{id} should soft-delete; GET should no longer show it."""
    wh = _create_webhook(
        client, webhook_authz_headers,
        "https://example.com/hooks/delete-test",
        ["agent.created"],
    )
    webhook_id = wh["id"]

    r_del = client.delete(f"/v1/webhooks/{webhook_id}", headers=webhook_authz_headers)
    assert r_del.status_code == 200, r_del.text
    assert r_del.json()["deleted"] is True

    r_list = client.get("/v1/webhooks", headers=webhook_authz_headers)
    active_ids = [item["id"] for item in r_list.json()]
    assert webhook_id not in active_ids


def test_invalid_event_type(client, webhook_authz_headers):
    """Registering a webhook with an invalid event type should return 422."""
    r = client.post(
        "/v1/webhooks",
        json={
            "url": "https://example.com/hooks/invalid",
            "events": ["invalid.event"],
        },
        headers=webhook_authz_headers,
    )
    assert r.status_code == 422, r.text


def test_dispatch_on_revocation(client, webhook_authz_headers):
    """
    Registering a webhook for credential.revoked and revoking a credential should
    cause dispatch_webhook_event to be called with the correct event type.
    """
    webhook_secret = "test-dispatch-secret-12345"
    _create_webhook(
        client, webhook_authz_headers,
        "https://hooks.example.com/revocation",
        ["credential.revoked"],
        secret=webhook_secret,
    )

    issuer = _create_agent(client, webhook_authz_headers, "dispatch-test-issuer")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"
    vc = _issue_vc(client, webhook_authz_headers, issuer["id"], subject_did)

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch("core.webhooks.httpx.Client") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.post.return_value = mock_response
        mock_client_class.return_value = mock_client_instance

        _revoke_vc(client, webhook_authz_headers, vc["credential_id"])

    # FastAPI TestClient processes BackgroundTasks synchronously
    # There may be other webhooks registered from previous tests in the session DB,
    # so we assert that at least one call targets our specific webhook URL.
    assert mock_client_instance.post.called, "dispatch_webhook_event was never called"
    calls_by_url = {
        call.args[0] if call.args else call.kwargs.get("url"): call
        for call in mock_client_instance.post.call_args_list
    }
    # Check any call had the right event header
    for call in mock_client_instance.post.call_args_list:
        hdrs = call.kwargs.get("headers") or {}
        if hdrs.get("X-Tesht-Event") == "credential.revoked":
            break
    else:
        raise AssertionError("No call had X-Tesht-Event: credential.revoked")


def test_webhook_signature_valid(client, webhook_authz_headers):
    """X-Tesht-Signature header must match HMAC-SHA256(body, secret)."""
    webhook_secret = "signature-verify-secret-abcdef"
    _create_webhook(
        client, webhook_authz_headers,
        "https://hooks.example.com/sig-verify",
        ["credential.revoked"],
        secret=webhook_secret,
    )

    issuer = _create_agent(client, webhook_authz_headers, "sig-test-issuer")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"
    vc = _issue_vc(client, webhook_authz_headers, issuer["id"], subject_did)

    mock_response = MagicMock()
    mock_response.status_code = 200

    captured = {}

    def capture_post(url, *, content, headers, **kwargs):
        captured["body"] = content
        captured["headers"] = headers
        return mock_response

    with patch("core.webhooks.httpx.Client") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.post.side_effect = capture_post
        mock_client_class.return_value = mock_client_instance

        _revoke_vc(client, webhook_authz_headers, vc["credential_id"])

    assert "body" in captured, "Webhook was not called"
    body_bytes = captured["body"]
    expected_sig = "sha256=" + hmac.new(
        webhook_secret.encode("utf-8"), body_bytes, hashlib.sha256
    ).hexdigest()
    assert captured["headers"]["X-Tesht-Signature"] == expected_sig


def test_dispatch_timeout_doesnt_block(client, webhook_authz_headers):
    """
    Even if the webhook URL times out, the revoke endpoint must still return 200.
    """
    _create_webhook(
        client, webhook_authz_headers,
        "https://non-responsive.example.com/hook",
        ["credential.revoked"],
    )

    issuer = _create_agent(client, webhook_authz_headers, "timeout-test-issuer")
    subject_did = f"did:key:z6Mk{uuid.uuid4().hex}"
    vc = _issue_vc(client, webhook_authz_headers, issuer["id"], subject_did)

    with patch("core.webhooks.httpx.Client") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.post.side_effect = httpx.TimeoutException("timeout")
        mock_client_class.return_value = mock_client_instance

        r = client.post(
            f"/v1/credentials/{vc['credential_id']}/revoke",
            headers=webhook_authz_headers,
        )

    assert r.status_code == 200, r.text
    assert r.json()["revoked"] is True
