"""Functional tests for commerce hardening: currency validation, spend ledger,
single-use cart JTI, and JTI deduplication on mandate verify.
"""
from __future__ import annotations

import core.auth.jwt_auth as jwt_auth


def _headers(scopes=None, tenant_id="default"):
    scopes = scopes or ["agents:create", "credentials:issue", "credentials:revoke"]
    token = jwt_auth.issue_admin_token(scopes=scopes, tenant_id=tenant_id)
    return {"Authorization": f"Bearer {token}"}


SAMPLE_INTENT = {
    "agent_did": "did:web:example.com:agents:shop-bot",
    "intent": {
        "max_amount": 10000,
        "currency": "USD",
        "merchants": ["*"],
        "categories": ["electronics"],
    },
    "ttl_seconds": 3600,
}


def _issue_intent(client, headers, intent=None):
    r = client.post("/v1/commerce/mandates/intent", json=intent or SAMPLE_INTENT, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["mandate_jwt"]


def _issue_cart(client, headers, intent_jwt, cart_total_value=5000, currency="USD"):
    cart_body = {
        "agent_did": "did:web:example.com:agents:shop-bot",
        "cart": {
            "total": {"currency": currency, "value": cart_total_value},
            "items": [{"sku": "ITEM-001", "quantity": 1, "price": cart_total_value}],
        },
        "intent_mandate_jwt": intent_jwt,
        "ttl_seconds": 300,
    }
    r = client.post("/v1/commerce/mandates/cart", json=cart_body, headers=headers)
    return r


# ── Currency validation ───────────────────────────────────────────────────────

def test_cart_currency_mismatch_rejected(client, authz_headers):
    """Cart with EUR currency against USD intent is rejected with 422."""
    intent_jwt = _issue_intent(client, authz_headers)

    r = _issue_cart(client, authz_headers, intent_jwt, cart_total_value=100, currency="EUR")
    assert r.status_code == 422, r.text
    body = r.json()
    msg = (body.get("detail") or body.get("error") or "").lower()
    assert "currency" in msg


def test_cart_matching_currency_accepted(client, authz_headers):
    """Cart with same currency as intent is accepted."""
    intent_jwt = _issue_intent(client, authz_headers)
    r = _issue_cart(client, authz_headers, intent_jwt, cart_total_value=5000, currency="USD")
    assert r.status_code == 200, r.text
    assert r.json().get("mandate_jwt")


def test_cart_over_budget_rejected(client, authz_headers):
    """Cart value exceeding intent max_amount is rejected."""
    intent_jwt = _issue_intent(client, authz_headers)
    r = _issue_cart(client, authz_headers, intent_jwt, cart_total_value=99999, currency="USD")
    assert r.status_code == 422, r.text
    body = r.json()
    msg = (body.get("detail") or body.get("error") or "").lower()
    assert "exceeds" in msg


# ── Single-use cart JTI (mandate spend ledger) ────────────────────────────────

def test_cart_mandate_single_use(client, authz_headers):
    """Same cart mandate JWT cannot be verified (fulfilled) twice."""
    intent_jwt = _issue_intent(client, authz_headers)
    cart_r = _issue_cart(client, authz_headers, intent_jwt, cart_total_value=100, currency="USD")
    assert cart_r.status_code == 200, cart_r.text
    cart_jwt = cart_r.json()["mandate_jwt"]

    # First verification: success
    v1 = client.post(
        "/v1/commerce/mandates/verify",
        json={"jwt": cart_jwt, "mandate_type": "AP2CartMandate"},
        headers=authz_headers,
    )
    assert v1.status_code == 200, v1.text
    assert v1.json()["verified"] is True

    # Second verification: rejected (single-use)
    v2 = client.post(
        "/v1/commerce/mandates/verify",
        json={"jwt": cart_jwt, "mandate_type": "AP2CartMandate"},
        headers=authz_headers,
    )
    assert v2.status_code == 200
    data = v2.json()
    # Either JTI dedup or mandate spend ledger should reject
    assert data["verified"] is False
    reason = (data.get("reason") or "").lower()
    assert "already fulfilled" in reason or "replay" in reason or "single-use" in reason or "already" in reason


# ── Spend ledger endpoint ─────────────────────────────────────────────────────

def test_spend_ledger_tracks_fulfillments(client, authz_headers):
    """GET /v1/commerce/mandates/{intent_jti}/spend returns cumulative spend."""
    intent_jwt = _issue_intent(client, authz_headers)

    # Issue and verify a cart
    cart_r = _issue_cart(client, authz_headers, intent_jwt, cart_total_value=2000, currency="USD")
    assert cart_r.status_code == 200
    cart_jwt = cart_r.json()["mandate_jwt"]

    client.post(
        "/v1/commerce/mandates/verify",
        json={"jwt": cart_jwt},
        headers=authz_headers,
    )

    # Extract intent JTI from JWT
    import base64
    import json
    parts = intent_jwt.split(".")
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    intent_jti = json.loads(base64.urlsafe_b64decode(padded)).get("jti", "")

    r = client.get(f"/v1/commerce/mandates/{intent_jti}/spend", headers=authz_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["intent_jti"] == intent_jti
    assert data["fulfillments"] >= 1
    assert "cumulative_spend" in data


# ── JTI deduplication on mandate verify ───────────────────────────────────────

def test_jti_dedup_rejects_replay_on_mandate_verify(client, authz_headers):
    """JTI dedup rejects same intent mandate JWT verified twice."""
    intent_jwt = _issue_intent(client, authz_headers)

    # First verify
    v1 = client.post(
        "/v1/commerce/mandates/verify",
        json={"jwt": intent_jwt, "mandate_type": "AP2IntentMandate"},
        headers=authz_headers,
    )
    assert v1.status_code == 200
    assert v1.json()["verified"] is True

    # Second verify (same JTI) — should be rejected by JTI dedup
    v2 = client.post(
        "/v1/commerce/mandates/verify",
        json={"jwt": intent_jwt, "mandate_type": "AP2IntentMandate"},
        headers=authz_headers,
    )
    assert v2.status_code == 200
    data = v2.json()
    assert data["verified"] is False
    assert "replay" in (data.get("reason") or "").lower()
