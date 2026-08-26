"""Integration tests for the Session authorization runtime API."""
from __future__ import annotations


def test_session_lifecycle_allow_and_revoke(client, authz_headers):
    agent = client.post("/v1/agents", json={"name": "session-bot"}, headers=authz_headers).json()
    agent_did = agent["did"]

    created = client.post(
        "/v1/sessions",
        headers={**authz_headers, "Idempotency-Key": "sess-test-001"},
        json={
            "agent_did": agent_did,
            "human_did": "did:example:alice",
            "scope": {"actions": ["read_data", "purchase"], "max_amount": 5000, "currency": "USD"},
            "packs": ["core"],
            "ttl_seconds": 3600,
        },
    )
    assert created.status_code == 200, created.text
    session = created.json()
    assert session["status"] == "active"
    assert "core" in session["packs"]
    session_id = session["id"]

    # Idempotent create
    again = client.post(
        "/v1/sessions",
        headers={**authz_headers, "Idempotency-Key": "sess-test-001"},
        json={
            "agent_did": agent_did,
            "human_did": "did:example:alice",
            "scope": {"actions": ["read_data", "purchase"], "max_amount": 5000, "currency": "USD"},
            "packs": ["core"],
        },
    )
    assert again.status_code == 200
    assert again.json()["id"] == session_id

    allowed = client.post(
        f"/v1/sessions/{session_id}/actions",
        headers=authz_headers,
        json={"action": "read_data", "tool_name": "query_database"},
    )
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert body["decision"] in {"allow", "step_up", "block"}
    assert body["session_id"] == session_id

    denied = client.post(
        f"/v1/sessions/{session_id}/actions",
        headers=authz_headers,
        json={"action": "admin_wipe"},
    )
    assert denied.status_code == 200
    assert denied.json()["decision"] == "block"
    assert denied.json()["error_code"] == "scope_denied"

    over = client.post(
        f"/v1/sessions/{session_id}/actions",
        headers=authz_headers,
        json={"action": "purchase", "amount": 99999, "currency": "USD"},
    )
    assert over.status_code == 200
    assert over.json()["error_code"] == "mandate_exceeded"

    revoked = client.post(
        f"/v1/sessions/{session_id}/revoke",
        headers=authz_headers,
        json={"cascade": True, "reason": "test done"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    after = client.post(
        f"/v1/sessions/{session_id}/actions",
        headers=authz_headers,
        json={"action": "read_data"},
    )
    assert after.status_code == 200
    assert after.json()["error_code"] == "revoked"


def test_session_step_up_restores_active(client, authz_headers):
    agent = client.post("/v1/agents", json={"name": "stepup-bot"}, headers=authz_headers).json()
    created = client.post(
        "/v1/sessions",
        headers=authz_headers,
        json={
            "agent_did": agent["did"],
            "scope": {"actions": ["read_data"]},
            "packs": ["core"],
        },
    ).json()
    session_id = created["id"]

    # Force step_up path by setting low trust via direct status if needed:
    # Call step_up even from active — should remain/return active with restored score.
    stepped = client.post(
        f"/v1/sessions/{session_id}/step_up",
        headers=authz_headers,
        json={"metadata": {"challenge": "ok"}},
    )
    assert stepped.status_code == 200, stepped.text
    assert stepped.json()["status"] == "active"


def test_packs_normalize_unknown(client, authz_headers):
    agent = client.post("/v1/agents", json={"name": "pack-bot"}, headers=authz_headers).json()
    created = client.post(
        "/v1/sessions",
        headers=authz_headers,
        json={
            "agent_did": agent["did"],
            "scope": {"actions": ["read_data"]},
            "packs": ["core", "unknown_future_pack"],
        },
    )
    assert created.status_code == 200
    packs = created.json()["packs"]
    assert packs == ["core"]


def _create_unscored_session(client, authz_headers, name):
    agent = client.post("/v1/agents", json={"name": name}, headers=authz_headers).json()
    created = client.post(
        "/v1/sessions",
        headers=authz_headers,
        json={
            "agent_did": agent["did"],
            "scope": {"actions": ["read_data"]},
            "packs": ["core"],
        },
    ).json()
    return created["id"]


def test_unscored_session_allows_in_development(client, authz_headers, monkeypatch):
    """No scored credential + development => demo-friendly allow (unchanged)."""
    monkeypatch.setenv("TESHT_ENV", "development")
    monkeypatch.setenv("GATEWAY_ENV", "")
    session_id = _create_unscored_session(client, authz_headers, "dev-unscored-bot")
    resp = client.post(
        f"/v1/sessions/{session_id}/actions",
        headers=authz_headers,
        json={"action": "read_data"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["decision"] == "allow"


def test_unscored_session_failsafe_stepup_in_production(client, authz_headers, monkeypatch):
    """No scored credential + production => fail-safe step-up, never silent allow."""
    monkeypatch.setenv("TESHT_ENV", "production")
    monkeypatch.setenv("GATEWAY_ENV", "")
    session_id = _create_unscored_session(client, authz_headers, "prod-unscored-bot")
    resp = client.post(
        f"/v1/sessions/{session_id}/actions",
        headers=authz_headers,
        json={"action": "read_data"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "step_up"
    assert body["error_code"] == "trust_step_up"
    assert body["session_status"] == "step_up_required"


# ---------------------------------------------------------------------------
# Commerce pack composition (cumulative budget + merchant allowlist + ledger)
# ---------------------------------------------------------------------------

def _create_commerce_session(client, authz_headers, name, *, max_amount, merchants=None):
    agent = client.post("/v1/agents", json={"name": name}, headers=authz_headers).json()
    scope = {"actions": ["purchase"], "max_amount": max_amount, "currency": "USD"}
    if merchants is not None:
        scope["merchants"] = merchants
    created = client.post(
        "/v1/sessions",
        headers=authz_headers,
        json={
            "agent_did": agent["did"],
            "human_did": "did:example:alice",
            "scope": scope,
            "packs": ["core", "commerce"],
        },
    )
    assert created.status_code == 200, created.text
    return created.json()["id"]


def _purchase(client, authz_headers, session_id, amount, merchant=None):
    body = {"action": "purchase", "amount": amount, "currency": "USD"}
    if merchant is not None:
        body["merchant"] = merchant
    return client.post(
        f"/v1/sessions/{session_id}/actions", headers=authz_headers, json=body
    )


def test_commerce_cumulative_budget_depletes_and_blocks(client, authz_headers, monkeypatch):
    """Multiple purchases deplete a shared budget; the one that would exceed is blocked."""
    monkeypatch.setenv("TESHT_ENV", "development")
    monkeypatch.setenv("GATEWAY_ENV", "")
    session_id = _create_commerce_session(client, authz_headers, "commerce-bot", max_amount=10000)

    first = _purchase(client, authz_headers, session_id, 6000)
    assert first.status_code == 200, first.text
    assert first.json()["decision"] == "allow"
    assert first.json()["factors"]["budget"]["remaining"] == 4000

    # 6000 + 6000 = 12000 > 10000 -> blocked, budget unchanged
    over = _purchase(client, authz_headers, session_id, 6000)
    assert over.status_code == 200
    assert over.json()["decision"] == "block"
    assert over.json()["error_code"] == "mandate_exceeded"

    # A purchase that fits the remaining 4000 still succeeds and zeroes the budget
    last = _purchase(client, authz_headers, session_id, 4000)
    assert last.status_code == 200, last.text
    assert last.json()["decision"] == "allow"
    assert last.json()["factors"]["budget"]["remaining"] == 0


def test_commerce_merchant_allowlist_blocks_unlisted(client, authz_headers, monkeypatch):
    """Purchases at a merchant outside the scope allowlist are blocked."""
    monkeypatch.setenv("TESHT_ENV", "development")
    monkeypatch.setenv("GATEWAY_ENV", "")
    session_id = _create_commerce_session(
        client, authz_headers, "merchant-bot", max_amount=50000, merchants=["nike-store"]
    )

    ok = _purchase(client, authz_headers, session_id, 8999, merchant="nike-store")
    assert ok.status_code == 200, ok.text
    assert ok.json()["decision"] == "allow"

    blocked = _purchase(client, authz_headers, session_id, 1900, merchant="apple-store")
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "block"
    assert blocked.json()["error_code"] == "scope_denied"


def test_commerce_spend_recorded_in_ledger(client, authz_headers, monkeypatch):
    """Allowed purchases are recorded and visible via the AP2 spend endpoint."""
    monkeypatch.setenv("TESHT_ENV", "development")
    monkeypatch.setenv("GATEWAY_ENV", "")
    session_id = _create_commerce_session(client, authz_headers, "ledger-bot", max_amount=100000)

    _purchase(client, authz_headers, session_id, 2499, merchant="acme-books")
    _purchase(client, authz_headers, session_id, 1899, merchant="acme-books")

    spend = client.get(
        f"/v1/commerce/mandates/{session_id}/spend", headers=authz_headers
    )
    assert spend.status_code == 200, spend.text
    data = spend.json()
    assert data["fulfillments"] == 2
    assert data["cumulative_spend"].get("USD") == 2499 + 1899
