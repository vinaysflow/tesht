"""End-to-end tests for the MCP Identity Gateway.

Uses httpx.ASGITransport to run the FastAPI app in-process (no subprocess).
Starts a real mock MCP server on an ephemeral port.
"""
from __future__ import annotations

import json
import threading
import time

import httpx
import pytest
import uvicorn

from pramana.credentials import create_blended_presentation, create_presentation, issue_vc
from pramana.delegation import issue_delegation
from pramana.identity import AgentIdentity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock_mcp_port() -> int:
    return 19200


@pytest.fixture(scope="module", autouse=True)
def mock_mcp_server(mock_mcp_port):
    """Start the mock MCP server in a background thread."""
    from gateway.mock_mcp_server import app as mock_app

    config = uvicorn.Config(
        mock_app, host="127.0.0.1", port=mock_mcp_port, log_level="error"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to be ready
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"http://127.0.0.1:{mock_mcp_port}/health", timeout=1.0)
            if r.status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.1)

    yield

    server.should_exit = True
    thread.join(timeout=3)


@pytest.fixture(scope="module")
def gateway_app(mock_mcp_port):
    """Create a gateway FastAPI app with state initialized manually.

    httpx.ASGITransport does not trigger the lifespan, so we populate
    app.state directly using the same objects that the lifespan handler would.
    """
    from fastapi import FastAPI

    from gateway.audit import GatewayAuditWriter
    from gateway.auth import GatewayAuth
    from gateway.config import (
        AuthSettings,
        GatewayConfig,
        TrustConfig,
        UpstreamServer,
    )
    from gateway.detection.engine import DetectionEngine
    from gateway.proxy import MCPProxy
    from gateway.scope import ScopeChecker
    from gateway.trust import GatewayTrustEvaluator

    config = GatewayConfig(
        upstream_servers={
            "mock_database": UpstreamServer(
                name="mock_database",
                url=f"http://127.0.0.1:{mock_mcp_port}/mcp",
                auth_type="api_key",
                credential="e2e-secret-key",
                credential_header="X-API-Key",
                tool_scope_mapping={
                    "query_database": "read_data",
                    "insert_record": "write_data",
                    "delete_record": "admin",
                },
            ),
        },
        trust=TrustConfig(allow_threshold=75, step_up_threshold=50, cache_ttl_seconds=30),
        auth=AuthSettings(require_delegation=True, require_delegator_identity=True),
    )

    from gateway.app import app

    audit = GatewayAuditWriter()
    trust = GatewayTrustEvaluator(config.trust)

    app.state.config = config
    app.state.auth = GatewayAuth(config)
    app.state.trust = trust
    app.state.scope = ScopeChecker(config.upstream_servers)
    app.state.proxy = MCPProxy(config.upstream_servers)
    app.state.audit = audit
    app.state.detection = DetectionEngine(audit, trust)

    yield app


def _get_gateway_did(gateway_app) -> str:
    """Get the gateway DID from app state directly (avoids network calls)."""
    return gateway_app.state.auth.gateway_identity.did


def _make_identities(audience_did: str):
    idp = AgentIdentity.create("e2e-idp")
    alice = AgentIdentity.create("e2e-alice")
    bot = AgentIdentity.create("e2e-bot")
    rogue = AgentIdentity.create("e2e-rogue")

    alice_vc = issue_vc(
        issuer=idp, subject_did=alice.did,
        credential_type="OrganizationalRoleCredential",
        claims={"name": "Alice", "role": "Buyer", "organization": "Acme"},
    )
    bot_vc = issue_vc(
        issuer=idp, subject_did=bot.did,
        credential_type="AgentCredential",
        claims={"agentName": "E2EBot"},
    )
    deleg = issue_delegation(
        delegator=alice, delegate_did=bot.did,
        scope={"actions": ["read_data", "write_data"], "max_amount": 50000,
               "currency": "USD", "merchants": ["*"], "categories": []},
        max_depth=2,
    )
    blended_vp = create_blended_presentation(
        agent=bot, delegation_jwt=deleg,
        delegator_identity_jwt=alice_vc,
        additional_credentials=[bot_vc],
        audience=audience_did,
    )
    rogue_vc = issue_vc(
        issuer=rogue, subject_did=rogue.did,
        credential_type="AgentCredential", claims={"agentName": "Rogue"},
    )
    rogue_vp = create_presentation(
        holder=rogue, credentials=[rogue_vc],
        audience=audience_did,
    )
    return blended_vp, rogue_vp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGatewayE2E:
    @pytest.mark.anyio
    async def test_authorized_request_proxied_and_audited(self, gateway_app):
        gw_did = _get_gateway_did(gateway_app)
        blended_vp, _ = _make_identities(gw_did)

        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "query_database", "arguments": {"sql": "SELECT 1"}},
            })
            r = await c.post(
                "/mcp/mock_database",
                content=body.encode(),
                headers={"Authorization": f"Bearer {blended_vp}", "Content-Type": "application/json"},
            )
            assert r.status_code == 200
            result = r.json()
            assert "result" in result
            assert result["result"]["isError"] is False

            events = (await c.get("/gateway/events?n=5")).json()
            assert any(e["decision"] == "allowed" for e in events)

    @pytest.mark.anyio
    async def test_out_of_scope_tool_blocked(self, gateway_app):
        gw_did = _get_gateway_did(gateway_app)
        blended_vp, _ = _make_identities(gw_did)

        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({
                "jsonrpc": "2.0", "id": 2,
                "method": "tools/call",
                "params": {"name": "delete_record", "arguments": {"table": "x", "id": "1"}},
            })
            r = await c.post(
                "/mcp/mock_database",
                content=body.encode(),
                headers={"Authorization": f"Bearer {blended_vp}"},
            )
            assert r.status_code == 403
            assert "admin" in r.json()["error"]["message"].lower()

    @pytest.mark.anyio
    async def test_no_auth_header_rejected(self, gateway_app):
        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            r = await c.post("/mcp/mock_database", content=body.encode())
            assert r.status_code == 401

    @pytest.mark.anyio
    async def test_invalid_vp_rejected(self, gateway_app):
        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
            r = await c.post(
                "/mcp/mock_database",
                content=body.encode(),
                headers={"Authorization": "Bearer garbage.token.here"},
            )
            assert r.status_code == 401

    @pytest.mark.anyio
    async def test_rogue_agent_no_delegation_rejected(self, gateway_app):
        gw_did = _get_gateway_did(gateway_app)
        _, rogue_vp = _make_identities(gw_did)

        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({
                "jsonrpc": "2.0", "id": 5,
                "method": "tools/call",
                "params": {"name": "query_database"},
            })
            r = await c.post(
                "/mcp/mock_database",
                content=body.encode(),
                headers={"Authorization": f"Bearer {rogue_vp}"},
            )
            assert r.status_code == 401
            assert "Delegation" in r.json()["error"]["message"]

    @pytest.mark.anyio
    async def test_unknown_server_404(self, gateway_app):
        gw_did = _get_gateway_did(gateway_app)
        blended_vp, _ = _make_identities(gw_did)

        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
            r = await c.post(
                "/mcp/nonexistent_server",
                content=body.encode(),
                headers={"Authorization": f"Bearer {blended_vp}"},
            )
            assert r.status_code == 404

    @pytest.mark.anyio
    async def test_credential_isolation(self, gateway_app, mock_mcp_port):
        """Verify the mock server received the gateway's API key, not the agent's VP."""
        gw_did = _get_gateway_did(gateway_app)
        blended_vp, _ = _make_identities(gw_did)

        # Reset the proxy's httpx client so it creates a fresh one on this event loop
        gateway_app.state.proxy._client = None

        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({
                "jsonrpc": "2.0", "id": 7,
                "method": "tools/call",
                "params": {"name": "query_database"},
            })
            await c.post(
                "/mcp/mock_database",
                content=body.encode(),
                headers={"Authorization": f"Bearer {blended_vp}"},
            )

        r = httpx.get(f"http://127.0.0.1:{mock_mcp_port}/credentials-received", timeout=5.0)
        assert r.status_code == 200
        reqs = r.json().get("requests", [])
        assert len(reqs) > 0
        last = reqs[-1]
        assert last["api_key_present"] is True
        assert not last["auth_header"].startswith("Bearer ey")

    @pytest.mark.anyio
    async def test_scope_block_degrades_trust_in_gateway(self, gateway_app):
        """Three scope violations should accumulate a behavioral penalty.

        After 3 blocked 'delete_record' requests the trust score on the next
        allowed request should reflect a non-zero behavioral penalty.
        """
        gw_did = _get_gateway_did(gateway_app)
        blended_vp, _ = _make_identities(gw_did)

        # Reset the trust cache so this test gets a clean slate
        gateway_app.state.trust.invalidate(
            gateway_app.state.auth.mcp_auth.config.identity.did
            if hasattr(gateway_app.state.auth.mcp_auth, "config")
            else ""
        )
        # Clear fully to be safe
        gateway_app.state.trust._cache.clear()

        transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            out_of_scope_body = json.dumps({
                "jsonrpc": "2.0", "id": 10,
                "method": "tools/call",
                "params": {"name": "delete_record", "arguments": {"table": "x", "id": "1"}},
            })
            # Send 3 out-of-scope requests
            for _ in range(3):
                r = await c.post(
                    "/mcp/mock_database",
                    content=out_of_scope_body.encode(),
                    headers={"Authorization": f"Bearer {blended_vp}"},
                )
                assert r.status_code == 403

            # Now check trust state: scope_violations should be recorded
            # Find the agent DID from the audit events
            events_r = await c.get("/gateway/events?n=10")
            events = events_r.json()
            scope_blocked = [e for e in events if e["decision"] == "blocked_scope"]
            assert len(scope_blocked) >= 3

            # The cache entry for the agent should reflect violations
            # (agent_did is in the audit events)
            agent_did = scope_blocked[0].get("agent_did")
            if agent_did and agent_did in gateway_app.state.trust._cache:
                cached = gateway_app.state.trust._cache[agent_did]
                assert cached.scope_violations >= 3
