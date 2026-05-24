"""Tests for gateway.proxy."""
import json

import pytest

from gateway.config import UpstreamServer
from gateway.proxy import MCPProxy


@pytest.fixture
def servers():
    return {
        "db": UpstreamServer(
            name="db",
            url="http://localhost:19999/mcp",  # intentionally unreachable
            auth_type="api_key",
            credential="test-key",
            credential_header="X-API-Key",
        ),
        "bearer_srv": UpstreamServer(
            name="bearer_srv",
            url="http://localhost:19998/mcp",
            auth_type="bearer_token",
            credential="my-secret-token",
            credential_header="Authorization",
        ),
    }


class TestMCPProxy:
    @pytest.mark.anyio
    async def test_unknown_server_returns_404(self, servers):
        proxy = MCPProxy(servers)
        try:
            result = await proxy.forward("nonexistent", b"{}", {})
            assert result.status_code == 404
        finally:
            await proxy.close()

    @pytest.mark.anyio
    async def test_credential_injection_api_key(self, servers):
        """Verify headers are built correctly (without actually connecting)."""
        headers: dict[str, str] = {}
        MCPProxy._inject_credential(servers["db"], headers)
        assert headers["X-API-Key"] == "test-key"
        assert "Authorization" not in headers

    @pytest.mark.anyio
    async def test_credential_injection_bearer(self, servers):
        headers: dict[str, str] = {}
        MCPProxy._inject_credential(servers["bearer_srv"], headers)
        assert headers["Authorization"] == "Bearer my-secret-token"

    @pytest.mark.anyio
    async def test_upstream_error_returns_502(self, servers):
        proxy = MCPProxy(servers)
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
            result = await proxy.forward("db", body, {"agent_did": "did:key:x", "delegator_did": ""})
            assert result.status_code == 502
            assert result.latency_ms > 0
        finally:
            await proxy.close()

    @pytest.mark.anyio
    async def test_health_check_unreachable(self, servers):
        proxy = MCPProxy(servers)
        try:
            healthy = await proxy.health_check("db")
            assert healthy is False
        finally:
            await proxy.close()

    @pytest.mark.anyio
    async def test_health_check_unknown_server(self, servers):
        proxy = MCPProxy(servers)
        try:
            assert await proxy.health_check("nope") is False
        finally:
            await proxy.close()
