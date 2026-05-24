"""
gateway.proxy
~~~~~~~~~~~~~
MCP request forwarding with credential injection and isolation.

The agent's incoming VP-JWT is stripped before forwarding.  The gateway
injects its own credentials for the upstream MCP server — the agent
NEVER sees the upstream API key or token.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from gateway.config import UpstreamServer


@dataclass
class ProxyResult:
    """Outcome of forwarding a request to an upstream MCP server."""

    status_code: int
    body: bytes
    headers: dict[str, str]
    latency_ms: float
    upstream_name: str = ""


class MCPProxy:
    """Forwards MCP JSON-RPC requests to upstream servers."""

    def __init__(self, upstream_servers: dict[str, UpstreamServer]) -> None:
        self.servers = upstream_servers
        self._client: Optional[httpx.AsyncClient] = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def forward(
        self,
        server_name: str,
        jsonrpc_body: bytes,
        gateway_context: dict[str, Any],
    ) -> ProxyResult:
        """Forward a JSON-RPC request to the named upstream server.

        Injects the gateway's own credentials and Pramana context headers.
        The agent's original Authorization header is NOT forwarded.
        """
        srv = self.servers.get(server_name)
        if srv is None:
            return ProxyResult(
                status_code=404,
                body=b'{"error": "unknown upstream server"}',
                headers={},
                latency_ms=0,
                upstream_name=server_name,
            )

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Pramana-Agent-DID": gateway_context.get("agent_did", ""),
            "X-Pramana-Delegator": gateway_context.get("delegator_did", ""),
        }
        self._inject_credential(srv, headers)

        client = await self._ensure_client()
        t0 = time.monotonic()
        try:
            resp = await client.post(
                srv.url, content=jsonrpc_body, headers=headers
            )
            elapsed_ms = (time.monotonic() - t0) * 1000
            return ProxyResult(
                status_code=resp.status_code,
                body=resp.content,
                headers=dict(resp.headers),
                latency_ms=elapsed_ms,
                upstream_name=server_name,
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            return ProxyResult(
                status_code=502,
                body=f'{{"error": "upstream error: {exc}"}}'.encode(),
                headers={},
                latency_ms=elapsed_ms,
                upstream_name=server_name,
            )

    async def health_check(self, server_name: str) -> bool:
        """Return True if the upstream server is reachable."""
        srv = self.servers.get(server_name)
        if srv is None:
            return False
        client = await self._ensure_client()
        try:
            resp = await client.get(srv.url, timeout=5.0)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def _inject_credential(
        srv: UpstreamServer, headers: dict[str, str]
    ) -> None:
        """Add the upstream server's own credential to the outgoing headers."""
        if srv.auth_type == "api_key":
            headers[srv.credential_header] = srv.credential
        elif srv.auth_type == "bearer_token":
            header_name = srv.credential_header or "Authorization"
            headers[header_name] = f"Bearer {srv.credential}"
        elif srv.auth_type == "basic_auth":
            import base64

            encoded = base64.b64encode(srv.credential.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
