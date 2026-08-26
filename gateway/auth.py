"""
gateway.auth
~~~~~~~~~~~~~
Authentication wrapper for the MCP Identity Gateway.

Constructs ``MCPAuthConfig`` from declarative YAML settings and wires in
the SDK's ``resolve_did_key`` as the DID resolver at runtime (callables
are not YAML-serialisable).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from tesht.identity import AgentIdentity, resolve_did_key
from tesht.integrations.mcp import MCPAuthConfig, MCPAuthResult, TeshtMCPAuth

from gateway.config import AuthSettings, GatewayConfig


def _default_resolver(did: str) -> dict[str, Any]:
    """Resolve did:key DIDs using the SDK.  Rejects other methods."""
    if did.startswith("did:key:"):
        return resolve_did_key(did)
    raise ValueError(f"Unsupported DID method for gateway resolution: {did}")


def build_mcp_auth_config(
    gateway_identity: AgentIdentity,
    auth_settings: AuthSettings,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_checker: Optional[Callable[[str, int], bool]] = None,
) -> MCPAuthConfig:
    """Build an ``MCPAuthConfig`` from YAML-derived settings + runtime callables.

    The YAML supplies declarative flags (require_delegation, trusted_issuers,
    etc.).  The resolver and status_checker are injected programmatically
    because they are callable functions — not YAML-serialisable.
    """
    return MCPAuthConfig(
        identity=gateway_identity,
        trusted_issuers=auth_settings.trusted_issuers,
        required_credential_types=auth_settings.required_credential_types,
        require_delegation=auth_settings.require_delegation,
        required_actions=auth_settings.required_actions,
        resolver=resolver or _default_resolver,
        status_checker=status_checker,
        require_delegator_identity=auth_settings.require_delegator_identity,
        delegator_credential_types=auth_settings.delegator_credential_types,
    )


@dataclass
class GatewayAuthResult:
    """Enriched auth result with gateway-specific metadata."""

    authenticated: bool
    agent_did: Optional[str] = None
    agent_name: Optional[str] = None
    delegator_did: Optional[str] = None
    delegator_claims: dict[str, Any] = field(default_factory=dict)
    effective_scope: dict[str, Any] = field(default_factory=dict)
    blended: bool = False
    credential_types: list[str] = field(default_factory=list)
    reason: Optional[str] = None
    raw_result: Optional[MCPAuthResult] = None
    auth_latency_ms: float = 0.0


class GatewayAuth:
    """VP verification wrapper for gateway request handling."""

    def __init__(
        self,
        config: GatewayConfig,
        gateway_identity: Optional[AgentIdentity] = None,
        resolver: Optional[Callable[[str], dict[str, Any]]] = None,
        status_checker: Optional[Callable[[str, int], bool]] = None,
    ) -> None:
        self.gateway_identity = gateway_identity or AgentIdentity.create(
            "tesht-mcp-gateway"
        )
        mcp_config = build_mcp_auth_config(
            self.gateway_identity,
            config.auth,
            resolver=resolver,
            status_checker=status_checker,
        )
        self.mcp_auth = TeshtMCPAuth(mcp_config)

    def authenticate(self, authorization: str) -> GatewayAuthResult:
        """Verify the blended VP from the Authorization header value.

        Returns a ``GatewayAuthResult`` with timing metadata.
        """
        t0 = time.monotonic()
        raw = self.mcp_auth.verify_request({"Authorization": authorization})
        elapsed_ms = (time.monotonic() - t0) * 1000

        cred_types = [cr.credential_type for cr in raw.credentials]

        return GatewayAuthResult(
            authenticated=raw.authenticated,
            agent_did=raw.agent_did,
            agent_name=raw.agent_name,
            delegator_did=raw.delegator_did,
            delegator_claims=raw.delegator_claims,
            effective_scope=raw.effective_scope,
            blended=raw.blended,
            credential_types=cred_types,
            reason=raw.reason,
            raw_result=raw,
            auth_latency_ms=elapsed_ms,
        )
