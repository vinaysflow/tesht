"""
gateway.config
~~~~~~~~~~~~~~
Configuration loading for the Pramana MCP Identity Gateway.

Declarative settings (trust thresholds, upstream servers, auth flags) are loaded
from YAML.  Runtime-only fields like ``resolver`` and ``status_checker`` are
wired programmatically at startup in ``gateway.auth``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class UpstreamServer:
    """One upstream MCP server behind the gateway."""

    name: str
    url: str
    auth_type: str = "none"
    credential: str = ""
    credential_header: str = "Authorization"
    tool_scope_mapping: dict[str, str] = field(default_factory=dict)


@dataclass
class TrustConfig:
    """Trust score thresholds for the gateway."""

    allow_threshold: int = 75
    step_up_threshold: int = 50
    cache_ttl_seconds: int = 30


@dataclass
class AuthSettings:
    """Declarative auth flags loaded from YAML.

    The actual ``MCPAuthConfig`` is built at runtime by ``gateway.auth``
    which adds non-serialisable fields (``resolver``, ``status_checker``,
    ``identity``).
    """

    require_delegation: bool = True
    require_delegator_identity: bool = True
    trusted_issuers: list[str] = field(default_factory=list)
    required_credential_types: list[str] = field(default_factory=list)
    required_actions: list[str] = field(default_factory=list)
    delegator_credential_types: list[str] = field(default_factory=list)


@dataclass
class GatewayConfig:
    """Root configuration for the gateway."""

    host: str = "0.0.0.0"
    port: int = 5052
    upstream_servers: dict[str, UpstreamServer] = field(default_factory=dict)
    trust: TrustConfig = field(default_factory=TrustConfig)
    auth: AuthSettings = field(default_factory=AuthSettings)


def load_config(path: str | Path) -> GatewayConfig:
    """Load gateway configuration from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    gw_raw = raw.get("gateway", {})
    trust_raw = raw.get("trust", {})
    auth_raw = raw.get("auth", {})
    servers_raw: dict[str, Any] = raw.get("upstream_servers", {})

    upstream_servers: dict[str, UpstreamServer] = {}
    for name, srv in servers_raw.items():
        upstream_servers[name] = UpstreamServer(
            name=name,
            url=srv.get("url", ""),
            auth_type=srv.get("auth_type", "none"),
            credential=srv.get("credential", ""),
            credential_header=srv.get("credential_header", "Authorization"),
            tool_scope_mapping=srv.get("tool_scope_mapping", {}),
        )

    return GatewayConfig(
        host=gw_raw.get("host", "0.0.0.0"),
        port=gw_raw.get("port", 5052),
        upstream_servers=upstream_servers,
        trust=TrustConfig(
            allow_threshold=trust_raw.get("allow_threshold", 75),
            step_up_threshold=trust_raw.get("step_up_threshold", 50),
            cache_ttl_seconds=trust_raw.get("cache_ttl_seconds", 30),
        ),
        auth=AuthSettings(
            require_delegation=auth_raw.get("require_delegation", True),
            require_delegator_identity=auth_raw.get("require_delegator_identity", True),
            trusted_issuers=auth_raw.get("trusted_issuers", []),
            required_credential_types=auth_raw.get("required_credential_types", []),
            required_actions=auth_raw.get("required_actions", []),
            delegator_credential_types=auth_raw.get("delegator_credential_types", []),
        ),
    )
