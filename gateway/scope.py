"""
gateway.scope
~~~~~~~~~~~~~
Scope-to-tool mapping and authorization checking.

The gateway operates on a whitelist model: only tools explicitly listed in the
upstream server's ``tool_scope_mapping`` are allowed.  Each mapped tool requires
a specific delegation scope action.  If the agent's ``effective_scope.actions``
includes that action, the tool call is permitted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from gateway.config import UpstreamServer


@dataclass
class ScopeCheckResult:
    """Outcome of a scope authorization check."""

    allowed: bool
    tool_name: str
    required_action: Optional[str]
    reason: str


class ScopeChecker:
    """Maps MCP tool names to required delegation scope actions."""

    def __init__(self, upstream_servers: dict[str, UpstreamServer]) -> None:
        self.servers = upstream_servers

    def check(
        self,
        server_name: str,
        tool_name: str,
        effective_scope: dict[str, Any],
    ) -> ScopeCheckResult:
        """Check whether *tool_name* is allowed by the agent's effective scope.

        Whitelist model — tools not in the mapping are denied.
        """
        required = self.get_required_action(server_name, tool_name)
        if required is None:
            return ScopeCheckResult(
                allowed=False,
                tool_name=tool_name,
                required_action=None,
                reason=f"Tool '{tool_name}' is not registered on server '{server_name}'",
            )

        allowed_actions: list[str] = effective_scope.get("actions", [])
        if required in allowed_actions:
            return ScopeCheckResult(
                allowed=True,
                tool_name=tool_name,
                required_action=required,
                reason="allowed",
            )

        return ScopeCheckResult(
            allowed=False,
            tool_name=tool_name,
            required_action=required,
            reason=(
                f"Action '{required}' required for tool '{tool_name}' "
                f"not in delegation scope {allowed_actions}"
            ),
        )

    def get_required_action(
        self, server_name: str, tool_name: str
    ) -> Optional[str]:
        """Return the scope action required for *tool_name*, or None."""
        srv = self.servers.get(server_name)
        if srv is None:
            return None
        return srv.tool_scope_mapping.get(tool_name)
