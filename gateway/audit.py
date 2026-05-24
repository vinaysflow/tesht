"""
gateway.audit
~~~~~~~~~~~~~
Non-blocking audit event writer for the MCP Identity Gateway.

For the demo: events are stored in an in-memory list.
Production: replace with async writes to ``backend.core.audit.write_audit()``
via an asyncio queue or a dedicated writer task.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from gateway.auth import GatewayAuthResult
from gateway.proxy import ProxyResult
from gateway.scope import ScopeCheckResult
from gateway.trust import TrustEvaluation


class GatewayAuditWriter:
    """In-memory audit event buffer."""

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def log_request(
        self,
        request_id: str,
        server_name: str,
        method: str,
        tool_name: Optional[str],
        auth_result: GatewayAuthResult,
        trust_eval: TrustEvaluation,
        scope_check: Optional[ScopeCheckResult],
        proxy_result: Optional[ProxyResult],
        decision: str,
        total_latency_ms: float,
        source_ip: Optional[str] = None,
        auth_reason: Optional[str] = None,
        delegation_depth: Optional[int] = None,
        delegation_chain_dids: Optional[list] = None,
    ) -> None:
        """Record a gateway request event (non-blocking, in-memory)."""
        event: dict[str, Any] = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server_name": server_name,
            "method": method,
            "tool_name": tool_name,
            "agent_did": auth_result.agent_did,
            "agent_name": auth_result.agent_name,
            "delegator_did": auth_result.delegator_did,
            "delegator_claims": auth_result.delegator_claims,
            "effective_scope": auth_result.effective_scope if hasattr(auth_result, "effective_scope") else None,
            "trust_score": trust_eval.score,
            "trust_decision": trust_eval.decision,
            "trust_factors": trust_eval.factors if trust_eval else {},
            "scope_allowed": scope_check.allowed if scope_check else None,
            "scope_reason": scope_check.reason if scope_check else None,
            "decision": decision,
            "proxy_status": proxy_result.status_code if proxy_result else None,
            "proxy_latency_ms": proxy_result.latency_ms if proxy_result else None,
            "auth_latency_ms": auth_result.auth_latency_ms,
            "total_latency_ms": total_latency_ms,
            "blended": auth_result.blended,
            "source_ip": source_ip,
            "auth_reason": auth_reason,
            "delegation_depth": delegation_depth,
            "delegation_chain_dids": delegation_chain_dids,
        }
        self._events.append(event)

    def get_recent_events(self, n: int = 50) -> list[dict[str, Any]]:
        """Return the *n* most recent events."""
        return self._events[-n:]

    def get_events_for_agent(self, agent_did: str) -> list[dict[str, Any]]:
        """Return all events for a given agent DID."""
        return [e for e in self._events if e["agent_did"] == agent_did]

    def get_events_filtered(
        self,
        agent_did: Optional[str] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """Return events filtered by agent DID and/or time range.

        ISO 8601 UTC strings compare lexicographically, so string comparison
        is equivalent to datetime comparison when both sides are UTC.
        """
        results = []
        for e in self._events:
            if agent_did and e.get("agent_did") != agent_did:
                continue
            ts = e.get("timestamp", "")
            if from_ts and ts < from_ts:
                continue
            if to_ts and ts > to_ts:
                continue
            results.append(e)
            if len(results) >= limit:
                break
        return results
