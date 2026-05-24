"""
gateway.detection.inventory
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tracks known vs unknown agents across the gateway session lifetime.

Unlike the trust cache (which evicts entries after 30s), the inventory
persists for the lifetime of the DetectionEngine, providing long-lived
state for detection.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentRecord:
    """A successfully authenticated agent seen through the gateway."""

    agent_did: str
    agent_name: Optional[str]
    delegator_did: Optional[str]
    first_seen: str
    last_seen: str
    request_count: int = 0


@dataclass
class ShadowAttempt:
    """An access attempt from an unverified or unknown entity."""

    reason: str
    timestamp_monotonic: float
    timestamp_iso: str
    source_ip: Optional[str] = None
    server_name: Optional[str] = None


class AgentInventory:
    """Registry of known agents and shadow access attempts."""

    def __init__(self) -> None:
        self._known_agents: dict[str, AgentRecord] = {}
        self._shadow_attempts: list[ShadowAttempt] = []

    # ------------------------------------------------------------------
    # Known agent tracking
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_did: str,
        agent_name: Optional[str],
        delegator_did: Optional[str],
        first_seen: str,
    ) -> None:
        """Register or update a successfully authenticated agent."""
        if agent_did not in self._known_agents:
            self._known_agents[agent_did] = AgentRecord(
                agent_did=agent_did,
                agent_name=agent_name,
                delegator_did=delegator_did,
                first_seen=first_seen,
                last_seen=first_seen,
                request_count=0,
            )
        record = self._known_agents[agent_did]
        record.last_seen = first_seen
        record.request_count += 1

    def get_known_agents(self) -> list[AgentRecord]:
        """Return all known agent records."""
        return list(self._known_agents.values())

    def is_known(self, agent_did: str) -> bool:
        """Return True if the agent DID has been successfully authenticated."""
        return agent_did in self._known_agents

    # ------------------------------------------------------------------
    # Shadow attempt tracking
    # ------------------------------------------------------------------

    def record_shadow_attempt(
        self,
        reason: str,
        timestamp_iso: str,
        source_ip: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> None:
        """Record a failed authentication — an unknown entity attempted access."""
        self._shadow_attempts.append(
            ShadowAttempt(
                reason=reason,
                timestamp_monotonic=time.monotonic(),
                timestamp_iso=timestamp_iso,
                source_ip=source_ip,
                server_name=server_name,
            )
        )

    def get_shadow_attempts(self, since_minutes: int = 60) -> list[ShadowAttempt]:
        """Return shadow attempts within the given time window."""
        cutoff = time.monotonic() - since_minutes * 60.0
        return [a for a in self._shadow_attempts if a.timestamp_monotonic >= cutoff]

    def get_all_shadow_attempts(self) -> list[ShadowAttempt]:
        """Return all recorded shadow attempts."""
        return list(self._shadow_attempts)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, int]:
        return {
            "known_agents": len(self._known_agents),
            "shadow_attempts_total": len(self._shadow_attempts),
            "shadow_attempts_last_hour": len(self.get_shadow_attempts(since_minutes=60)),
        }
