"""
gateway.detection.fleet
~~~~~~~~~~~~~~~~~~~~~~~
Correlates signals across multiple agents for fleet-level threat detection.

Three correlation rules fire alerts:
  1. Coordinated scope probing — 2+ agents simultaneously violating scope
  2. Shadow agent swarm        — 3+ unauthenticated attempts within 5 minutes
  3. Declining fleet trust     — average trust score below 60 across 3+ agents
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from gateway.detection.alerts import (
    AlertSeverity,
    AlertType,
    DetectionAlert,
    FleetSummary,
)
from gateway.detection.inventory import AgentInventory

if TYPE_CHECKING:
    from gateway.trust import CachedTrustScore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FleetCorrelator:
    """Correlates cross-agent signals to produce fleet-level alerts and summary."""

    # Fleet correlation thresholds
    COORDINATED_PROBE_MIN_AGENTS = 2
    SHADOW_SWARM_MIN_ATTEMPTS = 3
    SHADOW_SWARM_WINDOW_MINUTES = 5
    DECLINING_TRUST_THRESHOLD = 60
    DECLINING_TRUST_MIN_AGENTS = 3

    def analyze(
        self,
        trust_cache: dict[str, "CachedTrustScore"],
        audit_events: list[dict[str, Any]],
        inventory: AgentInventory,
    ) -> tuple[FleetSummary, list[DetectionAlert]]:
        """Compute fleet summary and emit cross-agent correlation alerts."""
        alerts: list[DetectionAlert] = []

        # ── Fleet metrics ────────────────────────────────────────────
        total = len(trust_cache)
        verified = len(inventory._known_agents)
        shadow_total = len(inventory.get_all_shadow_attempts())

        agents_with_violations = sum(
            1 for c in trust_cache.values() if c.scope_violations > 0
        )
        agents_with_penalties = sum(
            1 for c in trust_cache.values() if c.penalty > 0
        )

        scores = [c.score for c in trust_cache.values()]
        avg_score = sum(scores) / len(scores) if scores else 0.0

        risk_dist: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for s in scores:
            if s >= 75:
                risk_dist["low"] += 1
            elif s >= 50:
                risk_dist["medium"] += 1
            elif s >= 25:
                risk_dist["high"] += 1
            else:
                risk_dist["critical"] += 1

        # Count step_up and hard-blocked agents from audit log
        agents_in_step_up = len(
            {e.get("agent_did") for e in audit_events if e.get("decision") == "step_up"}
            - {None}
        )
        agents_blocked = len(
            {e.get("agent_did") for e in audit_events if e.get("decision") == "blocked_trust"}
            - {None}
        )

        # ── Correlation rule 1: Coordinated scope probing ────────────
        violating_agents = [
            did
            for did, c in trust_cache.items()
            if c.scope_violations >= 2
        ]
        if len(violating_agents) >= self.COORDINATED_PROBE_MIN_AGENTS:
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.FLEET_THREAT,
                    severity=AlertSeverity.CRITICAL,
                    timestamp=_now_iso(),
                    agent_did=None,
                    agent_name=None,
                    source_ip=None,
                    title=f"Coordinated scope probing: {len(violating_agents)} agents",
                    description=(
                        f"Multiple agents are simultaneously probing out-of-scope tools. "
                        f"Affected agents: {violating_agents}"
                    ),
                    evidence={
                        "violating_agent_count": len(violating_agents),
                        "violating_agents": violating_agents,
                    },
                    recommended_action=(
                        "Investigate shared delegator; possible compromised delegation authority"
                    ),
                )
            )

        # ── Correlation rule 2: Shadow agent swarm ───────────────────
        recent_shadows = inventory.get_shadow_attempts(
            since_minutes=self.SHADOW_SWARM_WINDOW_MINUTES
        )
        if len(recent_shadows) >= self.SHADOW_SWARM_MIN_ATTEMPTS:
            unique_ips = list(
                {s.source_ip for s in recent_shadows if s.source_ip}
            )

            # Tool/server overlap analysis: which servers did shadow agents target?
            servers = [s.server_name for s in recent_shadows if s.server_name]
            server_counts: dict[str, int] = {}
            for srv in servers:
                server_counts[srv] = server_counts.get(srv, 0) + 1
            # Servers targeted by 2+ distinct shadow attempts
            overlapping = [srv for srv, cnt in server_counts.items() if cnt >= 2]
            unique_servers = list(set(servers))

            if overlapping:
                overlap_desc = (
                    f" Multiple shadow agent types targeted the same server "
                    f"({', '.join(overlapping)}) within "
                    f"{self.SHADOW_SWARM_WINDOW_MINUTES} minutes."
                )
            else:
                overlap_desc = ""

            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.FLEET_THREAT,
                    severity=AlertSeverity.CRITICAL,
                    timestamp=_now_iso(),
                    agent_did=None,
                    agent_name=None,
                    source_ip=None,
                    title=(
                        f"Shadow agent swarm: {len(recent_shadows)} attempts "
                        f"in {self.SHADOW_SWARM_WINDOW_MINUTES} min"
                    ),
                    description=(
                        f"{len(recent_shadows)} unknown entities attempted MCP access "
                        f"in rapid succession.{overlap_desc}"
                    ),
                    evidence={
                        "attempt_count": len(recent_shadows),
                        "window_minutes": self.SHADOW_SWARM_WINDOW_MINUTES,
                        "source_ips": unique_ips,
                        "servers_targeted": unique_servers,
                        "server_overlap": overlapping,
                    },
                    recommended_action=(
                        "Investigate source IPs; consider network-level blocking"
                    ),
                )
            )

        # ── Correlation rule 3: Declining fleet trust ────────────────
        if avg_score < self.DECLINING_TRUST_THRESHOLD and total >= self.DECLINING_TRUST_MIN_AGENTS:
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.FLEET_THREAT,
                    severity=AlertSeverity.WARNING,
                    timestamp=_now_iso(),
                    agent_did=None,
                    agent_name=None,
                    source_ip=None,
                    title=f"Fleet trust declining: avg {avg_score:.0f}/100",
                    description=(
                        f"Average trust score across {total} active agents "
                        f"is below {self.DECLINING_TRUST_THRESHOLD}"
                    ),
                    evidence={
                        "avg_trust_score": round(avg_score, 1),
                        "agent_count": total,
                        "risk_distribution": risk_dist,
                    },
                    recommended_action=(
                        "Review fleet-wide credential and delegation health"
                    ),
                )
            )

        summary = FleetSummary(
            total_agents_seen=total,
            verified_agents=verified,
            shadow_attempts=shadow_total,
            agents_with_violations=agents_with_violations,
            agents_with_penalties=agents_with_penalties,
            agents_in_step_up=agents_in_step_up,
            agents_blocked=agents_blocked,
            avg_trust_score=round(avg_score, 1),
            risk_distribution=risk_dist,
            top_alerts=alerts[:5],
        )

        return summary, alerts
