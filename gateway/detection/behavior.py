"""
gateway.detection.behavior
~~~~~~~~~~~~~~~~~~~~~~~~~~
Detects behavioral anomalies by reading the live trust cache.

Three signal types are analyzed:
  1. High-penalty agents  — accumulated behavioral penalty indicates suspicious activity
  2. Scope probing agents — repeated attempts to access out-of-scope tools
  3. Velocity spike       — request rate far above normal
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from gateway.detection.alerts import AlertSeverity, AlertType, DetectionAlert
from gateway.detection.inventory import AgentInventory

if TYPE_CHECKING:
    from gateway.trust import CachedTrustScore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BehavioralDetector:
    """Reads trust cache entries and emits behavioral anomaly alerts."""

    # Penalty thresholds
    PENALTY_WARNING_THRESHOLD = 20
    PENALTY_CRITICAL_THRESHOLD = 40

    # Scope violation thresholds
    SCOPE_PROBING_THRESHOLD = 2

    # Requests-per-minute velocity thresholds
    VELOCITY_WARNING_RPM = 30
    VELOCITY_CRITICAL_RPM = 60

    def analyze(
        self,
        trust_cache: dict[str, "CachedTrustScore"],
        inventory: AgentInventory,
    ) -> list[DetectionAlert]:
        """Scan all cached trust entries for behavioral anomalies."""
        alerts: list[DetectionAlert] = []

        for agent_did, cached in trust_cache.items():
            record = inventory._known_agents.get(agent_did)
            agent_name = record.agent_name if record else None

            # 1. High-penalty agent
            if cached.penalty >= self.PENALTY_WARNING_THRESHOLD:
                severity = (
                    AlertSeverity.CRITICAL
                    if cached.penalty >= self.PENALTY_CRITICAL_THRESHOLD
                    else AlertSeverity.WARNING
                )
                alerts.append(
                    DetectionAlert(
                        alert_type=AlertType.BEHAVIORAL_ANOMALY,
                        severity=severity,
                        timestamp=_now_iso(),
                        agent_did=agent_did,
                        agent_name=agent_name,
                        source_ip=None,
                        title=f"Behavioral anomaly: penalty {cached.penalty}",
                        description=(
                            f"Agent accumulated {cached.penalty} behavioral penalty points. "
                            f"Trust degraded from {cached.base_score} to {cached.score}/100."
                        ),
                        evidence={
                            "base_score": cached.base_score,
                            "current_score": cached.score,
                            "penalty": cached.penalty,
                            "scope_violations": cached.scope_violations,
                            "novel_tools": list(cached.novel_tools),
                            "failure_count": cached.failure_count,
                            "request_count": cached.request_count,
                        },
                        recommended_action=(
                            "Review agent activity log; consider revoking delegation"
                        ),
                    )
                )

            # 2. Scope probing
            if cached.scope_violations >= self.SCOPE_PROBING_THRESHOLD:
                alerts.append(
                    DetectionAlert(
                        alert_type=AlertType.SCOPE_PROBING,
                        severity=AlertSeverity.CRITICAL,
                        timestamp=_now_iso(),
                        agent_did=agent_did,
                        agent_name=agent_name,
                        source_ip=None,
                        title=f"Scope probing: {cached.scope_violations} violation(s)",
                        description=(
                            f"Agent attempted to access {cached.scope_violations} "
                            f"out-of-scope tool(s): {list(cached.scope_violation_tools)}"
                        ),
                        evidence={
                            "scope_violations": cached.scope_violations,
                            "tools_probed": list(cached.scope_violation_tools),
                            "current_score": cached.score,
                        },
                        recommended_action=(
                            "Investigate agent behavior; "
                            "may indicate compromised or misconfigured delegation"
                        ),
                    )
                )

            # 3. Velocity spike — use the already-windowed timestamps list
            recent_rpm = len(cached.request_timestamps)
            if recent_rpm > self.VELOCITY_WARNING_RPM:
                severity = (
                    AlertSeverity.CRITICAL
                    if recent_rpm >= self.VELOCITY_CRITICAL_RPM
                    else AlertSeverity.WARNING
                )
                alerts.append(
                    DetectionAlert(
                        alert_type=AlertType.VELOCITY_SPIKE,
                        severity=severity,
                        timestamp=_now_iso(),
                        agent_did=agent_did,
                        agent_name=agent_name,
                        source_ip=None,
                        title=f"Velocity spike: {recent_rpm} requests/min",
                        description=(
                            f"Agent request rate ({recent_rpm}/min) exceeds normal threshold "
                            f"({self.VELOCITY_WARNING_RPM}/min)"
                        ),
                        evidence={
                            "requests_per_minute": recent_rpm,
                            "request_count_total": cached.request_count,
                        },
                        recommended_action=(
                            "Throttle agent or require step-up re-authentication"
                        ),
                    )
                )

        return alerts
