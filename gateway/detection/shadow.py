"""
gateway.detection.shadow
~~~~~~~~~~~~~~~~~~~~~~~~
Classifies blocked_auth audit events into shadow agent categories.

Shadow agents are entities that attempt MCP access but fail authentication.
They fall into three categories:
  - No credentials:  request arrived with no Authorization header
  - Invalid/expired: VP verification failed or delegation missing
  - Untrusted issuer: credentials presented from a non-trusted issuer
"""
from __future__ import annotations

from typing import Any

from gateway.detection.alerts import AlertSeverity, AlertType, DetectionAlert
from gateway.detection.inventory import AgentInventory


class ShadowDetector:
    """Classifies blocked_auth events into shadow agent alert categories."""

    def classify(
        self,
        audit_events: list[dict[str, Any]],
        inventory: AgentInventory,
    ) -> list[DetectionAlert]:
        """Scan recent audit events for shadow agent patterns.

        Groups blocked_auth events by reason string and emits one alert
        per category, with severity escalating on repeat attempts.
        """
        blocked = [e for e in audit_events if e.get("decision") == "blocked_auth"]
        if not blocked:
            return []

        # Group by classified reason category
        no_creds: list[dict] = []
        expired_vp: list[dict] = []
        invalid_vp: list[dict] = []
        untrusted: list[dict] = []
        other: list[dict] = []

        for event in blocked:
            reason = event.get("auth_reason") or event.get("scope_reason") or "unknown"
            if "Missing Authorization" in reason or "missing" in reason.lower():
                no_creds.append(event)
            elif "Untrusted issuer" in reason or "untrusted" in reason.lower():
                untrusted.append(event)
            elif "expired" in reason.lower() or "Presentation expired" in reason:
                expired_vp.append(event)
            elif (
                "VP verification failed" in reason
                or "Delegation required" in reason
                or "verification failed" in reason.lower()
                or "delegation" in reason.lower()
            ):
                invalid_vp.append(event)
            else:
                other.append(event)

        alerts: list[DetectionAlert] = []

        if no_creds:
            count = len(no_creds)
            severity = AlertSeverity.CRITICAL if count >= 3 else AlertSeverity.WARNING
            last = no_creds[-1]
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.SHADOW_AGENT,
                    severity=severity,
                    timestamp=last.get("timestamp", ""),
                    agent_did=None,
                    agent_name=None,
                    source_ip=last.get("source_ip"),
                    title="Shadow agent: No credentials",
                    description=(
                        f"Entity attempted MCP access {count} time(s) without any credentials"
                    ),
                    evidence={
                        "attempt_count": count,
                        "reason": "Missing Authorization header",
                        "source_ips": list(
                            {e.get("source_ip") for e in no_creds if e.get("source_ip")}
                        ),
                    },
                    recommended_action="Block source IP or enforce authentication at network layer",
                )
            )

        if expired_vp:
            count = len(expired_vp)
            severity = AlertSeverity.CRITICAL if count >= 3 else AlertSeverity.WARNING
            last = expired_vp[-1]
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.SHADOW_AGENT,
                    severity=severity,
                    timestamp=last.get("timestamp", ""),
                    agent_did=last.get("agent_did"),
                    agent_name=None,
                    source_ip=last.get("source_ip"),
                    title="Shadow agent: Expired VP",
                    description=(
                        f"Agent presented an expired Verifiable Presentation "
                        f"({count} attempt(s))"
                    ),
                    evidence={
                        "attempt_count": count,
                        "reason": "Presentation expired",
                        "agent_dids": list(
                            {e.get("agent_did") for e in expired_vp if e.get("agent_did")}
                        ),
                    },
                    recommended_action="Rotate agent VP — check clock skew or credential TTL",
                )
            )

        if untrusted:
            count = len(untrusted)
            last = untrusted[-1]
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.SHADOW_AGENT,
                    severity=AlertSeverity.CRITICAL,
                    timestamp=last.get("timestamp", ""),
                    agent_did=last.get("agent_did"),
                    agent_name=None,
                    source_ip=last.get("source_ip"),
                    title="Shadow agent: Untrusted issuer",
                    description=(
                        f"Agent presented credentials from an untrusted issuer "
                        f"({count} attempt(s))"
                    ),
                    evidence={
                        "attempt_count": count,
                        "reason": "Untrusted issuer",
                        "agent_dids": list(
                            {e.get("agent_did") for e in untrusted if e.get("agent_did")}
                        ),
                    },
                    recommended_action=(
                        "Investigate issuer, add to trusted list or block the agent DID"
                    ),
                )
            )

        if invalid_vp:
            count = len(invalid_vp)
            severity = AlertSeverity.CRITICAL if count >= 3 else AlertSeverity.WARNING
            last = invalid_vp[-1]
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.SHADOW_AGENT,
                    severity=severity,
                    timestamp=last.get("timestamp", ""),
                    agent_did=last.get("agent_did"),
                    agent_name=None,
                    source_ip=last.get("source_ip"),
                    title="Shadow agent: Invalid credentials",
                    description=(
                        f"Agent presented invalid or insufficient credentials "
                        f"({count} attempt(s))"
                    ),
                    evidence={
                        "attempt_count": count,
                        "reason": "VP verification failed or delegation missing",
                        "agent_dids": list(
                            {e.get("agent_did") for e in invalid_vp if e.get("agent_did")}
                        ),
                    },
                    recommended_action="Review agent VP configuration and delegation chain",
                )
            )

        if other:
            count = len(other)
            last = other[-1]
            reasons = list({e.get("auth_reason", "unknown") for e in other})
            alerts.append(
                DetectionAlert(
                    alert_type=AlertType.SHADOW_AGENT,
                    severity=AlertSeverity.WARNING,
                    timestamp=last.get("timestamp", ""),
                    agent_did=last.get("agent_did"),
                    agent_name=None,
                    source_ip=last.get("source_ip"),
                    title="Shadow agent: Authentication failure",
                    description=f"Unknown auth failure ({count} attempt(s)): {reasons[0]}",
                    evidence={"attempt_count": count, "reasons": reasons},
                    recommended_action="Investigate auth failure cause",
                )
            )

        return alerts
