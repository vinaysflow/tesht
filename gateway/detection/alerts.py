"""
gateway.detection.alerts
~~~~~~~~~~~~~~~~~~~~~~~~
Data structures for detection alerts and fleet summaries.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    SHADOW_AGENT = "shadow_agent"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    SCOPE_PROBING = "scope_probing"
    VELOCITY_SPIKE = "velocity_spike"
    CREDENTIAL_HEALTH = "credential_health"
    FLEET_THREAT = "fleet_threat"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DetectionAlert:
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    evidence: dict[str, Any]
    recommended_action: str
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(default_factory=_now_iso)
    agent_did: Optional[str] = None
    agent_name: Optional[str] = None
    source_ip: Optional[str] = None


@dataclass
class FleetSummary:
    total_agents_seen: int
    verified_agents: int
    shadow_attempts: int
    agents_with_violations: int
    agents_with_penalties: int
    agents_in_step_up: int
    agents_blocked: int
    avg_trust_score: float
    risk_distribution: dict[str, int]
    top_alerts: list[DetectionAlert] = field(default_factory=list)


@dataclass
class DetectionScanResult:
    alerts: list[DetectionAlert]
    fleet_summary: FleetSummary
    inventory_stats: dict[str, Any]
    scanned_at: str = field(default_factory=_now_iso)
