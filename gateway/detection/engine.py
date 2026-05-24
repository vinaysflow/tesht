"""
gateway.detection.engine
~~~~~~~~~~~~~~~~~~~~~~~~
DetectionEngine — the central orchestrator for lightweight agent detection.

Reads from the existing GatewayAuditWriter and GatewayTrustEvaluator without
modifying their internals (purely additive). Runs on-demand when the detection
endpoint is hit — no background tasks.

Usage:
    engine = DetectionEngine(audit_writer, trust_evaluator)

    # Register outcomes as they happen (called from app.py):
    engine.register_successful_auth(auth_result, source_ip="1.2.3.4")
    engine.register_failed_auth("Missing Authorization header", source_ip="5.6.7.8")

    # Run full scan on demand:
    result = engine.scan()
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from gateway.audit import GatewayAuditWriter
from gateway.auth import GatewayAuthResult
from gateway.detection.alerts import (
    AlertSeverity,
    DetectionAlert,
    DetectionScanResult,
)
from gateway.detection.behavior import BehavioralDetector
from gateway.detection.fleet import FleetCorrelator
from gateway.detection.inventory import AgentInventory
from gateway.detection.shadow import ShadowDetector
from gateway.trust import GatewayTrustEvaluator

_SEVERITY_ORDER = {
    AlertSeverity.CRITICAL: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.INFO: 2,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DetectionEngine:
    """Lightweight detection engine. Purely additive — reads existing data."""

    def __init__(
        self,
        audit_writer: GatewayAuditWriter,
        trust_evaluator: GatewayTrustEvaluator,
    ) -> None:
        self.audit = audit_writer
        self.trust = trust_evaluator
        self.inventory = AgentInventory()
        self._shadow_detector = ShadowDetector()
        self._behavioral_detector = BehavioralDetector()
        self._fleet_correlator = FleetCorrelator()

    # ------------------------------------------------------------------
    # Registration — called from app.py on every request
    # ------------------------------------------------------------------

    def register_successful_auth(
        self,
        auth_result: GatewayAuthResult,
        source_ip: Optional[str] = None,
    ) -> None:
        """Register a successfully authenticated agent in the inventory."""
        if auth_result.agent_did:
            self.inventory.register_agent(
                agent_did=auth_result.agent_did,
                agent_name=auth_result.agent_name,
                delegator_did=auth_result.delegator_did,
                first_seen=_now_iso(),
            )

    def register_failed_auth(
        self,
        reason: str,
        source_ip: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> None:
        """Record a failed auth attempt — marks this as a shadow access attempt."""
        self.inventory.record_shadow_attempt(
            reason=reason,
            timestamp_iso=_now_iso(),
            source_ip=source_ip,
            server_name=server_name,
        )

    # ------------------------------------------------------------------
    # On-demand scan
    # ------------------------------------------------------------------

    def scan(self) -> DetectionScanResult:
        """Run all detectors and return combined results.

        Called on-demand when GET /gateway/detections is hit.
        Scans the last 200 audit events and all live trust cache entries.
        """
        recent_events = self.audit.get_recent_events(200)

        all_alerts: list[DetectionAlert] = []

        # 1. Shadow agent detection (reads audit events for blocked_auth)
        shadow_alerts = self._shadow_detector.classify(recent_events, self.inventory)
        all_alerts.extend(shadow_alerts)

        # 2. Behavioral anomaly detection (reads trust cache)
        behavior_alerts = self._behavioral_detector.analyze(
            self.trust._cache, self.inventory
        )
        all_alerts.extend(behavior_alerts)

        # 3. Fleet-level correlation (reads trust cache + audit events)
        fleet_summary, fleet_alerts = self._fleet_correlator.analyze(
            self.trust._cache, recent_events, self.inventory
        )
        all_alerts.extend(fleet_alerts)

        # Sort critical first
        all_alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a.severity, 99))

        return DetectionScanResult(
            alerts=all_alerts,
            fleet_summary=fleet_summary,
            inventory_stats=self.inventory.stats(),
            scanned_at=_now_iso(),
        )
