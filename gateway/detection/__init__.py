"""
gateway.detection
~~~~~~~~~~~~~~~~~
Lightweight agent detection for the MCP Identity Gateway.
"""
from gateway.detection.alerts import (
    AlertSeverity,
    AlertType,
    DetectionAlert,
    DetectionScanResult,
    FleetSummary,
)
from gateway.detection.engine import DetectionEngine
from gateway.detection.inventory import AgentInventory, AgentRecord, ShadowAttempt

__all__ = [
    "AlertSeverity",
    "AlertType",
    "DetectionAlert",
    "DetectionEngine",
    "DetectionScanResult",
    "FleetSummary",
    "AgentInventory",
    "AgentRecord",
    "ShadowAttempt",
]
