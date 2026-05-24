"""
Tests for the lightweight detection engine.

Covers shadow detection, behavioral anomaly detection, fleet correlation,
inventory tracking, and integration with the gateway app endpoints.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import httpx
import pytest

from pramana.credentials import create_blended_presentation, issue_vc
from pramana.delegation import issue_delegation
from pramana.identity import AgentIdentity

from gateway.audit import GatewayAuditWriter
from gateway.auth import GatewayAuth, GatewayAuthResult
from gateway.config import AuthSettings, GatewayConfig, TrustConfig, UpstreamServer
from gateway.detection.alerts import AlertSeverity, AlertType
from gateway.detection.behavior import BehavioralDetector
from gateway.detection.engine import DetectionEngine
from gateway.detection.fleet import FleetCorrelator
from gateway.detection.inventory import AgentInventory
from gateway.detection.shadow import ShadowDetector
from gateway.proxy import MCPProxy
from gateway.scope import ScopeChecker
from gateway.trust import CachedTrustScore, GatewayTrustEvaluator


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _blocked_auth_event(reason: str, agent_did: str | None = None,
                        source_ip: str | None = None) -> dict:
    return {
        "decision": "blocked_auth",
        "auth_reason": reason,
        "agent_did": agent_did,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _make_cached(
    base_score: int = 80,
    penalty: int = 0,
    scope_violations: int = 0,
    scope_violation_tools: list | None = None,
    novel_tools: list | None = None,
    failure_count: int = 0,
    request_count: int = 5,
    request_timestamps: list | None = None,
) -> CachedTrustScore:
    return CachedTrustScore(
        base_score=base_score,
        base_factors={"credential_validity": 25, "delegation_depth": 20,
                      "issuer_reputation": 20, "agent_history": 15},
        computed_at=time.monotonic(),
        request_count=request_count,
        tools_accessed=set(),
        request_timestamps=list(request_timestamps or []),
        success_count=request_count - failure_count,
        failure_count=failure_count,
        scope_violations=scope_violations,
        scope_violation_tools=list(scope_violation_tools or []),
        novel_tools=list(novel_tools or []),
        penalty=penalty,
    )


def _make_failed_auth_result(reason: str) -> GatewayAuthResult:
    return GatewayAuthResult(
        authenticated=False,
        reason=reason,
        auth_latency_ms=1.0,
    )


# ---------------------------------------------------------------------------
# Shadow detection tests
# ---------------------------------------------------------------------------

class TestShadowDetector:
    def test_shadow_agent_no_auth_detected(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [_blocked_auth_event("Missing Authorization header") for _ in range(3)]
        alerts = detector.classify(events, inventory)
        assert len(alerts) == 1
        assert alerts[0].alert_type == AlertType.SHADOW_AGENT
        assert alerts[0].severity == AlertSeverity.CRITICAL
        assert "No credentials" in alerts[0].title

    def test_shadow_agent_below_threshold_is_warning(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [_blocked_auth_event("Missing Authorization header")]
        alerts = detector.classify(events, inventory)
        assert alerts[0].severity == AlertSeverity.WARNING

    def test_shadow_agent_untrusted_issuer_detected(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [_blocked_auth_event("Untrusted issuer: did:key:abc")]
        alerts = detector.classify(events, inventory)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.CRITICAL
        assert "Untrusted issuer" in alerts[0].title

    def test_shadow_agent_invalid_vp_detected(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [_blocked_auth_event("VP verification failed: signature invalid")]
        alerts = detector.classify(events, inventory)
        assert len(alerts) == 1
        assert alerts[0].alert_type == AlertType.SHADOW_AGENT
        assert "Invalid credentials" in alerts[0].title

    def test_shadow_agent_delegation_required_classified_as_invalid(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [_blocked_auth_event("Delegation required but not present")]
        alerts = detector.classify(events, inventory)
        assert len(alerts) == 1
        assert "Invalid credentials" in alerts[0].title

    def test_no_shadow_when_no_blocked_auth_events(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [
            {"decision": "allowed", "agent_did": "did:key:abc", "timestamp": "2024"},
        ]
        alerts = detector.classify(events, inventory)
        assert alerts == []

    def test_multiple_shadow_categories_produce_separate_alerts(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [
            _blocked_auth_event("Missing Authorization header"),
            _blocked_auth_event("Untrusted issuer: x"),
            _blocked_auth_event("VP verification failed: expired"),
        ]
        alerts = detector.classify(events, inventory)
        types = [a.title for a in alerts]
        assert any("No credentials" in t for t in types)
        assert any("Untrusted" in t for t in types)
        assert any("Invalid" in t for t in types)

    def test_evidence_contains_attempt_count(self):
        detector = ShadowDetector()
        inventory = AgentInventory()
        events = [_blocked_auth_event("Missing Authorization header") for _ in range(5)]
        alerts = detector.classify(events, inventory)
        assert alerts[0].evidence["attempt_count"] == 5


# ---------------------------------------------------------------------------
# Behavioral detection tests
# ---------------------------------------------------------------------------

class TestBehavioralDetector:
    def test_high_penalty_agent_flagged_as_warning(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        cache = {"did:key:agent1": _make_cached(penalty=25)}
        alerts = detector.analyze(cache, inventory)
        penalty_alerts = [a for a in alerts if a.alert_type == AlertType.BEHAVIORAL_ANOMALY]
        assert len(penalty_alerts) == 1
        assert penalty_alerts[0].severity == AlertSeverity.WARNING

    def test_high_penalty_agent_critical_at_threshold(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        cache = {"did:key:agent1": _make_cached(penalty=40)}
        alerts = detector.analyze(cache, inventory)
        penalty_alerts = [a for a in alerts if a.alert_type == AlertType.BEHAVIORAL_ANOMALY]
        assert penalty_alerts[0].severity == AlertSeverity.CRITICAL

    def test_scope_probing_agent_flagged(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        cache = {
            "did:key:agent1": _make_cached(
                scope_violations=3,
                scope_violation_tools=["delete_record", "admin_panel", "export_data"],
            )
        }
        alerts = detector.analyze(cache, inventory)
        probe_alerts = [a for a in alerts if a.alert_type == AlertType.SCOPE_PROBING]
        assert len(probe_alerts) == 1
        assert probe_alerts[0].severity == AlertSeverity.CRITICAL
        assert "delete_record" in str(probe_alerts[0].evidence)

    def test_velocity_spike_agent_flagged(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        now = time.monotonic()
        # Simulate 35 requests in the last 60 seconds
        timestamps = [now - i * 1.5 for i in range(35)]
        cache = {"did:key:agent1": _make_cached(
            request_timestamps=timestamps, request_count=40
        )}
        alerts = detector.analyze(cache, inventory)
        vel_alerts = [a for a in alerts if a.alert_type == AlertType.VELOCITY_SPIKE]
        assert len(vel_alerts) == 1
        assert vel_alerts[0].severity == AlertSeverity.WARNING

    def test_velocity_spike_critical_above_60rpm(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        now = time.monotonic()
        timestamps = [now - i * 0.8 for i in range(65)]
        cache = {"did:key:agent1": _make_cached(
            request_timestamps=timestamps, request_count=70
        )}
        alerts = detector.analyze(cache, inventory)
        vel_alerts = [a for a in alerts if a.alert_type == AlertType.VELOCITY_SPIKE]
        assert vel_alerts[0].severity == AlertSeverity.CRITICAL

    def test_normal_agent_no_alerts(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        cache = {"did:key:healthy": _make_cached(base_score=85, penalty=0)}
        alerts = detector.analyze(cache, inventory)
        assert alerts == []

    def test_agent_name_included_when_known(self):
        detector = BehavioralDetector()
        inventory = AgentInventory()
        inventory.register_agent("did:key:agent1", "ShoppingBot", None, "2024")
        cache = {"did:key:agent1": _make_cached(penalty=50)}
        alerts = detector.analyze(cache, inventory)
        behavioral = [a for a in alerts if a.alert_type == AlertType.BEHAVIORAL_ANOMALY]
        assert behavioral[0].agent_name == "ShoppingBot"


# ---------------------------------------------------------------------------
# Fleet correlation tests
# ---------------------------------------------------------------------------

class TestFleetCorrelator:
    def test_coordinated_probing_detected(self):
        correlator = FleetCorrelator()
        inventory = AgentInventory()
        cache = {
            "did:key:agent1": _make_cached(scope_violations=3),
            "did:key:agent2": _make_cached(scope_violations=2),
        }
        _, alerts = correlator.analyze(cache, [], inventory)
        fleet_alerts = [a for a in alerts if a.alert_type == AlertType.FLEET_THREAT]
        coordinated = [a for a in fleet_alerts if "Coordinated" in a.title]
        assert len(coordinated) == 1
        assert coordinated[0].severity == AlertSeverity.CRITICAL

    def test_no_coordinated_alert_with_single_violator(self):
        correlator = FleetCorrelator()
        inventory = AgentInventory()
        cache = {"did:key:agent1": _make_cached(scope_violations=5)}
        _, alerts = correlator.analyze(cache, [], inventory)
        coordinated = [a for a in alerts if "Coordinated" in a.title]
        assert len(coordinated) == 0

    def test_shadow_swarm_detected(self):
        correlator = FleetCorrelator()
        inventory = AgentInventory()
        now_iso = datetime.now(timezone.utc).isoformat()
        # Record 4 shadow attempts very recently
        for _ in range(4):
            inventory.record_shadow_attempt("Missing Authorization header", now_iso)
        _, alerts = correlator.analyze({}, [], inventory)
        swarm_alerts = [a for a in alerts if "swarm" in a.title.lower()]
        assert len(swarm_alerts) == 1
        assert swarm_alerts[0].severity == AlertSeverity.CRITICAL

    def test_shadow_swarm_not_triggered_below_threshold(self):
        correlator = FleetCorrelator()
        inventory = AgentInventory()
        now_iso = datetime.now(timezone.utc).isoformat()
        for _ in range(2):
            inventory.record_shadow_attempt("Missing Authorization header", now_iso)
        _, alerts = correlator.analyze({}, [], inventory)
        swarm_alerts = [a for a in alerts if "swarm" in a.title.lower()]
        assert len(swarm_alerts) == 0

    def test_fleet_trust_declining_detected(self):
        correlator = FleetCorrelator()
        inventory = AgentInventory()
        cache = {
            "did:key:a1": _make_cached(base_score=40, penalty=0),
            "did:key:a2": _make_cached(base_score=50, penalty=0),
            "did:key:a3": _make_cached(base_score=45, penalty=0),
        }
        _, alerts = correlator.analyze(cache, [], inventory)
        declining = [a for a in alerts if "declining" in a.title.lower()]
        assert len(declining) == 1
        assert declining[0].severity == AlertSeverity.WARNING

    def test_fleet_summary_counts_correct(self):
        correlator = FleetCorrelator()
        inventory = AgentInventory()
        inventory.register_agent("did:key:a1", "Bot1", None, "2024")
        inventory.register_agent("did:key:a2", "Bot2", None, "2024")
        now_iso = datetime.now(timezone.utc).isoformat()
        inventory.record_shadow_attempt("Missing Authorization header", now_iso)

        cache = {
            "did:key:a1": _make_cached(base_score=80, penalty=5, scope_violations=1),
            "did:key:a2": _make_cached(base_score=90, penalty=0),
        }
        summary, _ = correlator.analyze(cache, [], inventory)
        assert summary.total_agents_seen == 2
        assert summary.verified_agents == 2
        assert summary.shadow_attempts == 1
        assert summary.agents_with_violations == 1
        assert summary.agents_with_penalties == 1


# ---------------------------------------------------------------------------
# Inventory tests
# ---------------------------------------------------------------------------

class TestAgentInventory:
    def test_agent_registered_on_successful_auth(self):
        inv = AgentInventory()
        inv.register_agent("did:key:abc", "TestBot", "did:key:alice", "2024")
        assert inv.is_known("did:key:abc")

    def test_shadow_recorded_on_failed_auth(self):
        inv = AgentInventory()
        now_iso = datetime.now(timezone.utc).isoformat()
        inv.record_shadow_attempt("Missing Authorization header", now_iso, source_ip="1.2.3.4")
        attempts = inv.get_all_shadow_attempts()
        assert len(attempts) == 1
        assert attempts[0].source_ip == "1.2.3.4"

    def test_known_agent_returns_true(self):
        inv = AgentInventory()
        inv.register_agent("did:key:xyz", None, None, "2024")
        assert inv.is_known("did:key:xyz") is True

    def test_unknown_agent_returns_false(self):
        inv = AgentInventory()
        assert inv.is_known("did:key:nobody") is False

    def test_request_count_increments(self):
        inv = AgentInventory()
        for _ in range(3):
            inv.register_agent("did:key:bot", "Bot", None, "2024")
        assert inv._known_agents["did:key:bot"].request_count == 3

    def test_shadow_attempts_time_window(self):
        inv = AgentInventory()
        now_iso = datetime.now(timezone.utc).isoformat()
        inv.record_shadow_attempt("reason", now_iso)
        # Manually backdate the last attempt's monotonic time past the window
        inv._shadow_attempts[-1].timestamp_monotonic -= 120 * 60  # 120 minutes ago
        recent = inv.get_shadow_attempts(since_minutes=60)
        assert len(recent) == 0
        all_attempts = inv.get_all_shadow_attempts()
        assert len(all_attempts) == 1


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def detection_gateway_app():
    """Create a gateway app with detection engine initialized (no lifespan)."""
    from gateway.app import app

    config = GatewayConfig(
        upstream_servers={
            "mock_database": UpstreamServer(
                name="mock_database",
                url="http://127.0.0.1:19201/mcp",
                auth_type="api_key",
                credential="test-key",
                credential_header="X-API-Key",
                tool_scope_mapping={
                    "query_database": "read_data",
                    "delete_record": "admin",
                },
            ),
        },
        trust=TrustConfig(allow_threshold=75, step_up_threshold=50, cache_ttl_seconds=30),
        auth=AuthSettings(require_delegation=True, require_delegator_identity=True),
    )

    audit = GatewayAuditWriter()
    trust = GatewayTrustEvaluator(config.trust)

    app.state.config = config
    app.state.auth = GatewayAuth(config)
    app.state.trust = trust
    app.state.scope = ScopeChecker(config.upstream_servers)
    app.state.proxy = MCPProxy(config.upstream_servers)
    app.state.audit = audit
    app.state.detection = DetectionEngine(audit, trust)

    yield app


class TestDetectionIntegration:
    @pytest.mark.anyio
    async def test_detection_scan_returns_combined_results(self, detection_gateway_app):
        """Detection scan on a clean gateway returns empty results with correct structure."""
        detection_gateway_app.state.audit._events.clear()
        detection_gateway_app.state.trust._cache.clear()
        detection_gateway_app.state.detection = DetectionEngine(
            detection_gateway_app.state.audit,
            detection_gateway_app.state.trust,
        )

        engine = detection_gateway_app.state.detection
        result = engine.scan()
        assert hasattr(result, "alerts")
        assert hasattr(result, "fleet_summary")
        assert hasattr(result, "inventory_stats")
        assert isinstance(result.alerts, list)

    @pytest.mark.anyio
    async def test_detection_endpoint_returns_json(self, detection_gateway_app):
        """GET /gateway/detections returns valid JSON with expected keys."""
        transport = httpx.ASGITransport(app=detection_gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/gateway/detections")
        assert r.status_code == 200
        data = r.json()
        assert "alerts" in data
        assert "fleet" in data
        assert "inventory" in data
        assert "scanned_at" in data

    @pytest.mark.anyio
    async def test_inventory_endpoint_returns_agents_and_shadows(self, detection_gateway_app):
        """GET /gateway/inventory returns known_agents and shadow_attempts lists."""
        transport = httpx.ASGITransport(app=detection_gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/gateway/inventory")
        assert r.status_code == 200
        data = r.json()
        assert "known_agents" in data
        assert "shadow_attempts" in data
        assert isinstance(data["known_agents"], list)
        assert isinstance(data["shadow_attempts"], list)

    @pytest.mark.anyio
    async def test_shadow_attempt_registered_on_no_auth(self, detection_gateway_app):
        """A request with no auth header is recorded as a shadow attempt."""
        detection_gateway_app.state.detection.inventory._shadow_attempts.clear()

        transport = httpx.ASGITransport(app=detection_gateway_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            r = await c.post("/mcp/mock_database", content=body.encode())
            assert r.status_code == 401

            det_r = await c.get("/gateway/detections")
        data = det_r.json()
        # At least one shadow alert should now be present
        assert data["inventory"]["shadow_attempts_total"] >= 1

    @pytest.mark.anyio
    async def test_known_agent_registered_on_successful_auth(self, detection_gateway_app):
        """A successful auth registers the agent in the inventory."""
        idp = AgentIdentity.create("test-idp")
        alice = AgentIdentity.create("alice")
        bot = AgentIdentity.create("bot")

        alice_vc = issue_vc(
            issuer=idp, subject_did=alice.did,
            credential_type="OrganizationalRoleCredential",
            claims={"name": "Alice", "role": "Buyer", "organization": "Acme"},
        )
        bot_vc = issue_vc(
            issuer=idp, subject_did=bot.did,
            credential_type="AgentCredential",
            claims={"agentName": "TestBot", "ownerOrg": "Acme"},
        )
        deleg = issue_delegation(
            delegator=alice, delegate_did=bot.did,
            scope={"actions": ["read_data"], "max_amount": 1000, "currency": "USD",
                   "merchants": ["*"], "categories": []},
            max_depth=2,
        )
        gw_did = detection_gateway_app.state.auth.gateway_identity.did
        blended_vp = create_blended_presentation(
            agent=bot, delegation_jwt=deleg,
            delegator_identity_jwt=alice_vc,
            additional_credentials=[bot_vc],
            audience=gw_did,
        )

        # We can't proxy (mock MCP not running), but we can test the engine directly
        # by calling register_successful_auth with a synthetic result
        auth_result = GatewayAuthResult(
            authenticated=True,
            agent_did=bot.did,
            agent_name="TestBot",
            delegator_did=alice.did,
            auth_latency_ms=1.0,
        )
        detection_gateway_app.state.detection.register_successful_auth(auth_result)
        assert detection_gateway_app.state.detection.inventory.is_known(bot.did)
