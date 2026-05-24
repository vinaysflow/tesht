"""Tests for gateway.audit."""
from gateway.audit import GatewayAuditWriter
from gateway.auth import GatewayAuthResult
from gateway.proxy import ProxyResult
from gateway.scope import ScopeCheckResult
from gateway.trust import TrustEvaluation


def _auth(agent_did="did:key:a", delegator_did="did:key:d", blended=True):
    return GatewayAuthResult(
        authenticated=True,
        agent_did=agent_did,
        agent_name="TestBot",
        delegator_did=delegator_did,
        delegator_claims={"name": "Alice", "role": "Buyer"},
        blended=blended,
        auth_latency_ms=1.5,
    )


def _trust(score=85):
    return TrustEvaluation(
        score=score, decision="allow", factors={},
        cached=False, explanation="ok", latency_ms=0.1,
    )


def _scope(allowed=True):
    return ScopeCheckResult(
        allowed=allowed, tool_name="query_database",
        required_action="read_data", reason="allowed",
    )


def _proxy():
    return ProxyResult(status_code=200, body=b"{}", headers={}, latency_ms=3.0)


class TestGatewayAuditWriter:
    def test_allowed_request_audited(self):
        w = GatewayAuditWriter()
        w.log_request("r1", "db", "tools/call", "query_database",
                       _auth(), _trust(), _scope(), _proxy(), "allowed", 5.0)
        events = w.get_recent_events()
        assert len(events) == 1
        assert events[0]["decision"] == "allowed"
        assert events[0]["request_id"] == "r1"

    def test_blocked_request_audited(self):
        w = GatewayAuditWriter()
        w.log_request("r2", "db", "tools/call", "delete_record",
                       _auth(), _trust(0), _scope(False), None, "blocked_scope", 1.0)
        events = w.get_recent_events()
        assert events[0]["decision"] == "blocked_scope"
        assert events[0]["proxy_status"] is None

    def test_audit_contains_both_identities(self):
        w = GatewayAuditWriter()
        w.log_request("r3", "db", "tools/call", "q",
                       _auth(), _trust(), _scope(), _proxy(), "allowed", 5.0)
        e = w.get_recent_events()[0]
        assert e["agent_did"] == "did:key:a"
        assert e["delegator_did"] == "did:key:d"
        assert e["delegator_claims"]["name"] == "Alice"
        assert e["blended"] is True

    def test_audit_contains_trust_score(self):
        w = GatewayAuditWriter()
        w.log_request("r4", "db", "tools/call", "q",
                       _auth(), _trust(92), _scope(), _proxy(), "allowed", 5.0)
        assert w.get_recent_events()[0]["trust_score"] == 92

    def test_audit_contains_timing(self):
        w = GatewayAuditWriter()
        w.log_request("r5", "db", "tools/call", "q",
                       _auth(), _trust(), _scope(), _proxy(), "allowed", 7.5)
        e = w.get_recent_events()[0]
        assert e["total_latency_ms"] == 7.5
        assert e["auth_latency_ms"] == 1.5
        assert e["proxy_latency_ms"] == 3.0

    def test_get_events_for_agent(self):
        w = GatewayAuditWriter()
        w.log_request("r6", "db", "m", "t",
                       _auth(agent_did="did:key:x"), _trust(), _scope(), _proxy(), "allowed", 1.0)
        w.log_request("r7", "db", "m", "t",
                       _auth(agent_did="did:key:y"), _trust(), _scope(), _proxy(), "allowed", 1.0)
        assert len(w.get_events_for_agent("did:key:x")) == 1
        assert len(w.get_events_for_agent("did:key:y")) == 1
        assert len(w.get_events_for_agent("did:key:z")) == 0

    def test_get_recent_events_limit(self):
        w = GatewayAuditWriter()
        for i in range(10):
            w.log_request(f"r{i}", "db", "m", "t",
                           _auth(), _trust(), _scope(), _proxy(), "allowed", 1.0)
        assert len(w.get_recent_events(3)) == 3
