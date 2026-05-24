"""Tests for gateway.trust — dynamic behavioral trust scoring."""
from __future__ import annotations

import time

import pytest

from gateway.auth import GatewayAuthResult
from gateway.config import TrustConfig
from gateway.trust import CachedTrustScore, GatewayTrustEvaluator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth(authenticated=True, blended=True, depth=1):
    """Build a minimal GatewayAuthResult for trust testing."""
    from unittest.mock import MagicMock
    raw = MagicMock()
    raw.delegation = MagicMock()
    raw.delegation.chain = [{"delegator": "did:key:x"}] * depth
    return GatewayAuthResult(
        authenticated=authenticated,
        agent_did="did:key:test-agent",
        blended=blended,
        raw_result=raw,
    )


def _fresh_ev(config=None) -> GatewayTrustEvaluator:
    return GatewayTrustEvaluator(config or TrustConfig(allow_threshold=75, step_up_threshold=50, cache_ttl_seconds=60))


def _prime(ev: GatewayTrustEvaluator, did: str, n_requests: int = 5, tool: str = "query_database") -> None:
    """Prime the evaluator cache for *did* with *n_requests* known-tool calls."""
    ev.evaluate(did, _auth(), tool_name=tool, vp_hash="vp-hash-1")
    for _ in range(n_requests - 1):
        ev.update_from_request(did, tool, success=True)
        ev._cache[did].request_count += 1


# ---------------------------------------------------------------------------
# 1. Base scoring (unchanged from original model)
# ---------------------------------------------------------------------------

class TestBaseScoring:
    def test_initial_score_matches_base(self):
        ev = _fresh_ev()
        result = ev.evaluate("did:key:a", _auth())
        assert result.cached is False
        assert result.score == result.factors["credential_validity"] + \
               result.factors["delegation_depth"] + \
               result.factors["issuer_reputation"] + \
               result.factors["agent_history"]

    def test_high_trust_allows(self):
        ev = _fresh_ev()
        result = ev.evaluate("did:key:a", _auth())
        assert result.decision == "allow"
        assert result.score >= 75

    def test_unauthenticated_blocks(self):
        ev = _fresh_ev()
        result = ev.evaluate("did:key:a", _auth(authenticated=False))
        assert result.decision == "block"
        assert result.score == 0

    def test_deep_delegation_lowers_base_score(self):
        ev = _fresh_ev()
        shallow = ev.evaluate("did:key:s", _auth(depth=1))
        deep = ev.evaluate("did:key:d", _auth(depth=4))
        assert shallow.score > deep.score
        assert deep.factors["delegation_depth"] < shallow.factors["delegation_depth"]

    def test_non_blended_lower_issuer_score(self):
        ev = _fresh_ev()
        blended = ev.evaluate("did:key:b", _auth(blended=True))
        plain = ev.evaluate("did:key:p", _auth(blended=False))
        assert blended.factors["issuer_reputation"] > plain.factors["issuer_reputation"]

    def test_cache_hit_fast(self):
        ev = _fresh_ev()
        ev.evaluate("did:key:c", _auth())
        t0 = time.monotonic()
        result = ev.evaluate("did:key:c", _auth())
        elapsed = (time.monotonic() - t0) * 1000
        assert result.cached is True
        assert elapsed < 5.0

    def test_cache_expiry(self):
        ev = GatewayTrustEvaluator(TrustConfig(cache_ttl_seconds=0))
        ev.evaluate("did:key:e", _auth())
        time.sleep(0.01)
        result = ev.evaluate("did:key:e", _auth())
        assert result.cached is False

    def test_invalidate(self):
        ev = _fresh_ev()
        ev.evaluate("did:key:i", _auth())
        ev.invalidate("did:key:i")
        result = ev.evaluate("did:key:i", _auth())
        assert result.cached is False

    def test_step_up_range(self):
        ev = GatewayTrustEvaluator(TrustConfig(allow_threshold=90, step_up_threshold=50))
        result = ev.evaluate("did:key:s", _auth(blended=False, depth=4))
        assert result.decision in ("step_up", "block")


# ---------------------------------------------------------------------------
# 2. update_from_request — basic tracking
# ---------------------------------------------------------------------------

class TestUpdateFromRequest:
    def test_increments_request_count(self):
        ev = _fresh_ev()
        ev.evaluate("did:key:u", _auth())
        ev.update_from_request("did:key:u", "query_database", True)
        assert ev._cache["did:key:u"].request_count == 2

    def test_adds_to_tools_accessed(self):
        ev = _fresh_ev()
        ev.evaluate("did:key:u", _auth())
        ev.update_from_request("did:key:u", "query_database", True)
        assert "query_database" in ev._cache["did:key:u"].tools_accessed

    def test_tracks_success_count(self):
        ev = _fresh_ev()
        ev.evaluate("did:key:u", _auth())
        ev.update_from_request("did:key:u", "tool", True)
        ev.update_from_request("did:key:u", "tool", False)
        c = ev._cache["did:key:u"]
        assert c.success_count == 1
        assert c.failure_count == 1

    def test_noop_for_unknown_agent(self):
        ev = _fresh_ev()
        ev.update_from_request("did:key:unknown", "tool", True)  # should not raise


# ---------------------------------------------------------------------------
# 3. Tool Pattern Deviation
# ---------------------------------------------------------------------------

class TestToolPatternPenalty:
    def test_known_tool_no_penalty(self):
        ev = _fresh_ev()
        did = "did:key:tp1"
        _prime(ev, did, n_requests=5, tool="query_database")
        # query_database is already in tools_accessed — no penalty
        r = ev.evaluate(did, _auth(), tool_name="query_database", vp_hash="vp-hash-1")
        assert r.factors["tool_pattern_penalty"] == 0

    def test_novel_tool_no_penalty_before_history(self):
        ev = _fresh_ev()
        did = "did:key:tp2"
        # Only 1 request in history (request_count <= 3)
        ev.evaluate(did, _auth(), tool_name="query_database", vp_hash="vp-hash-1")
        r = ev.evaluate(did, _auth(), tool_name="send_email", vp_hash="vp-hash-1")
        assert r.factors["tool_pattern_penalty"] == 0

    def test_novel_tool_first_access_mild_penalty(self):
        ev = _fresh_ev()
        did = "did:key:tp3"
        _prime(ev, did, n_requests=5, tool="query_database")
        r = ev.evaluate(did, _auth(), tool_name="send_email", vp_hash="vp-hash-1")
        assert r.factors["tool_pattern_penalty"] == 5

    def test_novel_tool_second_access_moderate_penalty(self):
        ev = _fresh_ev()
        did = "did:key:tp4"
        _prime(ev, did, n_requests=5, tool="query_database")
        ev.evaluate(did, _auth(), tool_name="send_email", vp_hash="vp-hash-1")
        r = ev.evaluate(did, _auth(), tool_name="write_file", vp_hash="vp-hash-1")
        assert r.factors["tool_pattern_penalty"] == 10

    def test_novel_tool_third_access_severe_penalty(self):
        ev = _fresh_ev()
        did = "did:key:tp5"
        _prime(ev, did, n_requests=5, tool="query_database")
        ev.evaluate(did, _auth(), tool_name="send_email", vp_hash="vp-hash-1")
        ev.evaluate(did, _auth(), tool_name="write_file", vp_hash="vp-hash-1")
        r = ev.evaluate(did, _auth(), tool_name="delete_record", vp_hash="vp-hash-1")
        assert r.factors["tool_pattern_penalty"] == 15

    def test_novel_tools_tracked_in_factors(self):
        ev = _fresh_ev()
        did = "did:key:tp6"
        _prime(ev, did, n_requests=5, tool="query_database")
        ev.evaluate(did, _auth(), tool_name="send_email", vp_hash="vp-hash-1")
        r = ev.evaluate(did, _auth(), tool_name="write_file", vp_hash="vp-hash-1")
        assert "send_email" in r.factors["novel_tools"]


# ---------------------------------------------------------------------------
# 4. Velocity Anomaly
# ---------------------------------------------------------------------------

class TestVelocityPenalty:
    def test_normal_rate_no_penalty(self):
        ev = _fresh_ev()
        did = "did:key:vel1"
        # Prime with >10 requests but spread over time (fake old timestamps)
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        cached.request_count = 15
        # Timestamps far in the past — outside 60s window
        old_time = time.monotonic() - 120
        cached.request_timestamps = [old_time] * 15
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["velocity_penalty"] == 0

    def test_velocity_spike_moderate_penalty(self):
        ev = _fresh_ev()
        did = "did:key:vel2"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        cached.request_count = 50
        now = time.monotonic()
        # 35 requests in the last 60 seconds → >30 rpm
        cached.request_timestamps = [now - i * 1.5 for i in range(35)]
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["velocity_penalty"] == 10

    def test_velocity_spike_severe_penalty(self):
        ev = _fresh_ev()
        did = "did:key:vel3"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        cached.request_count = 70
        now = time.monotonic()
        # 65 requests in the last 60 seconds → >60 rpm
        cached.request_timestamps = [now - i * 0.9 for i in range(65)]
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["velocity_penalty"] == 20

    def test_velocity_baseline_no_penalty(self):
        ev = _fresh_ev()
        did = "did:key:vel4"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        # Only 5 requests — still in baseline
        cached.request_count = 5
        now = time.monotonic()
        cached.request_timestamps = [now - i for i in range(5)]
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["velocity_penalty"] == 0

    def test_old_timestamps_pruned(self):
        ev = _fresh_ev()
        did = "did:key:vel5"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        cached.request_count = 20
        old = time.monotonic() - 120
        fresh = time.monotonic() - 5
        cached.request_timestamps = [old] * 10 + [fresh] * 5
        ev.evaluate(did, _auth(), vp_hash="vp1")
        # Old timestamps should be pruned
        assert all(time.monotonic() - t < 70 for t in cached.request_timestamps)


# ---------------------------------------------------------------------------
# 5. Scope Boundary Probing
# ---------------------------------------------------------------------------

class TestScopeProbe:
    def test_no_violations_no_penalty(self):
        ev = _fresh_ev()
        did = "did:key:sp1"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["scope_probe_penalty"] == 0
        assert r.factors["scope_violations"] == 0

    def test_first_violation_mild_penalty(self):
        ev = _fresh_ev()
        did = "did:key:sp2"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        ev.record_scope_violation(did, "delete_record")
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["scope_probe_penalty"] == 5
        assert r.factors["scope_violations"] == 1

    def test_second_violation_moderate_penalty(self):
        ev = _fresh_ev()
        did = "did:key:sp3"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        ev.record_scope_violation(did, "delete_record")
        ev.record_scope_violation(did, "delete_record")
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["scope_probe_penalty"] == 15

    def test_third_violation_severe_penalty(self):
        ev = _fresh_ev()
        did = "did:key:sp4"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        for _ in range(3):
            ev.record_scope_violation(did, "delete_record")
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.factors["scope_probe_penalty"] == 25

    def test_scope_violation_recorded_correctly(self):
        ev = _fresh_ev()
        did = "did:key:sp5"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        ev.record_scope_violation(did, "delete_record")
        cached = ev._cache[did]
        assert cached.scope_violations == 1
        assert "delete_record" in cached.scope_violation_tools

    def test_record_violation_noop_for_unknown_agent(self):
        ev = _fresh_ev()
        ev.record_scope_violation("did:key:unknown", "tool")  # should not raise


# ---------------------------------------------------------------------------
# 6. Penalty accumulation and score clamping
# ---------------------------------------------------------------------------

class TestPenaltyAccumulation:
    def test_penalties_accumulate_across_requests(self):
        ev = _fresh_ev()
        did = "did:key:pa1"
        _prime(ev, did, n_requests=5, tool="query_database")
        # Two scope violations
        ev.record_scope_violation(did, "delete_record")
        ev.record_scope_violation(did, "delete_record")
        r = ev.evaluate(did, _auth(), vp_hash="vp-hash-1")
        # scope_probe_penalty at 2 violations = 15, accumulated on top of any prior
        assert r.factors["behavioral_penalty"] > 0
        assert r.score < r.factors["credential_validity"] + r.factors["delegation_depth"] + \
               r.factors["issuer_reputation"] + r.factors["agent_history"]

    def test_score_never_below_zero(self):
        ev = _fresh_ev()
        did = "did:key:pa2"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        cached.penalty = 9999  # extreme penalty
        assert cached.score == 0

    def test_score_never_above_100(self):
        ev = _fresh_ev()
        did = "did:key:pa3"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        cached.base_score = 150
        cached.penalty = 0
        assert cached.score == 100

    def test_base_score_stable_after_penalties(self):
        ev = _fresh_ev()
        did = "did:key:pa4"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        original_base = cached.base_score
        cached.penalty = 10
        assert cached.base_score == original_base


# ---------------------------------------------------------------------------
# 7. Fresh VP recovery
# ---------------------------------------------------------------------------

class TestFreshVPRecovery:
    def test_fresh_vp_reduces_penalty(self):
        ev = _fresh_ev()
        did = "did:key:rv1"
        ev.evaluate(did, _auth(), vp_hash="vp-old")
        ev._cache[did].penalty = 30
        # Present a fresh VP with a different hash
        ev.evaluate(did, _auth(), vp_hash="vp-new")
        assert ev._cache[did].penalty == 10  # 30 - 20 = 10

    def test_fresh_vp_resets_scope_violations(self):
        ev = _fresh_ev()
        did = "did:key:rv2"
        ev.evaluate(did, _auth(), vp_hash="vp-old")
        ev.record_scope_violation(did, "delete_record")
        ev.record_scope_violation(did, "delete_record")
        ev.evaluate(did, _auth(), vp_hash="vp-new")
        assert ev._cache[did].scope_violations == 0

    def test_fresh_vp_resets_novel_tools(self):
        ev = _fresh_ev()
        did = "did:key:rv3"
        _prime(ev, did, n_requests=5, tool="query_database")
        ev.evaluate(did, _auth(), tool_name="send_email", vp_hash="vp-old")
        assert len(ev._cache[did].novel_tools) == 1
        ev.evaluate(did, _auth(), vp_hash="vp-new")
        assert len(ev._cache[did].novel_tools) == 0

    def test_repeated_reauth_still_accumulates(self):
        ev = _fresh_ev()
        did = "did:key:rv4"
        ev.evaluate(did, _auth(), vp_hash="vp-1")
        ev._cache[did].penalty = 40
        # First re-auth: 40 - 20 = 20
        ev.evaluate(did, _auth(), vp_hash="vp-2")
        assert ev._cache[did].penalty == 20
        ev._cache[did].penalty += 25
        # Second re-auth: 45 - 20 = 25
        ev.evaluate(did, _auth(), vp_hash="vp-3")
        assert ev._cache[did].penalty == 25

    def test_same_vp_hash_no_penalty_reset(self):
        ev = _fresh_ev()
        did = "did:key:rv5"
        ev.evaluate(did, _auth(), vp_hash="vp-same")
        ev._cache[did].penalty = 15
        ev.evaluate(did, _auth(), vp_hash="vp-same")
        assert ev._cache[did].penalty >= 15  # no reset with same hash

    def test_penalty_clamped_to_zero_on_recovery(self):
        ev = _fresh_ev()
        did = "did:key:rv6"
        ev.evaluate(did, _auth(), vp_hash="vp-old")
        ev._cache[did].penalty = 5  # penalty less than the 20 reduction
        ev.evaluate(did, _auth(), vp_hash="vp-new")
        assert ev._cache[did].penalty == 0  # max(0, 5-20) = 0


# ---------------------------------------------------------------------------
# 8. Decision thresholds with degraded scores
# ---------------------------------------------------------------------------

class TestDecisionThresholds:
    def test_degraded_to_step_up(self):
        ev = _fresh_ev(TrustConfig(allow_threshold=75, step_up_threshold=50, cache_ttl_seconds=60))
        did = "did:key:dt1"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        base = cached.base_score
        # Degrade to between 50-74
        cached.penalty = base - 62
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.decision == "step_up"
        assert 50 <= r.score < 75

    def test_degraded_to_block(self):
        ev = _fresh_ev(TrustConfig(allow_threshold=75, step_up_threshold=50, cache_ttl_seconds=60))
        did = "did:key:dt2"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        cached = ev._cache[did]
        base = cached.base_score
        # Degrade below 50
        cached.penalty = base - 30
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert r.decision == "block"
        assert r.score < 50

    def test_recovery_allows_after_reauth(self):
        ev = _fresh_ev(TrustConfig(allow_threshold=75, step_up_threshold=50, cache_ttl_seconds=60))
        did = "did:key:dt3"
        ev.evaluate(did, _auth(), vp_hash="vp-old")
        cached = ev._cache[did]
        base = cached.base_score
        # Degrade to step-up range
        cached.penalty = base - 62
        r1 = ev.evaluate(did, _auth(), vp_hash="vp-old")
        assert r1.decision == "step_up"
        # Re-authenticate with fresh VP → penalty drops 20 → score improves
        r2 = ev.evaluate(did, _auth(), vp_hash="vp-new")
        # Score should be higher now
        assert r2.score > r1.score

    def test_explanation_includes_penalty_info(self):
        ev = _fresh_ev()
        did = "did:key:dt4"
        ev.evaluate(did, _auth(), vp_hash="vp1")
        ev._cache[did].penalty = 10
        ev.record_scope_violation(did, "delete")
        r = ev.evaluate(did, _auth(), vp_hash="vp1")
        assert "Behavioral penalty" in r.explanation or "penalty" in r.explanation.lower()
