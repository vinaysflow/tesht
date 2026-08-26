"""Unit tests for gateway fail-closed status checker and cold-path wiring."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from gateway.app import _env_truthy, _make_status_checker
from gateway.audit import GatewayAuditWriter
from gateway.config import TrustConfig, is_production, load_config
from gateway.trust import GatewayTrustEvaluator

_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.yaml"


def test_env_truthy():
    with patch.dict(os.environ, {"GATEWAY_FAIL_CLOSED": "1"}, clear=False):
        assert _env_truthy("GATEWAY_FAIL_CLOSED") is True
    with patch.dict(os.environ, {"GATEWAY_FAIL_CLOSED": "false"}, clear=False):
        assert _env_truthy("GATEWAY_FAIL_CLOSED") is False


def test_status_checker_fail_open_on_error():
    checker = _make_status_checker(fail_closed=False)
    with patch("httpx.get", side_effect=Exception("down")):
        # Import inside checker uses httpx — patch where used
        import gateway.app as app_mod

        with patch.object(app_mod, "_make_status_checker", wraps=_make_status_checker):
            pass
    # Direct: monkeypatch httpx inside the closure by calling with bad URL
    # The checker imports httpx locally — patch httpx.get globally
    with patch("httpx.get", side_effect=RuntimeError("boom")):
        assert checker("http://invalid.example/status", 0) is False


def test_status_checker_fail_closed_on_error():
    checker = _make_status_checker(fail_closed=True)
    with patch("httpx.get", side_effect=RuntimeError("boom")):
        assert checker("http://invalid.example/status", 0) is True


def test_status_checker_retries_before_failing():
    """The checker retries a transient error before deciding (avoids false revoke)."""
    checker = _make_status_checker(fail_closed=True)
    m = MagicMock(side_effect=RuntimeError("boom"))
    with patch("httpx.get", m):
        assert checker("http://invalid.example/status", 0) is True
    assert m.call_count >= 2  # bounded retry, not a single attempt


def test_cold_path_schedule_does_not_block():
    ev = GatewayTrustEvaluator(TrustConfig(cold_path_enabled=True, cache_ttl_seconds=30))
    auth = MagicMock()
    auth.authenticated = True
    auth.blended = True
    auth.raw_result = None

    result = ev.evaluate("did:key:zTestAgent", auth, tool_name="query_database")
    assert result.decision in {"allow", "step_up", "block"}
    assert 0 <= result.score <= 100
    ev.close()


def test_cold_path_pool_is_bounded():
    """Cold-path scheduling uses a bounded shared pool, not per-miss threads."""
    from concurrent.futures import ThreadPoolExecutor

    ev = GatewayTrustEvaluator(TrustConfig(cold_path_enabled=True))
    assert isinstance(ev._cold_path_pool, ThreadPoolExecutor)
    ev.close()


def test_is_production_env_switch():
    with patch.dict(os.environ, {"TESHT_ENV": "production"}, clear=False):
        assert is_production() is True
    with patch.dict(os.environ, {"TESHT_ENV": "development", "GATEWAY_ENV": ""}, clear=False):
        assert is_production() is False


def test_production_profile_flips_fail_closed():
    """With TESHT_ENV=production and no explicit YAML value, fail_closed flips true."""
    with patch.dict(os.environ, {"TESHT_ENV": "production", "GATEWAY_ENV": ""}, clear=False):
        cfg = load_config(_CONFIG_PATH)
        assert cfg.production is True
        assert cfg.auth.fail_closed is True
        assert cfg.trust.cold_path_enabled is True


def test_development_profile_is_fail_open():
    with patch.dict(os.environ, {"TESHT_ENV": "development", "GATEWAY_ENV": ""}, clear=False):
        cfg = load_config(_CONFIG_PATH)
        assert cfg.production is False
        assert cfg.auth.fail_closed is False


def test_audit_buffer_is_bounded():
    """In-memory audit buffer must not grow without bound."""
    writer = GatewayAuditWriter(max_events=5)
    auth = MagicMock()
    auth.agent_did = "did:key:zA"
    auth.agent_name = "a"
    auth.delegator_did = None
    auth.delegator_claims = {}
    auth.effective_scope = None
    auth.auth_latency_ms = 0.0
    auth.blended = True
    trust = MagicMock()
    trust.score = 90
    trust.decision = "allow"
    trust.factors = {}
    for i in range(20):
        writer.log_request(
            f"req{i}", "srv", "tools/call", "query_database",
            auth, trust, None, None, "allowed", 1.0,
        )
    assert len(writer._events) == 5
    assert len(writer.get_recent_events(50)) == 5
