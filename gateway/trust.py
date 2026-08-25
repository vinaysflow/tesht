"""
gateway.trust
~~~~~~~~~~~~~
Two-tier trust scoring for per-request gateway use.

Hot path:  in-memory cache with dynamic behavioral penalties (<1 ms).
Cold path: full ``compute_trust_score()`` runs async in a background thread
           and refreshes the cache base_score + persists a TrustEvent when
           a backend/DB path is available.

Trust score = base_score - accumulated_behavioral_penalties

Three behavioral signal types degrade the score in real-time:
  1. Tool Pattern Deviation  — agent accesses novel tools it has never used
  2. Velocity Anomaly        — sudden request-rate spike
  3. Scope Boundary Probing  — repeated attempts to access out-of-scope tools

A fresh VP presentation partially restores trust (penalty -= 20).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Optional

from gateway.auth import GatewayAuthResult
from gateway.config import TrustConfig

_logger = logging.getLogger(__name__)

# Cold-path tuning: bound the worker pool so a burst of distinct agents cannot
# spawn unbounded threads; retry the backend call to survive transient blips.
_COLD_PATH_MAX_WORKERS = 4
_COLD_PATH_HTTP_ATTEMPTS = 2
_COLD_PATH_HTTP_BACKOFF_SECONDS = 0.25


@dataclass
class CachedTrustScore:
    """In-memory cached trust evaluation for one agent.

    ``base_score`` is static (computed once from the auth context).
    ``penalty`` accumulates as behavioral signals fire and is subtracted
    dynamically via the ``score`` property.
    """

    base_score: int
    base_factors: dict[str, int]
    computed_at: float

    # ── Behavioral counters ──────────────────────────────────────────
    request_count: int = 0
    tools_accessed: set[str] = field(default_factory=set)
    request_timestamps: list[float] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0

    # ── Scope probing signals ────────────────────────────────────────
    scope_violations: int = 0
    scope_violation_tools: list[str] = field(default_factory=list)

    # ── Tool pattern signals ─────────────────────────────────────────
    novel_tools: list[str] = field(default_factory=list)

    # ── Penalty accumulator ──────────────────────────────────────────
    penalty: int = 0

    # ── VP session tracking ──────────────────────────────────────────
    last_vp_hash: Optional[str] = None

    @property
    def score(self) -> int:
        """Dynamic score = base_score minus accumulated penalties, clamped [0, 100]."""
        return max(0, min(100, self.base_score - self.penalty))


@dataclass
class TrustEvaluation:
    """Per-request trust decision."""

    score: int
    decision: str  # "allow", "step_up", "block"
    factors: dict[str, Any]
    cached: bool
    explanation: str
    latency_ms: float


class GatewayTrustEvaluator:
    """Per-request trust scorer with in-memory caching and dynamic penalties."""

    def __init__(self, config: TrustConfig) -> None:
        self.config = config
        self._cache: dict[str, CachedTrustScore] = {}
        self._cold_path_inflight: set[str] = set()
        self._lock = threading.Lock()
        # Shared bounded pool for cold-path refreshes (replaces per-miss threads).
        self._cold_path_pool = ThreadPoolExecutor(
            max_workers=_COLD_PATH_MAX_WORKERS, thread_name_prefix="trust-cold"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        agent_did: str,
        auth_result: GatewayAuthResult,
        tool_name: Optional[str] = None,
        vp_hash: Optional[str] = None,
        *,
        vc_jwt: Optional[str] = None,
        tenant_id: str = "default",
    ) -> TrustEvaluation:
        """Evaluate trust for a single gateway request.

        Cache miss path: compute base score from auth context (<1 ms),
        then optionally schedule a cold-path full score refresh.
        """
        t0 = time.monotonic()
        now = t0

        cached = self._cache.get(agent_did)

        if cached and (now - cached.computed_at) < self.config.cache_ttl_seconds:
            if vp_hash and cached.last_vp_hash and vp_hash != cached.last_vp_hash:
                cached.penalty = max(0, cached.penalty - 20)
                cached.scope_violations = 0
                cached.novel_tools = []
            if vp_hash:
                cached.last_vp_hash = vp_hash

            cached.request_timestamps.append(now)

            tool_penalty = self._compute_tool_pattern_penalty(cached, tool_name)
            velocity_penalty = self._compute_velocity_penalty(cached)
            scope_penalty = self._compute_scope_probe_penalty(cached)

            cached.penalty += tool_penalty + velocity_penalty + scope_penalty

            dynamic_score = cached.score
            decision = self._decide(dynamic_score)

            return TrustEvaluation(
                score=dynamic_score,
                decision=decision,
                factors={
                    **cached.base_factors,
                    "behavioral_penalty": cached.penalty,
                    "tool_pattern_penalty": tool_penalty,
                    "velocity_penalty": velocity_penalty,
                    "scope_probe_penalty": scope_penalty,
                    "novel_tools": list(cached.novel_tools),
                    "scope_violations": cached.scope_violations,
                    "requests_last_60s": len(cached.request_timestamps),
                },
                cached=True,
                explanation=self._explain(dynamic_score, decision, cached),
                latency_ms=(time.monotonic() - t0) * 1000,
            )

        base_factors = self._instant_score(auth_result)
        base_score = sum(base_factors.values())
        entry = CachedTrustScore(
            base_score=base_score,
            base_factors=base_factors,
            computed_at=now,
            request_count=1,
            request_timestamps=[now],
            last_vp_hash=vp_hash,
        )
        with self._lock:
            self._cache[agent_did] = entry

        if self.config.cold_path_enabled:
            token = vc_jwt or self._extract_bearer_token(auth_result)
            if token:
                self.schedule_cold_path_refresh(
                    agent_did=agent_did,
                    vc_jwt=token,
                    tenant_id=tenant_id,
                )

        decision = self._decide(base_score)
        return TrustEvaluation(
            score=base_score,
            decision=decision,
            factors={**base_factors, "behavioral_penalty": 0},
            cached=False,
            explanation=self._explain(base_score, decision, entry),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    def schedule_cold_path_refresh(
        self,
        *,
        agent_did: str,
        vc_jwt: str,
        tenant_id: str = "default",
    ) -> None:
        """Fire-and-forget full trust score refresh + TrustEvent persistence."""
        with self._lock:
            if agent_did in self._cold_path_inflight:
                return
            self._cold_path_inflight.add(agent_did)

        def _run() -> None:
            try:
                self._cold_path_refresh(agent_did, vc_jwt, tenant_id)
            finally:
                with self._lock:
                    self._cold_path_inflight.discard(agent_did)

        try:
            self._cold_path_pool.submit(_run)
        except RuntimeError:
            # Pool shut down (e.g. during teardown) — drop the inflight marker.
            with self._lock:
                self._cold_path_inflight.discard(agent_did)

    def _cold_path_refresh(self, agent_did: str, vc_jwt: str, tenant_id: str) -> None:
        """Compute full backend trust score and refresh cache base_score."""
        score_total: Optional[int] = None
        factors: dict[str, int] = {}
        explanation = ""

        try:
            from core.trust_score import compute_trust_score, record_trust_event

            result = compute_trust_score(vc_jwt, tenant_id)
            score_total = int(result.total)
            factors = {k: int(v) for k, v in (result.factors or {}).items()}
            explanation = result.explanation or ""
            try:
                record_trust_event(
                    tenant_id=tenant_id,
                    agent_did=agent_did,
                    event_type="trust.cold_path_refresh",
                    score_delta=0,
                    metadata={
                        "total": score_total,
                        "factors": factors,
                        "risk_level": result.risk_level,
                    },
                )
            except Exception as exc:
                _logger.debug("record_trust_event failed: %s", exc)
        except Exception as import_exc:
            _logger.debug("In-process cold path unavailable (%s); trying HTTP", import_exc)
            backend_url = os.environ.get("BACKEND_URL") or os.environ.get("PRAMANA_BACKEND_URL")
            if backend_url:
                # Authenticate the service-to-service call when a key is configured.
                headers: dict[str, str] = {}
                api_key = os.environ.get("BACKEND_API_KEY") or os.environ.get("PRAMANA_BACKEND_API_KEY")
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"

                last_exc: Optional[Exception] = None
                for attempt in range(_COLD_PATH_HTTP_ATTEMPTS):
                    try:
                        import httpx

                        r = httpx.post(
                            backend_url.rstrip("/") + "/v1/trust/score",
                            json={"jwt": vc_jwt},
                            headers=headers,
                            timeout=5.0,
                        )
                        if r.status_code < 400:
                            data = r.json()
                            score_total = int(data.get("total", data.get("score", 0)))
                            raw_factors = data.get("factors") or {}
                            factors = {k: int(v) for k, v in raw_factors.items()}
                            explanation = str(data.get("explanation", ""))
                            break
                        # 4xx/5xx: retry only on server-side errors
                        if r.status_code < 500:
                            break
                        last_exc = RuntimeError(f"HTTP {r.status_code}")
                    except Exception as http_exc:
                        last_exc = http_exc
                    if attempt + 1 < _COLD_PATH_HTTP_ATTEMPTS:
                        time.sleep(_COLD_PATH_HTTP_BACKOFF_SECONDS)
                if score_total is None and last_exc is not None:
                    _logger.debug("HTTP cold path failed after retries: %s", last_exc)

        if score_total is None:
            return

        with self._lock:
            cached = self._cache.get(agent_did)
            if cached is None:
                return
            cached.base_score = max(0, min(100, score_total))
            if factors:
                cached.base_factors = {**cached.base_factors, **factors, "cold_path": True}
            cached.computed_at = time.monotonic()
        _logger.debug(
            "Cold-path refresh agent=%s score=%s (%s)",
            agent_did[:40],
            score_total,
            explanation[:80],
        )

    @staticmethod
    def _extract_bearer_token(auth_result: GatewayAuthResult) -> Optional[str]:
        raw = getattr(auth_result, "raw_result", None)
        if raw is None:
            return None
        for attr in ("vc_jwts", "credentials", "vp_jwt", "token"):
            val = getattr(raw, attr, None)
            if isinstance(val, list) and val and isinstance(val[0], str):
                return val[0]
            if isinstance(val, str) and val:
                return val
        return None

    def update_from_request(
        self,
        agent_did: str,
        tool_name: Optional[str],
        success: bool,
    ) -> None:
        """Update behavioral signals from a completed gateway request."""
        cached = self._cache.get(agent_did)
        if cached is None:
            return

        cached.request_count += 1
        cached.request_timestamps.append(time.monotonic())

        if tool_name:
            cached.tools_accessed.add(tool_name)

        if success:
            cached.success_count += 1
        else:
            cached.failure_count += 1

    def record_scope_violation(self, agent_did: str, tool_name: str) -> None:
        """Record a scope violation — called when the scope check blocks a request."""
        cached = self._cache.get(agent_did)
        if cached is None:
            return
        cached.scope_violations += 1
        cached.scope_violation_tools.append(tool_name)

    def invalidate(self, agent_did: str) -> None:
        """Evict the cached score for an agent."""
        with self._lock:
            self._cache.pop(agent_did, None)

    def close(self) -> None:
        """Shut down the cold-path worker pool (called on gateway shutdown)."""
        self._cold_path_pool.shutdown(wait=False)

    def _compute_tool_pattern_penalty(
        self, cached: CachedTrustScore, tool_name: Optional[str]
    ) -> int:
        if not tool_name or cached.request_count <= 3:
            return 0
        if tool_name in cached.tools_accessed:
            return 0

        cached.novel_tools.append(tool_name)
        n = len(cached.novel_tools)
        if n == 1:
            return 5
        elif n == 2:
            return 10
        else:
            return 15

    def _compute_velocity_penalty(self, cached: CachedTrustScore) -> int:
        now = time.monotonic()
        window = 60.0
        recent = [t for t in cached.request_timestamps if now - t < window]
        cached.request_timestamps = recent

        if cached.request_count <= 10:
            return 0

        rpm = len(recent)
        if rpm > 60:
            return 20
        elif rpm > 30:
            return 10
        elif rpm > 15:
            return 5
        return 0

    def _compute_scope_probe_penalty(self, cached: CachedTrustScore) -> int:
        v = cached.scope_violations
        if v == 0:
            return 0
        elif v == 1:
            return 5
        elif v == 2:
            return 15
        else:
            return 25

    def _instant_score(self, auth_result: GatewayAuthResult) -> dict[str, int]:
        if not auth_result.authenticated:
            return {
                "credential_validity": 0,
                "delegation_depth": 0,
                "issuer_reputation": 0,
                "agent_history": 0,
            }

        depth = 1
        raw = auth_result.raw_result
        if raw and raw.delegation and raw.delegation.chain:
            depth = len(raw.delegation.chain)

        depth_score = max(0, 25 - depth * 5)
        issuer_score = 20 if auth_result.blended else 10

        return {
            "credential_validity": 25,
            "delegation_depth": depth_score,
            "issuer_reputation": issuer_score,
            "agent_history": 15,
        }

    def _decide(self, score: int) -> str:
        if score >= self.config.allow_threshold:
            return "allow"
        if score >= self.config.step_up_threshold:
            return "step_up"
        return "block"

    def _explain(
        self, score: int, decision: str, cached: CachedTrustScore
    ) -> str:
        parts = [f"Score {score}/100 → {decision.upper()}"]
        if cached.penalty > 0:
            parts.append(f"Behavioral penalty: -{cached.penalty}")
        if cached.novel_tools:
            parts.append(f"Novel tools: {cached.novel_tools}")
        if cached.scope_violations > 0:
            parts.append(f"Scope violations: {cached.scope_violations}")
        recent_count = len(cached.request_timestamps)
        if recent_count > 15:
            parts.append(f"Velocity: {recent_count}/min")
        return ". ".join(parts)
