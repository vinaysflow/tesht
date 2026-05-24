"""
gateway.trust
~~~~~~~~~~~~~
Two-tier trust scoring for per-request gateway use.

Hot path:  in-memory cache with dynamic behavioral penalties (<1 ms).
Cold path: full ``compute_trust_score()`` would run async in background
           and refresh the cache (not wired for demo — placeholder hook).

Trust score = base_score - accumulated_behavioral_penalties

Three behavioral signal types degrade the score in real-time:
  1. Tool Pattern Deviation  — agent accesses novel tools it has never used
  2. Velocity Anomaly        — sudden request-rate spike
  3. Scope Boundary Probing  — repeated attempts to access out-of-scope tools

A fresh VP presentation partially restores trust (penalty -= 20).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from gateway.auth import GatewayAuthResult
from gateway.config import TrustConfig


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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        agent_did: str,
        auth_result: GatewayAuthResult,
        tool_name: Optional[str] = None,
        vp_hash: Optional[str] = None,
    ) -> TrustEvaluation:
        """Evaluate trust for a single gateway request.

        Cache miss path: compute base score from auth context (<1 ms).
        Cache hit path: apply behavioral penalties on top of base score,
                        so the score degrades dynamically during a session.
        VP hash detection: if the agent presents a fresh VP, reduce penalty
                           by 20 and reset volatile signal counters.
        """
        t0 = time.monotonic()
        now = t0

        cached = self._cache.get(agent_did)

        if cached and (now - cached.computed_at) < self.config.cache_ttl_seconds:
            # ── Detect fresh VP presentation ──────────────────────────
            if vp_hash and cached.last_vp_hash and vp_hash != cached.last_vp_hash:
                cached.penalty = max(0, cached.penalty - 20)
                cached.scope_violations = 0
                cached.novel_tools = []
            if vp_hash:
                cached.last_vp_hash = vp_hash

            # ── Record timestamp for velocity tracking ────────────────
            cached.request_timestamps.append(now)

            # ── Compute dynamic penalties ─────────────────────────────
            tool_penalty = self._compute_tool_pattern_penalty(cached, tool_name)
            velocity_penalty = self._compute_velocity_penalty(cached)
            scope_penalty = self._compute_scope_probe_penalty(cached)

            cached.penalty += tool_penalty + velocity_penalty + scope_penalty

            dynamic_score = cached.score  # reads the @property
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

        # ── Cache miss: compute base score ────────────────────────────
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
        self._cache[agent_did] = entry

        decision = self._decide(base_score)
        return TrustEvaluation(
            score=base_score,
            decision=decision,
            factors={**base_factors, "behavioral_penalty": 0},
            cached=False,
            explanation=self._explain(base_score, decision, entry),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    def update_from_request(
        self,
        agent_did: str,
        tool_name: Optional[str],
        success: bool,
    ) -> None:
        """Update behavioral signals from a completed gateway request.

        Called on ALL request outcomes (success and failure), not just
        successful proxied requests.
        """
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

    def record_scope_violation(
        self, agent_did: str, tool_name: str
    ) -> None:
        """Record a scope violation — called when the scope check blocks a request.

        This is separate from ``update_from_request()`` so that scope probing
        signals accumulate independently of general failure tracking.
        """
        cached = self._cache.get(agent_did)
        if cached is None:
            return
        cached.scope_violations += 1
        cached.scope_violation_tools.append(tool_name)

    def invalidate(self, agent_did: str) -> None:
        """Evict the cached score for an agent."""
        self._cache.pop(agent_did, None)

    # ------------------------------------------------------------------
    # Behavioral signal computation
    # ------------------------------------------------------------------

    def _compute_tool_pattern_penalty(
        self, cached: CachedTrustScore, tool_name: Optional[str]
    ) -> int:
        """Penalty for accessing a tool the agent has never used before.

        Only activates after the agent has established a history of at least
        3 requests, so the first few requests are not penalised for exploration.
        """
        if not tool_name or cached.request_count <= 3:
            return 0
        if tool_name in cached.tools_accessed:
            return 0

        # This is a novel tool — record it and apply a graduated penalty
        cached.novel_tools.append(tool_name)
        n = len(cached.novel_tools)
        if n == 1:
            return 5
        elif n == 2:
            return 10
        else:
            return 15

    def _compute_velocity_penalty(self, cached: CachedTrustScore) -> int:
        """Penalty for a sudden request-rate spike.

        Measures requests per minute using a 60-second sliding window.
        No penalty during the first 10 requests (baseline establishment).
        """
        now = time.monotonic()
        window = 60.0
        # Prune timestamps outside the window
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
        """Penalty based on accumulated scope violation count.

        Returns the *marginal* penalty for the current violation count, so
        the caller should accumulate it into ``cached.penalty``.
        Note: this is re-evaluated each request from the violation count, so
        it only fires non-zero when violations are freshly detected.
        """
        v = cached.scope_violations
        if v == 0:
            return 0
        elif v == 1:
            return 5
        elif v == 2:
            return 15
        else:
            return 25

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _instant_score(self, auth_result: GatewayAuthResult) -> dict[str, int]:
        """Compute a lightweight base trust score from auth context alone.

        Four factors, each 0-25, matching the backend's scoring model:
        - credential_validity: 25 if auth passed, 0 otherwise
        - delegation_depth:    25 minus 5 per depth level (min 0)
        - issuer_reputation:   20 if blended (human delegator), 10 neutral
        - agent_history:       15 (neutral — no DB history on this path)
        """
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
