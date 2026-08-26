from __future__ import annotations

import time
from typing import Any, Optional
from urllib.parse import unquote

import jwt as pyjwt
from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field

from api.middleware.authz import require_scopes
from core.audit import write_audit
from core.db import db_session
from core.trust_score import (
    compute_trust_score,
    get_agent_trust_profile,
    record_trust_event,
)
from core.webhooks import dispatch_webhook_event
from models import Agent, TrustEvent

router = APIRouter(prefix="/v1/trust", tags=["trust"])


class TrustScoreRequest(BaseModel):
    jwt: str = Field(min_length=10)


class TrustScoreResponse(BaseModel):
    total: int
    factors: dict[str, int]
    risk_level: str
    explanation: str
    computed_at: str


class AgentTrustProfileResponse(BaseModel):
    did: str
    total_events: int
    success_rate: Optional[float]
    average_score: Optional[float]
    last_scored_at: Optional[str]
    history: list[dict[str, Any]]


@router.post("/score", response_model=TrustScoreResponse)
def score_credential(
    req: TrustScoreRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> TrustScoreResponse:
    """Compute a composite trust score (0-100) for a VC-JWT."""
    tenant_id = auth.get("tenant_id", "default")

    score = compute_trust_score(req.jwt, tenant_id)

    # Extract subject DID and jti for the event record.
    subject_did = ""
    credential_jti = None
    try:
        payload = pyjwt.decode(req.jwt, options={"verify_signature": False})
        subject_did = payload.get("sub", "")
        credential_jti = payload.get("jti")
    except Exception:
        pass

    event_type = (
        "verification_success"
        if score.factors["credential_validity"] > 0
        else "verification_failure"
    )

    if subject_did:
        try:
            record_trust_event(
                tenant_id=tenant_id,
                agent_did=subject_did,
                event_type=event_type,
                credential_jti=credential_jti,
                score_delta=score.total,
                metadata={"risk_level": score.risk_level, "factors": score.factors},
            )
        except Exception:
            pass

    write_audit(
        tenant_id=tenant_id,
        event_type="trust.score.computed",
        actor="api",
        resource_type="credential",
        resource_id=credential_jti or "",
        payload={
            "subject_did": subject_did,
            "total": score.total,
            "risk_level": score.risk_level,
        },
    )

    background_tasks.add_task(
        dispatch_webhook_event,
        tenant_id,
        "trust.score_changed",
        {
            "credential_jti": credential_jti,
            "subject_did": subject_did,
            "total": score.total,
            "risk_level": score.risk_level,
            "factors": score.factors,
        },
    )

    return TrustScoreResponse(
        total=score.total,
        factors=score.factors,
        risk_level=score.risk_level,
        explanation=score.explanation,
        computed_at=score.computed_at,
    )


@router.get("/agent/{did:path}", response_model=AgentTrustProfileResponse)
def agent_trust_profile(
    did: str,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> AgentTrustProfileResponse:
    """Return aggregate trust profile for an agent DID (last 20 events)."""
    tenant_id = auth.get("tenant_id", "default")
    did = unquote(did)

    profile = get_agent_trust_profile(agent_did=did, tenant_id=tenant_id)

    write_audit(
        tenant_id=tenant_id,
        event_type="trust.agent.profile.read",
        actor="api",
        resource_type="agent",
        resource_id=did,
        payload={"total_events": profile["total_events"]},
    )

    return AgentTrustProfileResponse(**profile)


# ---------------------------------------------------------------------------
# Risk Dashboard — fleet risk tier aggregation
# ---------------------------------------------------------------------------

class RiskTierSummary(BaseModel):
    tier: str
    count: int
    description: str
    color: str


class AgentRiskRow(BaseModel):
    name: str
    did: str
    spiffe_id: Optional[str]
    trust_score: int
    risk_tier: str
    event_count: int
    recent_delta: int
    failure_rate: float


class RiskDashboardResponse(BaseModel):
    fleet_size: int
    tiers: list[RiskTierSummary]
    agents: list[AgentRiskRow]
    mock_insurance_premium_usd: float
    generated_at: str


def _score_to_tier(score: int) -> str:
    if score >= 80:
        return "insurable"
    elif score >= 60:
        return "elevated"
    elif score >= 40:
        return "review"
    else:
        return "uninsurable"


@router.get("/risk-dashboard", response_model=RiskDashboardResponse)
def risk_dashboard(auth: dict = Depends(require_scopes(["credentials:verify"]))) -> RiskDashboardResponse:
    """Aggregate all agents into risk tiers for insurance/compliance review."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
        all_events = (
            db.query(TrustEvent)
            .filter(TrustEvent.tenant_id == tenant_id)
            .order_by(TrustEvent.created_at.desc())
            .all()
        )

    # Build per-agent stats from trust events
    from collections import defaultdict
    agent_events: dict[str, list[TrustEvent]] = defaultdict(list)
    for ev in all_events:
        agent_events[ev.agent_did].append(ev)

    rows: list[AgentRiskRow] = []
    tier_counts: dict[str, int] = {"insurable": 0, "elevated": 0, "review": 0, "uninsurable": 0}

    for agent in agents:
        evs = agent_events.get(agent.did, [])
        event_count = len(evs)
        total_delta = sum(ev.score_delta for ev in evs)
        base_score = 75  # starting assumption
        score = max(0, min(100, base_score + total_delta))

        # Recent delta (last 3 events)
        recent = evs[:3]
        recent_delta = sum(ev.score_delta for ev in recent)

        # Failure rate
        failure_evs = [e for e in evs if "failure" in (e.event_type or "").lower() or "violation" in (e.event_type or "").lower()]
        failure_rate = len(failure_evs) / event_count if event_count > 0 else 0.0

        tier = _score_to_tier(score)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

        rows.append(AgentRiskRow(
            name=agent.name,
            did=agent.did,
            spiffe_id=getattr(agent, "spiffe_id", None),
            trust_score=score,
            risk_tier=tier,
            event_count=event_count,
            recent_delta=recent_delta,
            failure_rate=round(failure_rate, 3),
        ))

    rows.sort(key=lambda r: r.trust_score)

    # Mock insurance premium: higher risk fleet = higher premium
    uninsurable_count = tier_counts.get("uninsurable", 0)
    review_count = tier_counts.get("review", 0)
    fleet_size = len(agents)
    risk_factor = 1.0 + (uninsurable_count * 0.5) + (review_count * 0.2)
    mock_premium = round(fleet_size * 120.0 * risk_factor, 2)  # $120/agent base

    tiers = [
        RiskTierSummary(tier="insurable", count=tier_counts.get("insurable", 0),
                        description="Score ≥ 80 — low risk, meets insurance requirements", color="emerald"),
        RiskTierSummary(tier="elevated", count=tier_counts.get("elevated", 0),
                        description="Score 60–79 — moderate risk, increased monitoring recommended", color="amber"),
        RiskTierSummary(tier="review", count=tier_counts.get("review", 0),
                        description="Score 40–59 — high risk, manual review required", color="orange"),
        RiskTierSummary(tier="uninsurable", count=tier_counts.get("uninsurable", 0),
                        description="Score < 40 — critical risk, consider decommissioning", color="red"),
    ]

    return RiskDashboardResponse(
        fleet_size=fleet_size,
        tiers=tiers,
        agents=rows,
        mock_insurance_premium_usd=mock_premium,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


# ---------------------------------------------------------------------------
# Anomaly Monitor
# ---------------------------------------------------------------------------

class AnomalyEvent(BaseModel):
    event_type: str
    score_delta: int
    created_at: str


class AnomalyAgent(BaseModel):
    name: str
    did: str
    spiffe_id: Optional[str]
    trust_score: int
    risk_tier: str
    recent_delta: int
    failure_rate: float
    anomaly_reasons: list[str]
    recent_events: list[AnomalyEvent]


class AnomalyMonitorResponse(BaseModel):
    flagged_count: int
    total_agents_checked: int
    anomalies: list[AnomalyAgent]
    generated_at: str


@router.get("/anomalies", response_model=AnomalyMonitorResponse)
def anomaly_monitor(auth: dict = Depends(require_scopes(["credentials:verify"]))) -> AnomalyMonitorResponse:
    """Detect agents with anomalous trust behavior: rapid score drops, high failure rates, or risk escalation."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
        all_events = (
            db.query(TrustEvent)
            .filter(TrustEvent.tenant_id == tenant_id)
            .order_by(TrustEvent.created_at.desc())
            .all()
        )

    from collections import defaultdict
    agent_events: dict[str, list[TrustEvent]] = defaultdict(list)
    for ev in all_events:
        agent_events[ev.agent_did].append(ev)

    anomalies: list[AnomalyAgent] = []

    for agent in agents:
        evs = agent_events.get(agent.did, [])
        if not evs:
            continue

        total_delta = sum(ev.score_delta for ev in evs)
        score = max(0, min(100, 75 + total_delta))
        recent = evs[:5]
        recent_delta = sum(ev.score_delta for ev in recent)
        failure_evs = [e for e in evs if "failure" in (e.event_type or "").lower() or "violation" in (e.event_type or "").lower()]
        failure_rate = len(failure_evs) / len(evs)

        reasons: list[str] = []
        if recent_delta < -15:
            reasons.append(f"Rapid score drop: {recent_delta:+d} in last {len(recent)} events")
        if failure_rate > 0.4:
            reasons.append(f"High failure rate: {failure_rate:.0%} of events are failures or violations")
        if score < 40:
            reasons.append(f"Critical risk score: {score}/100 — below insurable threshold")
        if any("scope_violation" in (e.event_type or "") for e in recent):
            reasons.append("Recent scope violation attempts detected")

        if not reasons:
            continue

        tier = _score_to_tier(score)
        recent_events = [
            AnomalyEvent(
                event_type=e.event_type or "",
                score_delta=e.score_delta,
                created_at=e.created_at.isoformat() if hasattr(e.created_at, "isoformat") else str(e.created_at),
            )
            for e in recent[:5]
        ]

        anomalies.append(AnomalyAgent(
            name=agent.name,
            did=agent.did,
            spiffe_id=getattr(agent, "spiffe_id", None),
            trust_score=score,
            risk_tier=tier,
            recent_delta=recent_delta,
            failure_rate=round(failure_rate, 3),
            anomaly_reasons=reasons,
            recent_events=recent_events,
        ))

    anomalies.sort(key=lambda a: a.trust_score)

    return AnomalyMonitorResponse(
        flagged_count=len(anomalies),
        total_agents_checked=len(agents),
        anomalies=anomalies,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
