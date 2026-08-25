"""
Session API — Stripe-simple agent authorization runtime surface.

Additive orchestration over credentials / delegations / trust / packs.
Does not replace existing routes.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

import jwt as pyjwt
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func

from api.middleware.authz import require_scopes
from core.audit import write_audit
from core.db import db_session
from core.packs import PackContext, normalize_packs, run_pack_hooks
from core.settings import settings
from core.tenancy import ensure_tenant
from core.trust_score import compute_trust_score, record_trust_event
from core.webhooks import dispatch_webhook_event
from models import AuthorizationSession, MandateSpend

router = APIRouter(prefix="/v1/sessions", tags=["sessions"])

# Stable error codes (plan contract)
ERR_SCOPE_DENIED = "scope_denied"
ERR_TRUST_STEP_UP = "trust_step_up"
ERR_MANDATE_EXCEEDED = "mandate_exceeded"
ERR_REVOKED = "revoked"
ERR_EXPIRED = "expired"
ERR_BLOCKED = "blocked"

ALLOW_THRESHOLD = 75
STEP_UP_THRESHOLD = 50

# Fallback trust when a session has no scored credential. In development we keep
# the demo-friendly allow default; in production we fail safe to step-up so an
# unscored session never silently allows a sensitive action.
DEFAULT_UNSCORED_TRUST_DEV = 80              # -> allow
DEFAULT_UNSCORED_TRUST_PROD = STEP_UP_THRESHOLD  # -> step_up


def _is_production() -> bool:
    """Unified production switch: PRAMANA_ENV/GATEWAY_ENV or backend ENV."""
    env = (os.environ.get("PRAMANA_ENV") or os.environ.get("GATEWAY_ENV") or "").strip().lower()
    if env in {"production", "prod"}:
        return True
    return str(getattr(settings, "env", "dev")).strip().lower() == "production"


def _hash_payload(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _idempotency_key(request: Request) -> Optional[str]:
    k = request.headers.get("idempotency-key") or request.headers.get("Idempotency-Key")
    if isinstance(k, str) and k.strip():
        return k.strip()[:200]
    return None


def _session_to_response(session: AuthorizationSession) -> "SessionResponse":
    return SessionResponse(
        id=session.id,
        status=session.status,
        tenant_id=session.tenant_id,
        agent_did=session.agent_did,
        human_did=session.human_did,
        delegation_jti=session.delegation_jti,
        scope=session.scope or {},
        packs=list(session.packs or []),
        trust_score=session.trust_score,
        last_decision=session.last_decision or {},
        proof_bundle=session.proof_bundle or {},
        created_at=session.created_at,
        updated_at=session.updated_at,
        expires_at=session.expires_at,
    )


class CreateSessionRequest(BaseModel):
    agent_did: str = Field(min_length=8, max_length=600)
    human_did: Optional[str] = Field(default=None, max_length=600)
    human_proof_jwt: Optional[str] = Field(default=None, min_length=10)
    agent_vc_jwt: Optional[str] = Field(default=None, min_length=10)
    delegation_jwt: Optional[str] = Field(default=None, min_length=10)
    scope: dict[str, Any] = Field(default_factory=dict)
    packs: list[str] = Field(default_factory=lambda: ["core"])
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionResponse(BaseModel):
    id: uuid.UUID
    status: str
    tenant_id: str
    agent_did: str
    human_did: Optional[str] = None
    delegation_jti: Optional[str] = None
    scope: dict[str, Any]
    packs: list[str]
    trust_score: Optional[int] = None
    last_decision: dict[str, Any]
    proof_bundle: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None


class ActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    resource: Optional[str] = Field(default=None, max_length=500)
    amount: Optional[int] = Field(default=None, ge=0)
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    merchant: Optional[str] = Field(default=None, max_length=500)
    tool_name: Optional[str] = Field(default=None, max_length=200)
    # Dogfood/testing hook: force a trust score for this decision. Honored ONLY
    # in development and only when the session has no real scored credential, so
    # production behavior is never affected.
    simulate_score: Optional[int] = Field(default=None, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    session_id: uuid.UUID
    decision: str  # allow | step_up | block
    error_code: Optional[str] = None
    reason: str
    trust_score: Optional[int] = None
    factors: dict[str, Any] = Field(default_factory=dict)
    session_status: str


class StepUpRequest(BaseModel):
    human_proof_jwt: Optional[str] = Field(default=None, min_length=10)
    fresh_vp_jwt: Optional[str] = Field(default=None, min_length=10)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RevokeSessionRequest(BaseModel):
    cascade: bool = True
    reason: Optional[str] = Field(default=None, max_length=500)


def _decode_jti(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        payload = pyjwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")
        return str(jti) if jti else None
    except Exception:
        return None


def _decode_sub(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        payload = pyjwt.decode(token, options={"verify_signature": False})
        sub = payload.get("sub")
        return str(sub) if sub else None
    except Exception:
        return None


def _decide_from_score(score: int) -> str:
    if score >= ALLOW_THRESHOLD:
        return "allow"
    if score >= STEP_UP_THRESHOLD:
        return "step_up"
    return "block"


def _check_scope(session: AuthorizationSession, action: str, amount: Optional[int], currency: Optional[str]) -> Optional[str]:
    """Return error_code if scope violated, else None."""
    scope = session.scope or {}
    actions = scope.get("actions") or []
    if actions and action != "*" and action not in actions:
        return ERR_SCOPE_DENIED

    max_amount = scope.get("max_amount")
    if amount is not None and isinstance(max_amount, int) and amount > max_amount:
        return ERR_MANDATE_EXCEEDED

    scope_currency = scope.get("currency")
    if currency and scope_currency and currency.upper() != str(scope_currency).upper():
        return ERR_MANDATE_EXCEEDED

    return None


# ---------------------------------------------------------------------------
# Commerce composition (AP2 mandates): cumulative budget + merchant allowlist +
# spend ledger. Active when the session enables the "commerce" pack.
# ---------------------------------------------------------------------------

def _commerce_enabled(session: AuthorizationSession) -> bool:
    return "commerce" in (session.packs or [])


def _merchant_allowed(scope: dict[str, Any], merchant: Optional[str]) -> bool:
    """True if the merchant is permitted by the scope's allowlist.

    Empty/absent allowlist or ["*"] means any merchant is allowed.
    """
    merchants = scope.get("merchants")
    if not merchants or merchants == ["*"]:
        return True
    if merchant is None:
        return False
    return merchant in merchants


def _cumulative_spend(db, tenant_id: str, session_id: uuid.UUID, currency: str) -> int:
    """Sum of prior recorded spend for this session in the given currency.

    Reuses the AP2 MandateSpend ledger, namespacing this session's fulfilments
    under intent_jti == str(session_id) so cumulative budget is enforced across
    all purchases in the session (and surfaced by GET /v1/commerce/.../spend).
    """
    total = (
        db.query(func.coalesce(func.sum(MandateSpend.amount), 0))
        .filter(
            MandateSpend.tenant_id == tenant_id,
            MandateSpend.intent_jti == str(session_id),
            MandateSpend.currency == currency,
        )
        .scalar()
    )
    return int(total or 0)


def _record_spend(db, tenant_id: str, session_id: uuid.UUID, amount: int, currency: str, merchant: Optional[str]) -> None:
    db.add(
        MandateSpend(
            tenant_id=tenant_id,
            intent_jti=str(session_id),
            cart_jti=uuid.uuid4().hex,  # single-use fulfilment id
            amount=amount,
            currency=currency,
            merchant_did=merchant,
        )
    )


def _commerce_block(
    db,
    background_tasks: BackgroundTasks,
    session: AuthorizationSession,
    tenant_id: str,
    now: datetime,
    error_code: str,
    reason: str,
    factors: dict[str, Any],
) -> "DecisionResponse":
    """Persist + audit a commerce-policy block and return the decision."""
    session.last_decision = {
        "decision": "block",
        "error_code": error_code,
        "reason": reason,
        **factors,
    }
    session.updated_at = now
    db.commit()
    write_audit(
        tenant_id=tenant_id,
        event_type="session.action.blocked",
        actor="api",
        resource_type="session",
        resource_id=str(session.id),
        payload=session.last_decision,
    )
    background_tasks.add_task(
        dispatch_webhook_event,
        tenant_id,
        "session.decision",
        {"session_id": str(session.id), **session.last_decision},
    )
    return DecisionResponse(
        session_id=session.id,
        decision="block",
        error_code=error_code,
        reason=reason,
        trust_score=session.trust_score,
        factors=factors,
        session_status=session.status,
    )


def _get_session(
    db,
    session_id: uuid.UUID,
    tenant_id: str,
    *,
    for_update: bool = False,
) -> AuthorizationSession:
    query = db.query(AuthorizationSession).filter(
        AuthorizationSession.id == session_id,
        AuthorizationSession.tenant_id == tenant_id,
    )
    if for_update:
        # Row-level lock serializes concurrent actions on the same session so
        # they cannot double-decide against a stale trust score. No-op on
        # SQLite (dev/tests); enforced on PostgreSQL (production).
        query = query.with_for_update()
    session = query.one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("", response_model=SessionResponse)
def create_session(
    req: CreateSessionRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> SessionResponse:
    """Create an authorization session (human→agent handoff)."""
    tenant_id = auth.get("tenant_id", "default")
    idem = _idempotency_key(request)
    packs = normalize_packs(req.packs)
    body = req.model_dump()
    body["packs"] = packs
    req_hash = _hash_payload({"tenant_id": tenant_id, "body": body})

    with db_session() as db:
        ensure_tenant(db, tenant_id)

        if idem:
            existing = (
                db.query(AuthorizationSession)
                .filter(
                    AuthorizationSession.tenant_id == tenant_id,
                    AuthorizationSession.idempotency_key == idem,
                )
                .one_or_none()
            )
            if existing is not None:
                if existing.request_hash and existing.request_hash != req_hash:
                    raise HTTPException(status_code=409, detail="Idempotency-Key reuse with different request")
                return _session_to_response(existing)

        human_did = req.human_did or _decode_sub(req.human_proof_jwt)
        delegation_jti = _decode_jti(req.delegation_jwt)

        # Derive scope from request or decode from delegation JWT claims.
        scope = dict(req.scope or {})
        if req.delegation_jwt and not scope:
            try:
                payload = pyjwt.decode(req.delegation_jwt, options={"verify_signature": False})
                cs = (payload.get("vc") or {}).get("credentialSubject") or {}
                scope = cs.get("scope") or cs.get("delegationScope") or {}
            except Exception:
                pass

        trust_score: Optional[int] = None
        proof_bundle: dict[str, Any] = {
            "agent_did": req.agent_did,
            "human_did": human_did,
            "delegation_jti": delegation_jti,
            "has_human_proof": bool(req.human_proof_jwt),
            "has_agent_vc": bool(req.agent_vc_jwt),
            "has_delegation": bool(req.delegation_jwt),
        }

        score_token = req.agent_vc_jwt or req.delegation_jwt or req.human_proof_jwt
        if score_token:
            try:
                ts = compute_trust_score(score_token, tenant_id)
                trust_score = ts.total
                proof_bundle["initial_trust"] = {
                    "total": ts.total,
                    "risk_level": ts.risk_level,
                    "factors": ts.factors,
                }
            except Exception:
                pass

        now = datetime.utcnow()
        session = AuthorizationSession(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            status="active",
            agent_did=req.agent_did,
            human_did=human_did,
            delegation_jti=delegation_jti,
            scope=scope,
            packs=packs,
            proof_bundle=proof_bundle,
            last_decision={},
            trust_score=trust_score,
            metadata_json=req.metadata or {},
            idempotency_key=idem,
            request_hash=req_hash,
            created_at=now,
            updated_at=now,
            expires_at=now + timedelta(seconds=req.ttl_seconds),
        )

        ctx = PackContext(
            session_id=str(session.id),
            tenant_id=tenant_id,
            agent_did=req.agent_did,
            human_did=human_did,
            scope=scope,
            packs=packs,
            metadata=req.metadata or {},
        )
        hook = run_pack_hooks(packs, "on_handoff", ctx)
        if not hook.ok:
            raise HTTPException(
                status_code=400,
                detail={"error": hook.error_code or "pack_rejected", "reason": hook.reason},
            )
        session.proof_bundle = {**proof_bundle, "pack_hooks": hook.extra}

        db.add(session)
        db.commit()
        db.refresh(session)

        write_audit(
            tenant_id=tenant_id,
            event_type="session.created",
            actor="api",
            resource_type="session",
            resource_id=str(session.id),
            payload={"agent_did": req.agent_did, "packs": packs, "status": session.status},
        )

        background_tasks.add_task(
            dispatch_webhook_event,
            tenant_id,
            "session.created",
            {"session_id": str(session.id), "agent_did": req.agent_did, "status": session.status},
        )

        return _session_to_response(session)


@router.get("/{session_id}", response_model=SessionResponse)
def get_session(
    session_id: uuid.UUID,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> SessionResponse:
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        session = _get_session(db, session_id, tenant_id)
        return _session_to_response(session)


@router.post("/{session_id}/actions", response_model=DecisionResponse)
def decide_action(
    session_id: uuid.UUID,
    req: ActionRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> DecisionResponse:
    """Evaluate an action: allow | step_up | block."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        session = _get_session(db, session_id, tenant_id, for_update=True)
        now = datetime.utcnow()

        if session.status == "revoked":
            decision = DecisionResponse(
                session_id=session.id,
                decision="block",
                error_code=ERR_REVOKED,
                reason="Session has been revoked",
                trust_score=session.trust_score,
                session_status=session.status,
            )
            return decision

        if session.expires_at and session.expires_at < now:
            session.status = "expired"
            session.updated_at = now
            session.last_decision = {"decision": "block", "error_code": ERR_EXPIRED}
            db.commit()
            return DecisionResponse(
                session_id=session.id,
                decision="block",
                error_code=ERR_EXPIRED,
                reason="Session expired",
                trust_score=session.trust_score,
                session_status="expired",
            )

        # Scope / mandate checks run even when step-up is pending.
        scope_err = _check_scope(session, req.action, req.amount, req.currency)
        if scope_err:
            decision_name = "block"
            reason = (
                "Action not in session scope"
                if scope_err == ERR_SCOPE_DENIED
                else "Amount/currency exceeds mandate/scope"
            )
            session.last_decision = {
                "decision": decision_name,
                "error_code": scope_err,
                "action": req.action,
                "reason": reason,
            }
            session.updated_at = now
            db.commit()
            write_audit(
                tenant_id=tenant_id,
                event_type="session.action.blocked",
                actor="api",
                resource_type="session",
                resource_id=str(session.id),
                payload=session.last_decision,
            )
            background_tasks.add_task(
                dispatch_webhook_event,
                tenant_id,
                "session.decision",
                {"session_id": str(session.id), **session.last_decision},
            )
            return DecisionResponse(
                session_id=session.id,
                decision=decision_name,
                error_code=scope_err,
                reason=reason,
                trust_score=session.trust_score,
                session_status=session.status,
            )

        # Commerce composition: for priced actions, enforce merchant allowlist
        # and cumulative budget (AP2) before trust scoring. Only when the
        # session enabled the "commerce" pack, so core sessions are unchanged.
        is_purchase = _commerce_enabled(session) and req.amount is not None
        scope = session.scope or {}
        budget_currency = (req.currency or scope.get("currency") or "USD").upper()
        max_amount = scope.get("max_amount") if isinstance(scope.get("max_amount"), int) else None
        budget_info: dict[str, Any] = {}
        if is_purchase:
            if not _merchant_allowed(scope, req.merchant):
                return _commerce_block(
                    db, background_tasks, session, tenant_id, now,
                    ERR_SCOPE_DENIED,
                    f"Merchant not allowed: {req.merchant}",
                    {"merchant": req.merchant, "allowed_merchants": scope.get("merchants")},
                )
            spent = _cumulative_spend(db, tenant_id, session.id, budget_currency)
            projected = spent + int(req.amount)
            budget_info = {
                "budget": max_amount,
                "spent": spent,
                "currency": budget_currency,
                "remaining": (max_amount - spent) if max_amount is not None else None,
            }
            if max_amount is not None and projected > max_amount:
                return _commerce_block(
                    db, background_tasks, session, tenant_id, now,
                    ERR_MANDATE_EXCEEDED,
                    f"Cumulative budget exceeded: {projected} > {max_amount} {budget_currency}",
                    {"budget": budget_info, "projected": projected},
                )

        if session.status == "step_up_required":
            return DecisionResponse(
                session_id=session.id,
                decision="step_up",
                error_code=ERR_TRUST_STEP_UP,
                reason="Step-up authentication required before further actions",
                trust_score=session.trust_score,
                factors=budget_info,
                session_status=session.status,
            )

        # Pack hooks
        ctx = PackContext(
            session_id=str(session.id),
            tenant_id=tenant_id,
            agent_did=session.agent_did,
            human_did=session.human_did,
            scope=session.scope or {},
            packs=list(session.packs or []),
            action=req.model_dump(),
        )
        hook = run_pack_hooks(list(session.packs or []), "on_action", ctx)
        if not hook.ok:
            session.last_decision = {
                "decision": "block",
                "error_code": hook.error_code or ERR_BLOCKED,
                "reason": hook.reason or "Pack rejected action",
            }
            session.updated_at = now
            db.commit()
            return DecisionResponse(
                session_id=session.id,
                decision="block",
                error_code=hook.error_code or ERR_BLOCKED,
                reason=hook.reason or "Pack rejected action",
                trust_score=session.trust_score,
                factors=hook.extra,
                session_status=session.status,
            )

        # Trust decide. When the session has a scored credential we use it. When
        # it does not, we fall back: development allows (demo-friendly), while
        # production fails safe to step-up so an unscored session never silently
        # allows. The behavioral/gateway path can still lower the score later.
        if req.simulate_score is not None and not _is_production():
            # Dogfood/testing: explicit per-action risk selector (dev only).
            score = req.simulate_score
        elif session.trust_score is not None:
            score = session.trust_score
        elif _is_production():
            score = DEFAULT_UNSCORED_TRUST_PROD
        else:
            score = DEFAULT_UNSCORED_TRUST_DEV
        decision_name = _decide_from_score(score)
        error_code: Optional[str] = None
        reason = f"Trust score {score}/100 → {decision_name}"

        if decision_name == "step_up":
            error_code = ERR_TRUST_STEP_UP
            session.status = "step_up_required"
            reason = f"Trust score {score}/100 requires step-up"
        elif decision_name == "block":
            error_code = ERR_BLOCKED
            reason = f"Trust score {score}/100 blocked"

        # Commerce: on an allowed purchase, record the spend so the cumulative
        # budget depletes across the session, and reflect it in the response.
        if is_purchase and decision_name == "allow":
            _record_spend(db, tenant_id, session.id, int(req.amount), budget_currency, req.merchant)
            new_spent = int(budget_info.get("spent") or 0) + int(req.amount)
            budget_info["spent"] = new_spent
            budget_info["remaining"] = (max_amount - new_spent) if max_amount is not None else None

        session.trust_score = score
        session.last_decision = {
            "decision": decision_name,
            "error_code": error_code,
            "action": req.action,
            "reason": reason,
            "trust_score": score,
            "pack_hooks": hook.extra,
            **({"budget": budget_info} if budget_info else {}),
        }
        session.updated_at = now
        db.commit()

        write_audit(
            tenant_id=tenant_id,
            event_type=f"session.action.{decision_name}",
            actor="api",
            resource_type="session",
            resource_id=str(session.id),
            payload=session.last_decision,
        )
        try:
            record_trust_event(
                tenant_id=tenant_id,
                agent_did=session.agent_did,
                event_type=f"session.action.{decision_name}",
                score_delta=0,
                metadata={"session_id": str(session.id), "action": req.action, "score": score},
            )
        except Exception:
            pass

        background_tasks.add_task(
            dispatch_webhook_event,
            tenant_id,
            "session.decision",
            {"session_id": str(session.id), **session.last_decision},
        )

        return DecisionResponse(
            session_id=session.id,
            decision=decision_name,
            error_code=error_code,
            reason=reason,
            trust_score=score,
            factors={"pack_hooks": hook.extra, **({"budget": budget_info} if budget_info else {})},
            session_status=session.status,
        )


@router.post("/{session_id}/step_up", response_model=SessionResponse)
def complete_step_up(
    session_id: uuid.UUID,
    req: StepUpRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> SessionResponse:
    """Complete step-up / re-bind and restore session to active."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        session = _get_session(db, session_id, tenant_id, for_update=True)
        if session.status == "revoked":
            raise HTTPException(status_code=400, detail={"error": ERR_REVOKED, "reason": "Session revoked"})

        ctx = PackContext(
            session_id=str(session.id),
            tenant_id=tenant_id,
            agent_did=session.agent_did,
            human_did=session.human_did,
            scope=session.scope or {},
            packs=list(session.packs or []),
            metadata=req.metadata or {},
        )
        hook = run_pack_hooks(list(session.packs or []), "on_step_up", ctx)
        if not hook.ok:
            raise HTTPException(
                status_code=400,
                detail={"error": hook.error_code or "pack_rejected", "reason": hook.reason},
            )

        # Partial trust restore on successful step-up
        score = session.trust_score if session.trust_score is not None else 50
        session.trust_score = min(100, score + 20)
        session.status = "active"
        session.updated_at = datetime.utcnow()
        session.proof_bundle = {
            **(session.proof_bundle or {}),
            "step_up_completed_at": session.updated_at.isoformat() + "Z",
            "has_fresh_human_proof": bool(req.human_proof_jwt),
            "has_fresh_vp": bool(req.fresh_vp_jwt),
            "pack_hooks": hook.extra,
        }
        session.last_decision = {
            "decision": "allow",
            "reason": "Step-up completed; trust partially restored",
            "trust_score": session.trust_score,
        }
        db.commit()
        db.refresh(session)

        write_audit(
            tenant_id=tenant_id,
            event_type="session.step_up.completed",
            actor="api",
            resource_type="session",
            resource_id=str(session.id),
            payload={"trust_score": session.trust_score},
        )
        background_tasks.add_task(
            dispatch_webhook_event,
            tenant_id,
            "session.step_up",
            {"session_id": str(session.id), "trust_score": session.trust_score},
        )
        return _session_to_response(session)


@router.post("/{session_id}/revoke", response_model=SessionResponse)
def revoke_session(
    session_id: uuid.UUID,
    req: RevokeSessionRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:revoke"])),
) -> SessionResponse:
    """Revoke a session; optionally cascade-revoke linked delegation."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        session = _get_session(db, session_id, tenant_id, for_update=True)

        ctx = PackContext(
            session_id=str(session.id),
            tenant_id=tenant_id,
            agent_did=session.agent_did,
            human_did=session.human_did,
            scope=session.scope or {},
            packs=list(session.packs or []),
            metadata={"reason": req.reason},
        )
        run_pack_hooks(list(session.packs or []), "on_revoke", ctx)

        cascaded: list[str] = []
        if req.cascade and session.delegation_jti:
            try:
                from api.routes.delegations import _cascade_revoke, _get_delegation_registry_table, _revoke_single

                if _get_delegation_registry_table() is not None:
                    if _revoke_single(db, session.delegation_jti, tenant_id):
                        cascaded = _cascade_revoke(db, session.delegation_jti, tenant_id)
            except Exception:
                cascaded = []

        session.status = "revoked"
        session.updated_at = datetime.utcnow()
        session.last_decision = {
            "decision": "block",
            "error_code": ERR_REVOKED,
            "reason": req.reason or "Session revoked",
            "cascaded_delegations": cascaded,
        }
        session.last_error = req.reason
        db.commit()
        db.refresh(session)

        write_audit(
            tenant_id=tenant_id,
            event_type="session.revoked",
            actor="api",
            resource_type="session",
            resource_id=str(session.id),
            payload={
                "cascade": req.cascade,
                "cascaded_count": len(cascaded),
                "delegation_jti": session.delegation_jti,
            },
        )
        background_tasks.add_task(
            dispatch_webhook_event,
            tenant_id,
            "session.revoked",
            {"session_id": str(session.id), "cascaded_count": len(cascaded)},
        )
        return _session_to_response(session)
