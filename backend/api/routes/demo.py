from __future__ import annotations

import secrets

from fastapi import APIRouter, Response, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, text

from api.middleware.authz import require_scopes
from core.auth.demo import issue_demo_token
from core.demo_metrics import inc, snapshot
from core.settings import settings

router = APIRouter(prefix='/v1/demo', tags=['demo'])


class DemoSessionResponse(BaseModel):
    token: str
    tenant_id: str
    expires_in: int


@router.post('/session', response_model=DemoSessionResponse)
def demo_session(resp: Response):
    # Always available when DEMO_MODE true; safe no-op otherwise.
    if not settings.demo_mode:
        # Still return a token for local testing if explicitly enabled.
        pass

    session_id = secrets.token_urlsafe(16)
    tenant_id = f"demo_{session_id}"

    token, exp = issue_demo_token(tenant_id=tenant_id, ttl_seconds=settings.demo_token_ttl_seconds)
    if settings.demo_mode:
        inc("demo_session_created_total", 1)

    resp.set_cookie(
        key='tesht_demo_session',
        value=session_id,
        httponly=True,
        secure=False,
        samesite='lax',
        max_age=settings.demo_token_ttl_seconds,
    )

    return DemoSessionResponse(token=token, tenant_id=tenant_id, expires_in=settings.demo_token_ttl_seconds)


@router.post('/reset')
def demo_reset(auth: dict = Depends(require_scopes(['tenant:admin']))):
    tenant_id = auth.get('tenant_id', 'default')
    if settings.demo_mode:
        inc("demo_reset_total", 1)

    from core.db import db_session
    from models import Agent, AuditEvent, Credential, Key, StatusList
    from models.tenant import Tenant

    with db_session() as db:
        # delete in FK-safe order
        db.query(Credential).filter(Credential.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(Key).filter(Key.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(Agent).filter(Agent.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(StatusList).filter(StatusList.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(AuditEvent).filter(AuditEvent.tenant_id == tenant_id).delete(synchronize_session=False)
        db.query(Tenant).filter(Tenant.id == tenant_id).delete(synchronize_session=False)
        db.commit()

    return {"reset": True, "tenant_id": tenant_id}


@router.get("/metrics")
def demo_metrics():
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="Not found")
    return snapshot()


# ---------------------------------------------------------------------------
# Seed endpoint
# ---------------------------------------------------------------------------

class SeedRequest(BaseModel):
    profile: str = Field(default="standard", pattern="^(minimal|standard)$")


class SeedResponse(BaseModel):
    seeded: bool
    agents: int
    credentials: int
    credentials_revoked: int
    delegations: int
    mandate_intents: int
    mandate_spends: int
    audit_events: int
    trust_events: int


@router.post('/seed', response_model=SeedResponse)
def demo_seed(req: SeedRequest, auth: dict = Depends(require_scopes(['tenant:admin']))):
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="Not found")
    tenant_id = auth.get('tenant_id', 'default')
    from core.seed import seed_tenant
    result = seed_tenant(tenant_id, req.profile)
    return SeedResponse(seeded=True, **result.__dict__)


# ---------------------------------------------------------------------------
# Summary endpoint
# ---------------------------------------------------------------------------

class DemoSummaryResponse(BaseModel):
    agents_count: int
    credentials_active: int
    credentials_revoked: int
    delegations_count: int
    audit_events_count: int
    chain_valid: bool
    trust_events_count: int
    mandate_spends_count: int
    total_spend_usd: float


@router.get('/summary', response_model=DemoSummaryResponse)
def demo_summary(auth: dict = Depends(require_scopes(['tenant:admin']))):
    tenant_id = auth.get('tenant_id', 'default')
    from core.audit import verify_chain
    from core.db import db_session
    from core.status_list import is_revoked
    from models import Agent, AuditEvent, Credential, MandateSpend
    from models.trust_event import TrustEvent

    with db_session() as db:
        agents_count = db.query(func.count(Agent.id)).filter(Agent.tenant_id == tenant_id).scalar() or 0
        creds = db.query(Credential).filter(Credential.tenant_id == tenant_id).all()
        revoked_count = sum(1 for c in creds if is_revoked(c.status_list_id, c.status_list_index))
        audit_count = db.query(func.count(AuditEvent.id)).filter(AuditEvent.tenant_id == tenant_id).scalar() or 0
        trust_count = db.query(func.count(TrustEvent.id)).filter(TrustEvent.tenant_id == tenant_id).scalar() or 0
        spends = db.query(MandateSpend).filter(MandateSpend.tenant_id == tenant_id).all()
        total_usd = sum(float(s.amount) for s in spends if s.currency == "USD") / 100.0
        try:
            del_count = db.execute(
                text("SELECT COUNT(*) FROM delegation_registry WHERE tenant_id = :tid"),
                {"tid": tenant_id},
            ).scalar() or 0
        except Exception:
            del_count = 0

    chain = verify_chain(tenant_id)

    return DemoSummaryResponse(
        agents_count=agents_count,
        credentials_active=len(creds) - revoked_count,
        credentials_revoked=revoked_count,
        delegations_count=del_count,
        audit_events_count=audit_count,
        chain_valid=chain["valid"],
        trust_events_count=trust_count,
        mandate_spends_count=len(spends),
        total_spend_usd=total_usd,
    )
