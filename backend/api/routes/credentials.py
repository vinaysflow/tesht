from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from api.middleware.authz import require_scopes
from core import did as did_core
from core.audit import write_audit
from core.db import db_session
from core.settings import settings
from core.status_list import allocate_index, get_or_create_default_list
from core.tenancy import ensure_tenant
from core.vc import issue_vc_jwt
from core.webhooks import dispatch_webhook_event
from models import Agent, Credential

router = APIRouter(prefix="/v1/credentials", tags=["credentials"])


class IssueCredentialRequest(BaseModel):
    issuer_agent_id: uuid.UUID
    subject_did: str = Field(min_length=3, max_length=600)
    credential_type: str = Field(default="AgentCredential", min_length=1, max_length=200)
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=60 * 60 * 24 * 365)
    subject_claims: Optional[dict[str, Any]] = None


class IssueCredentialResponse(BaseModel):
    credential_id: uuid.UUID
    jwt: str
    jti: str
    issued_at: datetime
    expires_at: Optional[datetime]
    status_list_id: uuid.UUID
    status_list_index: int


@router.post("/issue", response_model=IssueCredentialResponse)
def issue_credential(
    req: IssueCredentialRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
):
    tenant_id = auth.get("tenant_id", "default")
    sl = get_or_create_default_list(tenant_id=tenant_id)
    index = allocate_index(sl.id)

    status_list_url = f"{settings.tesht_scheme}://{did_core.domain_decoded()}/v1/status/{sl.id}"

    with db_session() as db:
        ensure_tenant(db, tenant_id)
        issuer = db.query(Agent).filter(Agent.id == req.issuer_agent_id).filter(Agent.tenant_id == tenant_id).one_or_none()
        if issuer is None:
            raise HTTPException(status_code=404, detail="Issuer agent not found")


    token, jti, iat, exp = issue_vc_jwt(
        issuer_agent_id=req.issuer_agent_id,
        subject_did=req.subject_did,
        credential_type=req.credential_type,
        status_list_url=status_list_url,
        status_list_index=index,
        ttl_seconds=req.ttl_seconds,
        extra_claims=req.subject_claims,
    )

    cred = Credential(
        tenant_id=tenant_id,
        issuer_agent_id=req.issuer_agent_id,
        subject_did=req.subject_did,
        credential_type=req.credential_type,
        jti=jti,
        jwt=token,
        status_list_id=sl.id,
        status_list_index=index,
        issued_at=datetime.utcfromtimestamp(iat),
        expires_at=(datetime.utcfromtimestamp(exp) if exp else None),
    )

    with db_session() as db:
        db.add(cred)
        db.commit()
        db.refresh(cred)

    write_audit(
        tenant_id=tenant_id,
        event_type="credential.issued",
        actor=str(req.issuer_agent_id),
        resource_type="credential",
        resource_id=str(cred.id),
        payload={"jti": jti, "subject": req.subject_did, "type": req.credential_type, "status_list_index": index},
    )

    background_tasks.add_task(
        dispatch_webhook_event,
        tenant_id,
        "credential.issued",
        {
            "credential_id": str(cred.id),
            "jti": jti,
            "issuer_agent_id": str(req.issuer_agent_id),
            "subject_did": req.subject_did,
            "credential_type": req.credential_type,
        },
    )

    return IssueCredentialResponse(
        credential_id=cred.id,
        jwt=token,
        jti=jti,
        issued_at=cred.issued_at,
        expires_at=cred.expires_at,
        status_list_id=sl.id,
        status_list_index=index,
    )
