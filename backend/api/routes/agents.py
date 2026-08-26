from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from core import did as did_core
from core.crypto import encrypt_text
from core.db import db_session
from core.settings import settings
from core.tenancy import ensure_tenant
from api.middleware.authz import require_scopes
from models import Agent, Key

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class CreateAgentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class CreateAgentResponse(BaseModel):
    id: uuid.UUID
    name: str
    did: str
    did_document: dict
    did_document_url: str
    created_at: datetime


@router.post("", response_model=CreateAgentResponse)
def create_agent(req: CreateAgentRequest, auth: dict = Depends(require_scopes(["agents:create"]))):
    agent_id = uuid.uuid4()
    did = did_core.create_did(agent_id)

    private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
    kid = f"{did}#key-1"

    tenant_id = auth.get("tenant_id", "default")
    agent = Agent(id=agent_id, name=req.name, did=did, tenant_id=tenant_id)
    key = Key(
        agent_id=agent_id,
        tenant_id=tenant_id,
        kid=kid,
        public_jwk=public_jwk,
        private_key_enc=encrypt_text(private_pem),
    )

    with db_session() as db:
        ensure_tenant(db, tenant_id)
        db.add(agent)
        db.add(key)
        db.commit()
        db.refresh(agent)

    doc = did_core.build_did_document(did=did, kid=kid, public_jwk=public_jwk)
    did_url = f"{settings.tesht_scheme}://{did_core.domain_decoded()}/agents/{agent_id}/did.json"

    return CreateAgentResponse(
        id=agent.id,
        name=agent.name,
        did=agent.did,
        did_document=doc,
        did_document_url=did_url,
        created_at=agent.created_at,
    )
