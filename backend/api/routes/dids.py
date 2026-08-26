from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from core.db import db_session
from core.did import build_did_document_multi
from models import Agent, Key
from core.status_issuer import status_issuer_did

router = APIRouter(tags=["dids"])


@router.get("/agents/{agent_id}/did.json")
def agent_did_document(agent_id: uuid.UUID):
    with db_session() as db:
        agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        keys = (
            db.query(Key)
            .filter(Key.agent_id == agent.id)
            .order_by(Key.created_at.asc())
            .all()
        )
        if not keys:
            raise HTTPException(status_code=404, detail="Key not found")

    return build_did_document_multi(did=agent.did, keys=[{"kid": k.kid, "public_jwk": k.public_jwk} for k in keys])


@router.get("/v1/dids/{did_path:path}/did.json")
def did_document_by_path(did_path: str):
    # did_path is like: localhost%3A8000/agents/<uuid>
    did = "did:web:" + did_path.replace("/", ":")

    with db_session() as db:
        agent = db.query(Agent).filter(Agent.did == did).one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail="DID not found")
        keys = (
            db.query(Key)
            .filter(Key.agent_id == agent.id)
            .order_by(Key.created_at.asc())
            .all()
        )
        if not keys:
            raise HTTPException(status_code=404, detail="Key not found")

    return build_did_document_multi(did=agent.did, keys=[{"kid": k.kid, "public_jwk": k.public_jwk} for k in keys])


@router.get("/.well-known/did.json")
def well_known_did_document():
    did = status_issuer_did()

    with db_session() as db:
        agent = db.query(Agent).filter(Agent.did == did).one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail="DID not found")
        keys = (
            db.query(Key)
            .filter(Key.agent_id == agent.id)
            .order_by(Key.created_at.asc())
            .all()
        )
        if not keys:
            raise HTTPException(status_code=404, detail="Key not found")

    return build_did_document_multi(did=agent.did, keys=[{"kid": k.kid, "public_jwk": k.public_jwk} for k in keys])
