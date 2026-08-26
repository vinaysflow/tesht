from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy import select

from core.audit import verify_chain
from core.db import db_session
from api.middleware.authz import require_scopes
from models import AuditEvent

router = APIRouter(prefix="/v1/audit", tags=["audit"])


class AuditEventOut(BaseModel):
    id: str
    event_type: str
    actor: str
    resource_type: str
    resource_id: str
    payload: dict
    created_at: datetime
    event_hash: Optional[str] = None
    prev_hash: Optional[str] = None


def _serialize(e: AuditEvent) -> dict:
    return AuditEventOut(
        id=str(e.id),
        event_type=e.event_type,
        actor=e.actor,
        resource_type=e.resource_type,
        resource_id=e.resource_id,
        payload=e.payload_json,
        created_at=e.created_at,
        event_hash=e.event_hash,
        prev_hash=e.prev_hash,
    ).model_dump()


@router.get("")
def list_audit_events(
    limit: int = 50,
    after: Optional[str] = None,
    include_public: bool = False,
    actor: Optional[str] = None,
    event_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    auth: dict = Depends(require_scopes(["tenant:admin"])),
):
    """List audit events with cursor-based pagination.

    Use `after=<last_event_id>` to page forward. Returns newest-first.
    """
    limit = max(1, min(limit, 500))
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        q = db.query(AuditEvent)
        if include_public:
            q = q.filter(AuditEvent.tenant_id.in_([tenant_id, "public"]))
        else:
            q = q.filter(AuditEvent.tenant_id == tenant_id)
        if actor:
            q = q.filter(AuditEvent.actor == actor)
        if event_type:
            q = q.filter(AuditEvent.event_type == event_type)
        if resource_type:
            q = q.filter(AuditEvent.resource_type == resource_type)
        if resource_id:
            q = q.filter(AuditEvent.resource_id == resource_id)

        if after:
            try:
                cursor_id = uuid.UUID(after)
                cursor_evt = db.query(AuditEvent).filter(AuditEvent.id == cursor_id).one_or_none()
                if cursor_evt:
                    q = q.filter(AuditEvent.created_at < cursor_evt.created_at)
            except (ValueError, TypeError):
                pass  # ignore invalid cursor

        events = q.order_by(AuditEvent.created_at.desc()).limit(limit).all()

    return {
        "events": [_serialize(e) for e in events],
        "next_cursor": str(events[-1].id) if len(events) == limit else None,
    }


@router.get("/export")
def export_audit_events(
    format: str = "jsonl",
    auth: dict = Depends(require_scopes(["tenant:admin"])),
):
    """Export all audit events as JSONL for independent chain verification."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        events = (
            db.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == tenant_id)
                .order_by(AuditEvent.created_at.asc())
            )
            .scalars()
            .all()
        )

    lines = [json.dumps(_serialize(e), default=str) for e in events]
    content = "\n".join(lines)

    return Response(
        content=content,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="audit-{tenant_id}.jsonl"'},
    )


@router.get("/verify")
def verify_audit_chain(
    auth: dict = Depends(require_scopes(["tenant:admin"])),
):
    """Walk the entire audit chain and verify hash integrity.

    Returns whether the chain is valid and where it first breaks if not.
    """
    tenant_id = auth.get("tenant_id", "default")
    result = verify_chain(tenant_id)
    return result
