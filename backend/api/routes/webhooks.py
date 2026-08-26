from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from api.middleware.authz import require_scopes
from core.audit import write_audit
from core.db import db_session
from core.webhooks import VALID_EVENT_TYPES, dispatch_webhook_event
from models import Webhook

router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])


class CreateWebhookRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    events: list[str] = Field(min_length=1)
    secret: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = Field(default=None, max_length=500)

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: list[str]) -> list[str]:
        invalid = [e for e in v if e not in VALID_EVENT_TYPES]
        if invalid:
            raise ValueError(
                f"Invalid event type(s): {invalid}. "
                f"Valid types: {VALID_EVENT_TYPES}"
            )
        return v


class WebhookCreateResponse(BaseModel):
    id: str
    tenant_id: str
    url: str
    events: list[str]
    secret: str
    active: bool
    description: Optional[str]
    created_at: str


class WebhookListItem(BaseModel):
    id: str
    url: str
    events: list[str]
    active: bool
    description: Optional[str]
    created_at: str


class WebhookDeliveryResult(BaseModel):
    webhook_id: str
    status_code: Optional[int]
    error: Optional[str]


@router.post("", response_model=WebhookCreateResponse)
def create_webhook(
    req: CreateWebhookRequest,
    auth: dict = Depends(require_scopes(["webhooks:manage"])),
) -> WebhookCreateResponse:
    """Register a new webhook endpoint."""
    tenant_id = auth.get("tenant_id", "default")
    secret = req.secret or secrets.token_hex(32)

    webhook = Webhook(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        url=req.url,
        events=req.events,
        secret=secret,
        active=True,
        description=req.description,
        created_at=datetime.utcnow(),
    )
    with db_session() as db:
        db.add(webhook)
        db.commit()
        db.refresh(webhook)
        webhook_id = str(webhook.id)
        created_at = webhook.created_at.isoformat() + "Z"

    write_audit(
        tenant_id=tenant_id,
        event_type="webhook.created",
        actor="api",
        resource_type="webhook",
        resource_id=webhook_id,
        payload={"url": req.url, "events": req.events},
    )

    return WebhookCreateResponse(
        id=webhook_id,
        tenant_id=tenant_id,
        url=req.url,
        events=req.events,
        secret=secret,
        active=True,
        description=req.description,
        created_at=created_at,
    )


@router.get("", response_model=list[WebhookListItem])
def list_webhooks(
    auth: dict = Depends(require_scopes(["webhooks:manage"])),
) -> list[WebhookListItem]:
    """List all active webhooks for the tenant. Secret is never returned."""
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        webhooks = (
            db.query(Webhook)
            .filter(Webhook.tenant_id == tenant_id, Webhook.active.is_(True))
            .order_by(Webhook.created_at.desc())
            .all()
        )
        return [
            WebhookListItem(
                id=str(w.id),
                url=w.url,
                events=w.events or [],
                active=w.active,
                description=w.description,
                created_at=w.created_at.isoformat() + "Z",
            )
            for w in webhooks
        ]


@router.delete("/{webhook_id}")
def delete_webhook(
    webhook_id: uuid.UUID,
    auth: dict = Depends(require_scopes(["webhooks:manage"])),
) -> dict[str, Any]:
    """Soft-delete a webhook by setting active=False."""
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        webhook = (
            db.query(Webhook)
            .filter(Webhook.id == webhook_id, Webhook.tenant_id == tenant_id)
            .one_or_none()
        )
        if webhook is None:
            raise HTTPException(status_code=404, detail="Webhook not found")
        webhook.active = False
        db.commit()

    write_audit(
        tenant_id=tenant_id,
        event_type="webhook.deleted",
        actor="api",
        resource_type="webhook",
        resource_id=str(webhook_id),
        payload={},
    )
    return {"deleted": True, "webhook_id": str(webhook_id)}


@router.post("/{webhook_id}/test", response_model=list[WebhookDeliveryResult])
def test_webhook(
    webhook_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["webhooks:manage"])),
) -> list[WebhookDeliveryResult]:
    """Send a test event to a specific webhook URL and return delivery result."""
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        webhook = (
            db.query(Webhook)
            .filter(Webhook.id == webhook_id, Webhook.tenant_id == tenant_id)
            .one_or_none()
        )
        if webhook is None:
            raise HTTPException(status_code=404, detail="Webhook not found")
        wh_events = webhook.events or []

    test_event = wh_events[0] if wh_events else "credential.issued"
    results = dispatch_webhook_event(
        tenant_id=tenant_id,
        event_type=test_event,
        data={"test": True, "webhook_id": str(webhook_id)},
    )
    return [WebhookDeliveryResult(**r) for r in results]
