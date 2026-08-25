from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Any

import httpx

from core.db import db_session
from models import Webhook

VALID_EVENT_TYPES = [
    "credential.issued",
    "credential.revoked",
    "trust.score_changed",
    "agent.created",
    "session.created",
    "session.decision",
    "session.step_up",
    "session.revoked",
]


def compute_signature(secret: str, body_bytes: bytes) -> str:
    """Compute HMAC-SHA256 signature. Returns 'sha256=<hex>'."""
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def dispatch_webhook_event(
    tenant_id: str,
    event_type: str,
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Find all active webhooks for the tenant matching the event_type and POST to each.

    Fire-and-forget with 5s timeout per delivery.
    Never raises — all errors are captured in the returned list.

    Returns: [{webhook_id, status_code, error}]
    """
    with db_session() as db:
        webhooks = (
            db.query(Webhook)
            .filter(
                Webhook.tenant_id == tenant_id,
                Webhook.active.is_(True),
            )
            .all()
        )
        matching = [w for w in webhooks if event_type in (w.events or [])]

    if not matching:
        return []

    delivery_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "event": event_type,
        "timestamp": timestamp,
        "delivery_id": delivery_id,
        "data": data,
    }

    body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    results = []
    for webhook in matching:
        signature = compute_signature(webhook.secret, body_bytes)
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.post(
                    webhook.url,
                    content=body_bytes,
                    headers={
                        "Content-Type": "application/json",
                        "X-Pramana-Signature": signature,
                        "X-Pramana-Event": event_type,
                        "X-Pramana-Delivery-Id": delivery_id,
                    },
                )
            results.append({
                "webhook_id": str(webhook.id),
                "status_code": response.status_code,
                "error": None,
            })
        except Exception as exc:
            results.append({
                "webhook_id": str(webhook.id),
                "status_code": None,
                "error": str(exc),
            })

    return results
