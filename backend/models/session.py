from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class AuthorizationSession(Base):
    """Agent authorization session (Stripe-like handoff object).

    Orchestrates identity → mandate → risk → allow/step_up/revoke.
    Additive over existing credential/delegation/trust primitives.
    """

    __tablename__ = "authorization_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)

    # active | step_up_required | revoked | expired
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active", index=True)

    agent_did: Mapped[str] = mapped_column(String(600), nullable=False, index=True)
    human_did: Mapped[Optional[str]] = mapped_column(String(600), nullable=True, index=True)
    delegation_jti: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)

    # Scope / packs / evidence
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    packs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    proof_bundle: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_decision: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    trust_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # metadata is reserved by SQLAlchemy Declarative
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    # Idempotency
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)
    request_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
