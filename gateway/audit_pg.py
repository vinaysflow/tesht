"""
gateway.audit_pg
~~~~~~~~~~~~~~~~
Persistent audit event writer for the MCP Identity Gateway.

Writes every gateway request event to PostgreSQL with SHA-256 hash chaining,
identical to the backend's tamper-evident audit trail.  Falls back gracefully
if the database is unavailable.

The writer maintains the same in-memory ``_events`` list as
``GatewayAuditWriter`` so the ``/gateway/events`` endpoint keeps working
unchanged (important for the React demo-app).

Usage:
    writer = PersistentAuditWriter(database_url="postgresql://...", tenant_id="gateway")

The ``tenant_id`` is ``"gateway"`` by default, which keeps gateway events
segregated from backend application events in the same ``audit_events`` table.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_ts(dt: Optional[datetime]) -> str:
    """Return a canonical UTC ISO 8601 string regardless of input timezone."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Always normalize to UTC so write-time and read-time produce identical strings.
    return dt.astimezone(timezone.utc).isoformat()


def _compute_event_hash(
    event_id: str,
    event_type: str,
    actor: str,
    resource_id: str,
    payload_json: dict,
    created_at: datetime,
    prev_hash: str,
) -> str:
    """SHA-256 over deterministic fields — identical algorithm to backend/core/audit.py."""
    payload_str = json.dumps(payload_json, sort_keys=True, separators=(",", ":"))
    created_at_iso = _normalize_ts(created_at)
    raw = (
        f"{event_id}|{event_type}|{actor}|{resource_id}"
        f"|{payload_str}|{created_at_iso}|{prev_hash}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class PersistentAuditWriter:
    """
    Drop-in replacement for GatewayAuditWriter that persists events to
    PostgreSQL with SHA-256 hash chaining.

    - Same ``log_request()`` interface as the in-memory writer.
    - Writes to PG non-blocking via a dedicated ThreadPoolExecutor.
    - Maintains an in-memory copy for the ``/gateway/events`` endpoint.
    - Exposes ``verify_chain()`` to prove tamper-evidence.
    """

    def __init__(self, database_url: str, tenant_id: str = "gateway") -> None:
        from sqlalchemy import (
            Column, DateTime, JSON, String, Text, create_engine, desc, select
        )
        from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

        self._database_url = database_url
        self._tenant_id = tenant_id
        self._events: list[dict[str, Any]] = []
        # Single-worker executor + lock guarantees serial writes so the hash
        # chain is never forked by concurrent requests.
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="audit-pg")
        self._write_lock = threading.Lock()

        # Build a self-contained engine — does NOT share the backend singleton.
        engine_kwargs: dict[str, Any] = {"pool_pre_ping": True}
        if not database_url.startswith("sqlite"):
            engine_kwargs.update({"pool_size": 3, "max_overflow": 5})
        self._engine = create_engine(database_url, **engine_kwargs)
        self._Session = sessionmaker(bind=self._engine, autocommit=False, autoflush=False)

        # Inline minimal ORM model — avoids importing backend.models which
        # drags in backend settings, OIDC config, etc.
        class _Base(DeclarativeBase):
            pass

        class _AuditEvent(_Base):
            __tablename__ = "audit_events"
            __table_args__ = {"extend_existing": True}

            id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
            tenant_id = Column(String(100), nullable=False, default="default", index=True)
            event_type = Column(String(100), nullable=False)
            actor = Column(String(200), nullable=False)
            resource_type = Column(String(100), nullable=False)
            resource_id = Column(String(200), nullable=False)
            payload_json = Column(JSON, nullable=False, default=dict)
            created_at = Column(DateTime(timezone=True), nullable=False, default=_now_utc)
            event_hash = Column(String(64), nullable=True)
            prev_hash = Column(String(64), nullable=True)
            chain_signature = Column(Text, nullable=True)

        self._AuditEvent = _AuditEvent

        # Ensure table exists (idempotent — no-op if already created by Alembic).
        try:
            _Base.metadata.create_all(self._engine, checkfirst=True)
            logger.info("PersistentAuditWriter ready (tenant=%s)", tenant_id)
        except Exception as exc:
            logger.warning("PersistentAuditWriter: table creation skipped: %s", exc)

    # ------------------------------------------------------------------
    # Public interface (mirrors GatewayAuditWriter exactly)
    # ------------------------------------------------------------------

    def log_request(
        self,
        request_id: str,
        server_name: str,
        method: str,
        tool_name: Optional[str],
        auth_result: Any,
        trust_eval: Any,
        scope_check: Any,
        proxy_result: Any,
        decision: str,
        total_latency_ms: float,
        source_ip: Optional[str] = None,
        auth_reason: Optional[str] = None,
        delegation_depth: Optional[int] = None,
        delegation_chain_dids: Optional[list] = None,
    ) -> None:
        """Record a gateway request — in-memory immediately, PostgreSQL async."""
        event: dict[str, Any] = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server_name": server_name,
            "method": method,
            "tool_name": tool_name,
            "agent_did": auth_result.agent_did,
            "agent_name": auth_result.agent_name,
            "delegator_did": auth_result.delegator_did,
            "delegator_claims": auth_result.delegator_claims,
            "effective_scope": auth_result.effective_scope if hasattr(auth_result, "effective_scope") else None,
            "trust_score": trust_eval.score,
            "trust_decision": trust_eval.decision,
            "trust_factors": trust_eval.factors if trust_eval else {},
            "scope_allowed": scope_check.allowed if scope_check else None,
            "scope_reason": scope_check.reason if scope_check else None,
            "decision": decision,
            "proxy_status": proxy_result.status_code if proxy_result else None,
            "proxy_latency_ms": proxy_result.latency_ms if proxy_result else None,
            "auth_latency_ms": auth_result.auth_latency_ms,
            "total_latency_ms": total_latency_ms,
            "blended": auth_result.blended,
            "source_ip": source_ip,
            "auth_reason": auth_reason,
            "delegation_depth": delegation_depth,
            "delegation_chain_dids": delegation_chain_dids,
        }
        # 1. Immediate in-memory append (keeps /gateway/events working)
        self._events.append(event)

        # 2. Non-blocking PG write via thread executor
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.run_in_executor(self._executor, self._write_to_pg, event)
            else:
                self._executor.submit(self._write_to_pg, event)
        except Exception as exc:
            logger.warning("PersistentAuditWriter: failed to schedule PG write: %s", exc)

    def get_recent_events(self, n: int = 50) -> list[dict[str, Any]]:
        return self._events[-n:]

    def get_events_for_agent(self, agent_did: str) -> list[dict[str, Any]]:
        return [e for e in self._events if e.get("agent_did") == agent_did]

    def get_events_filtered(
        self,
        agent_did: Optional[str] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """Return events filtered by agent DID and/or time range.

        ISO 8601 UTC strings compare lexicographically, so string comparison
        is equivalent to datetime comparison when both sides are UTC.
        """
        results = []
        for e in self._events:
            if agent_did and e.get("agent_did") != agent_did:
                continue
            ts = e.get("timestamp", "")
            if from_ts and ts < from_ts:
                continue
            if to_ts and ts > to_ts:
                continue
            results.append(e)
            if len(results) >= limit:
                break
        return results

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> dict[str, Any]:
        """Walk the full audit chain for this tenant and verify hash integrity."""
        from sqlalchemy import asc, select as sa_select

        try:
            with self._Session() as db:
                rows = db.execute(
                    sa_select(self._AuditEvent)
                    .where(self._AuditEvent.tenant_id == self._tenant_id)
                    .order_by(asc(self._AuditEvent.created_at))
                ).scalars().all()
        except Exception as exc:
            return {
                "valid": False,
                "events_checked": 0,
                "first_broken_at": None,
                "reason": f"Database error: {exc}",
                "storage": "postgresql",
                "tenant_id": self._tenant_id,
            }

        if not rows:
            return {
                "valid": True,
                "events_checked": 0,
                "first_broken_at": None,
                "reason": None,
                "storage": "postgresql",
                "tenant_id": self._tenant_id,
            }

        # Only verify events that were written with the hash-chain logic (have a non-null
        # event_hash). Pre-existing rows from the backend app may have null hashes and are
        # skipped — the gateway chain is an independent sub-chain within the same table.
        hashed_rows = [r for r in rows if r.event_hash is not None]

        if not hashed_rows:
            return {
                "valid": True,
                "events_checked": 0,
                "first_broken_at": None,
                "reason": "No hash-chained events yet",
                "storage": "postgresql",
                "tenant_id": self._tenant_id,
            }

        # Verify consecutive pairs — each row's prev_hash must equal the previous row's
        # event_hash (or GENESIS_HASH for the first row).
        prev_hash = hashed_rows[0].prev_hash or _GENESIS_HASH
        for idx, evt in enumerate(hashed_rows):
            if evt.prev_hash != prev_hash:
                return {
                    "valid": False,
                    "events_checked": idx,
                    "first_broken_at": str(evt.id),
                    "reason": f"prev_hash mismatch at event {evt.id}",
                    "storage": "postgresql",
                    "tenant_id": self._tenant_id,
                }

            # Use _hash_input if present (new-style events), else full payload_json
            payload = evt.payload_json or {}
            hash_input = payload.get("_hash_input") or payload
            expected = _compute_event_hash(
                str(evt.id),
                evt.event_type,
                evt.actor,
                evt.resource_id,
                hash_input,
                evt.created_at,
                evt.prev_hash or _GENESIS_HASH,
            )
            if evt.event_hash != expected:
                return {
                    "valid": False,
                    "events_checked": idx,
                    "first_broken_at": str(evt.id),
                    "reason": f"event_hash mismatch at event {evt.id}: record was tampered",
                    "storage": "postgresql",
                    "tenant_id": self._tenant_id,
                }

            prev_hash = evt.event_hash

        return {
            "valid": True,
            "events_checked": len(hashed_rows),
            "first_broken_at": None,
            "reason": None,
            "storage": "postgresql",
            "tenant_id": self._tenant_id,
        }

    # ------------------------------------------------------------------
    # Internal sync write (runs in thread executor)
    # ------------------------------------------------------------------

    def _write_to_pg(self, event: dict[str, Any]) -> None:
        """Synchronous PostgreSQL write — runs in single-worker thread pool.

        The write lock serializes all writes so the hash chain is never forked
        by two concurrent requests reading the same prev_hash simultaneously.
        """
        from sqlalchemy import desc as sa_desc, select as sa_select

        AuditEvent = self._AuditEvent

        with self._write_lock:
            agent_did = event.get("agent_did") or "anonymous"
            decision = event.get("decision", "unknown")
            server_name = event.get("server_name", "unknown")
            tool_name = event.get("tool_name") or "unknown"
            resource_id = f"{server_name}/{tool_name}"

            # Build payload — all gateway fields go into payload_json
            payload = {k: v for k, v in event.items() if v is not None}

            try:
                with self._Session() as db:
                    # Fetch the last event with a non-null hash for this tenant.
                    # This keeps the chain consistent even if pre-existing backend events
                    # (with null hashes) exist in the same table.
                    last = db.execute(
                        sa_select(AuditEvent)
                        .where(
                            AuditEvent.tenant_id == self._tenant_id,
                            AuditEvent.event_hash.isnot(None),
                        )
                        .order_by(sa_desc(AuditEvent.created_at))
                        .limit(1)
                    ).scalars().first()

                    prev_hash = last.event_hash if last else _GENESIS_HASH

                    event_id = str(uuid.uuid4())
                    created_at = _now_utc()

                    evt = AuditEvent(
                        id=event_id,
                        tenant_id=self._tenant_id,
                        event_type=decision,
                        actor=agent_did,
                        resource_type="mcp_request",
                        resource_id=resource_id,
                        payload_json=payload,
                        created_at=created_at,
                        prev_hash=prev_hash,
                    )
                    db.add(evt)
                    db.flush()

                    # Hash over stable, non-volatile fields only — avoids float/dict
                    # serialization differences between Python and PostgreSQL round-trips.
                    # Store the hash_input in payload_json so verify_chain can reconstruct it.
                    stable_payload = {
                        "decision": decision,
                        "server_name": event.get("server_name"),
                        "tool_name": event.get("tool_name") or "unknown",
                        "agent_did": agent_did,
                        "delegator_did": event.get("delegator_did") or "",
                        "trust_score": int(event.get("trust_score") or 0),
                        "request_id": event.get("request_id") or "",
                    }
                    evt.payload_json = {**payload, "_hash_input": stable_payload}
                    evt.event_hash = _compute_event_hash(
                        event_id,
                        decision,
                        agent_did,
                        resource_id,
                        stable_payload,
                        created_at,
                        prev_hash,
                    )
                    db.commit()

            except Exception as exc:
                logger.error("PersistentAuditWriter: PG write failed: %s", exc)

    def close(self) -> None:
        self._executor.shutdown(wait=False)
        self._engine.dispose()
