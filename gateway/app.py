"""
gateway.app
~~~~~~~~~~~~
Pramana MCP Identity Gateway — FastAPI application.

Eight-step per-request pipeline:
  1. Validate upstream server name
  2. Authenticate (verify blended VP)
  3. Parse JSON-RPC method and tool name
  4. Scope check (tool vs delegation)
  5. Trust evaluation
  6. Proxy to upstream with credential injection
  7. Audit log
  8. Return response

Run standalone:
    uvicorn gateway.app:app --host 0.0.0.0 --port 5052
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from gateway.audit import GatewayAuditWriter
from gateway.auth import GatewayAuth, GatewayAuthResult
from gateway.config import load_config
from gateway.detection.engine import DetectionEngine
import logging

_logger = logging.getLogger(__name__)
from gateway.jsonrpc import (
    build_jsonrpc_error,
    extract_tool_name,
    is_tool_call,
    parse_jsonrpc,
)
from gateway.proxy import MCPProxy
from gateway.scope import ScopeChecker
from gateway.trust import GatewayTrustEvaluator, TrustEvaluation

_EMPTY_TRUST = TrustEvaluation(
    score=0, decision="block", factors={}, cached=False, explanation="", latency_ms=0,
)


def _env_truthy(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _make_status_checker(*, fail_closed: bool = False) -> Callable[[str, int], bool]:
    """Return a status_checker that fetches a BitstringStatusList from the
    given URL and checks whether the credential at *index* is revoked.

    Default is fail-open (returns False / not-revoked) on network/parse errors
    so demos stay resilient. Set ``auth.fail_closed: true`` in config.yaml or
    ``GATEWAY_FAIL_CLOSED=1`` for production (treat errors as revoked).
    """
    import httpx as _httpx

    env_override = _env_truthy("GATEWAY_FAIL_CLOSED")
    closed = fail_closed if env_override is None else env_override

    # Bounded retry so a single transient network blip does not falsely revoke
    # a valid credential (important once fail_closed is the production default).
    _attempts = 2
    _backoff_seconds = 0.15

    def checker(status_list_url: str, index: int) -> bool:
        last_exc: Optional[Exception] = None
        for attempt in range(_attempts):
            try:
                r = _httpx.get(status_list_url, timeout=2.0)
                r.raise_for_status()
                data = r.json()
                bits_b64 = data.get("bitstring", "")
                padded = bits_b64 + "=" * ((4 - len(bits_b64) % 4) % 4)
                bits = base64.urlsafe_b64decode(padded)
                byte_i = index // 8
                bit_i = index % 8
                if byte_i >= len(bits):
                    return bool(closed)  # unknown index: fail-closed => revoked
                return bool(bits[byte_i] & (1 << bit_i))
            except Exception as exc:
                last_exc = exc
                if attempt + 1 < _attempts:
                    time.sleep(_backoff_seconds)
        _logger.warning(
            "status_checker failed after %d attempts for %s index %d (fail_closed=%s): %s",
            _attempts, status_list_url, index, closed, last_exc,
        )
        return bool(closed)  # fail-closed => treat as revoked

    return checker


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup / shutdown lifecycle for the gateway."""
    config_path = os.environ.get(
        "GATEWAY_CONFIG",
        str(Path(__file__).resolve().parent / "config.yaml"),
    )
    config = load_config(config_path)

    application.state.config = config
    fail_closed = config.auth.fail_closed
    env_fc = _env_truthy("GATEWAY_FAIL_CLOSED")
    if env_fc is not None:
        fail_closed = env_fc

    # Production requires durable Postgres audit unless env explicitly overrides.
    require_pg_env = _env_truthy("GATEWAY_REQUIRE_PG_AUDIT")
    require_pg = config.production if require_pg_env is None else require_pg_env

    _logger.info(
        "Gateway profile: production=%s fail_closed=%s require_pg_audit=%s cold_path=%s",
        config.production, fail_closed, require_pg, config.trust.cold_path_enabled,
    )
    application.state.auth = GatewayAuth(
        config, status_checker=_make_status_checker(fail_closed=fail_closed)
    )
    application.state.trust = GatewayTrustEvaluator(config.trust)
    application.state.scope = ScopeChecker(config.upstream_servers)
    application.state.proxy = MCPProxy(config.upstream_servers)

    # Prefer PersistentAuditWriter when DATABASE_URL is set (production default).
    # In production (or GATEWAY_REQUIRE_PG_AUDIT=1) startup fails instead of
    # silently falling back to the in-memory writer.
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        try:
            from gateway.audit_pg import PersistentAuditWriter
            application.state.audit = PersistentAuditWriter(database_url)
            _logger.info("Gateway audit: PostgreSQL mode (url=%s)", database_url[:30] + "…")
        except Exception as exc:
            if require_pg:
                raise RuntimeError(
                    f"GATEWAY_REQUIRE_PG_AUDIT=1 but PersistentAuditWriter failed: {exc}"
                ) from exc
            _logger.warning("PersistentAuditWriter init failed (%s) — falling back to in-memory", exc)
            application.state.audit = GatewayAuditWriter()
    else:
        if require_pg:
            raise RuntimeError(
                "Durable audit required (PRAMANA_ENV=production or "
                "GATEWAY_REQUIRE_PG_AUDIT=1) but DATABASE_URL is not set"
            )
        application.state.audit = GatewayAuditWriter()
        _logger.info("Gateway audit: in-memory mode (set DATABASE_URL for PostgreSQL persistence)")

    application.state.detection = DetectionEngine(
        application.state.audit, application.state.trust
    )

    yield

    await application.state.proxy.close()
    trust_mod = getattr(application.state, "trust", None)
    if trust_mod is not None and hasattr(trust_mod, "close"):
        trust_mod.close()


app = FastAPI(
    title="Pramana MCP Identity Gateway",
    version="0.1.0",
    lifespan=lifespan,
)

if os.getenv("PRAMANA_CORS_ENABLED", "").lower() in ("1", "true", "yes"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Pramana-Trust-Factors", "X-Pramana-StepUp"],
    )


# ---------------------------------------------------------------------------
# Main proxy endpoint
# ---------------------------------------------------------------------------

@app.post("/mcp/{server_name}")
async def proxy_mcp(server_name: str, request: Request) -> Response:
    """Eight-step MCP proxy pipeline."""
    request_id = uuid.uuid4().hex[:8]
    start = time.monotonic()

    auth_mod: GatewayAuth = request.app.state.auth
    trust_mod: GatewayTrustEvaluator = request.app.state.trust
    scope_mod: ScopeChecker = request.app.state.scope
    proxy_mod: MCPProxy = request.app.state.proxy
    audit_mod: GatewayAuditWriter = request.app.state.audit
    detection_mod: DetectionEngine = request.app.state.detection

    source_ip: Optional[str] = request.client.host if request.client else None

    # ── 1. Validate server name ──────────────────────────────────────
    if server_name not in request.app.state.config.upstream_servers:
        return JSONResponse(
            status_code=404,
            content=build_jsonrpc_error(None, -32000, f"Unknown MCP server: {server_name}"),
        )

    # ── 2. Authenticate — verify blended VP ──────────────────────────
    auth_header = request.headers.get("authorization", "")
    auth_result = auth_mod.authenticate(auth_header)

    if not auth_result.authenticated:
        _empty_auth = auth_result
        detection_mod.register_failed_auth(auth_result.reason or "unknown", source_ip, server_name=server_name)
        audit_mod.log_request(
            request_id, server_name, "unknown", None,
            _empty_auth,
            TrustEvaluation(0, "block", {}, False, auth_result.reason or "", 0),
            None, None, "blocked_auth",
            (time.monotonic() - start) * 1000,
            source_ip=source_ip,
            auth_reason=auth_result.reason,
        )
        return JSONResponse(
            status_code=401,
            content=build_jsonrpc_error(
                None, -32001,
                f"Authentication failed: {auth_result.reason}",
            ),
        )

    detection_mod.register_successful_auth(auth_result, source_ip)

    # Extract delegation chain info for audit enrichment
    _delegation_depth: Optional[int] = None
    _delegation_chain_dids: Optional[list] = None
    if auth_result.raw_result and auth_result.raw_result.delegation:
        _d = auth_result.raw_result.delegation
        _delegation_depth = _d.depth
        if _d.chain:
            _delegation_chain_dids = (
                [link["delegator"] for link in _d.chain]
                + ([auth_result.agent_did] if auth_result.agent_did else [])
            )

    # ── 3. Parse JSON-RPC body ───────────────────────────────────────
    body = await request.body()
    try:
        jsonrpc = parse_jsonrpc(body)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content=build_jsonrpc_error(None, -32700, f"Parse error: {exc}"),
        )

    tool_name = extract_tool_name(jsonrpc)

    # ── 4. Scope check ───────────────────────────────────────────────
    scope_result = None
    if tool_name and is_tool_call(jsonrpc):
        scope_result = scope_mod.check(
            server_name, tool_name, auth_result.effective_scope
        )
        if not scope_result.allowed:
            agent_did = auth_result.agent_did or ""
            trust_mod.record_scope_violation(agent_did, tool_name)
            trust_mod.update_from_request(agent_did, tool_name, success=False)
            audit_mod.log_request(
                request_id, server_name, jsonrpc.method, tool_name,
                auth_result,
                TrustEvaluation(0, "block", {}, False, scope_result.reason, 0),
                scope_result, None, "blocked_scope",
                (time.monotonic() - start) * 1000,
                source_ip=source_ip,
                delegation_depth=_delegation_depth,
                delegation_chain_dids=_delegation_chain_dids,
            )
            return JSONResponse(
                status_code=403,
                content=build_jsonrpc_error(
                    jsonrpc.id, -32003,
                    f"Scope denied: {scope_result.reason}",
                ),
            )

    # ── 5. Trust evaluation ──────────────────────────────────────────
    vp_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:16]
    trust_eval = trust_mod.evaluate(
        auth_result.agent_did or "",
        auth_result,
        tool_name=tool_name,
        vp_hash=vp_hash,
    )

    if trust_eval.decision == "block":
        trust_mod.update_from_request(auth_result.agent_did or "", tool_name, success=False)
        audit_mod.log_request(
            request_id, server_name, jsonrpc.method, tool_name,
            auth_result, trust_eval, scope_result, None, "blocked_trust",
            (time.monotonic() - start) * 1000,
            source_ip=source_ip,
            delegation_depth=_delegation_depth,
            delegation_chain_dids=_delegation_chain_dids,
        )
        return JSONResponse(
            status_code=403,
            content=build_jsonrpc_error(
                jsonrpc.id, -32004,
                f"Trust score too low ({trust_eval.score}): {trust_eval.explanation}",
            ),
            headers={"X-Pramana-Trust-Factors": json.dumps(trust_eval.factors)},
        )

    if trust_eval.decision == "step_up":
        trust_mod.update_from_request(auth_result.agent_did or "", tool_name, success=False)
        audit_mod.log_request(
            request_id, server_name, jsonrpc.method, tool_name,
            auth_result, trust_eval, scope_result, None, "step_up",
            (time.monotonic() - start) * 1000,
            source_ip=source_ip,
            delegation_depth=_delegation_depth,
            delegation_chain_dids=_delegation_chain_dids,
        )
        return JSONResponse(
            status_code=401,
            content=build_jsonrpc_error(
                jsonrpc.id, -32005, "Step-up authentication required",
            ),
            headers={
                "X-Pramana-StepUp": "re-present-vp",
                "X-Pramana-Trust-Factors": json.dumps(trust_eval.factors),
            },
        )

    # ── 6. Proxy to upstream ─────────────────────────────────────────
    proxy_result = await proxy_mod.forward(
        server_name,
        body,
        {
            "agent_did": auth_result.agent_did or "",
            "delegator_did": auth_result.delegator_did or "",
        },
    )

    # ── 7. Audit log ─────────────────────────────────────────────────
    total_ms = (time.monotonic() - start) * 1000
    audit_mod.log_request(
        request_id, server_name, jsonrpc.method, tool_name,
        auth_result, trust_eval, scope_result, proxy_result, "allowed",
        total_ms,
        source_ip=source_ip,
        delegation_depth=_delegation_depth,
        delegation_chain_dids=_delegation_chain_dids,
    )

    # ── 8. Update trust behavioural data ─────────────────────────────
    trust_mod.update_from_request(
        auth_result.agent_did or "",
        tool_name,
        proxy_result.status_code < 400,
    )

    return Response(
        content=proxy_result.body,
        status_code=proxy_result.status_code,
        media_type="application/json",
        headers={"X-Pramana-Trust-Factors": json.dumps(trust_eval.factors)},
    )


# ---------------------------------------------------------------------------
# Observability endpoints
# ---------------------------------------------------------------------------

@app.get("/gateway/health")
async def health(request: Request):
    """Health check — includes upstream connectivity and gateway DID."""
    proxy_mod: MCPProxy = request.app.state.proxy
    auth_mod: GatewayAuth = request.app.state.auth
    upstream_status = {}
    for name in request.app.state.config.upstream_servers:
        upstream_status[name] = await proxy_mod.health_check(name)
    return {
        "status": "healthy",
        "gateway_did": auth_mod.gateway_identity.did,
        "upstream": upstream_status,
    }


@app.get("/gateway/status")
async def status(request: Request):
    """Gateway status — cache size, upstream servers, recent events."""
    return {
        "recent_events": request.app.state.audit.get_recent_events(20),
        "trust_cache_size": len(request.app.state.trust._cache),
        "upstream_servers": list(request.app.state.config.upstream_servers.keys()),
    }


@app.get("/gateway/events")
async def events(
    request: Request,
    agent_did: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    n: int = 50,
):
    """Query audit events, optionally filtered by agent DID and/or time range.

    - agent_did: filter to events from this DID
    - from_ts: ISO 8601 UTC lower bound (inclusive), e.g. 2026-03-16T00:00:00+00:00
    - to_ts:   ISO 8601 UTC upper bound (inclusive)
    - n:       max results when no time-range is specified (ignored when from_ts/to_ts set)
    """
    audit_mod: GatewayAuditWriter = request.app.state.audit
    if from_ts or to_ts:
        return audit_mod.get_events_filtered(
            agent_did=agent_did, from_ts=from_ts, to_ts=to_ts
        )
    if agent_did:
        return audit_mod.get_events_for_agent(agent_did)
    return audit_mod.get_recent_events(n)


_CSV_COLUMNS = [
    "timestamp", "agent_did", "agent_name", "delegator_did",
    "delegator_name", "delegator_email", "delegator_org", "delegator_role",
    "trust_score", "trust_decision", "tool_name", "server_name",
    "decision", "auth_latency_ms", "proxy_latency_ms", "total_latency_ms",
    "source_ip", "request_id",
]


@app.get("/gateway/events/export")
async def events_export(
    request: Request,
    format: str = "json",
    agent_did: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
):
    """Export audit events as JSON or CSV for compliance / CISO queries.

    Query params:
    - format:    "json" (default) or "csv"
    - agent_did: filter to a specific agent DID
    - from_ts:   ISO 8601 UTC lower bound (inclusive)
    - to_ts:     ISO 8601 UTC upper bound (inclusive)

    Returns a downloadable file with Content-Disposition attachment header.
    """
    audit_mod: GatewayAuditWriter = request.app.state.audit
    raw_events = audit_mod.get_events_filtered(
        agent_did=agent_did, from_ts=from_ts, to_ts=to_ts
    )

    if format.lower() == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for e in raw_events:
            claims = e.get("delegator_claims") or {}
            row = {
                "timestamp": e.get("timestamp", ""),
                "agent_did": e.get("agent_did", ""),
                "agent_name": e.get("agent_name", ""),
                "delegator_did": e.get("delegator_did", ""),
                "delegator_name": claims.get("name", ""),
                "delegator_email": claims.get("email", ""),
                "delegator_org": claims.get("organization", ""),
                "delegator_role": claims.get("role", ""),
                "trust_score": e.get("trust_score", ""),
                "trust_decision": e.get("trust_decision", ""),
                "tool_name": e.get("tool_name", ""),
                "server_name": e.get("server_name", ""),
                "decision": e.get("decision", ""),
                "auth_latency_ms": e.get("auth_latency_ms", ""),
                "proxy_latency_ms": e.get("proxy_latency_ms", ""),
                "total_latency_ms": e.get("total_latency_ms", ""),
                "source_ip": e.get("source_ip", ""),
                "request_id": e.get("request_id", ""),
            }
            writer.writerow(row)
        csv_bytes = buf.getvalue().encode("utf-8")
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="pramana_audit_export.csv"'},
        )

    # JSON export
    json_bytes = json.dumps(raw_events, indent=2, default=str).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="pramana_audit_export.json"'},
    )


@app.get("/gateway/detections")
async def detections(request: Request):
    """Run detection scan and return alerts + fleet summary."""
    detection_mod: DetectionEngine = request.app.state.detection
    result = detection_mod.scan()
    return {
        "scanned_at": result.scanned_at,
        "alert_count": len(result.alerts),
        "alerts": [
            {
                "id": a.alert_id,
                "type": a.alert_type.value,
                "severity": a.severity.value,
                "title": a.title,
                "description": a.description,
                "agent_did": a.agent_did,
                "agent_name": a.agent_name,
                "source_ip": a.source_ip,
                "evidence": a.evidence,
                "action": a.recommended_action,
                "timestamp": a.timestamp,
            }
            for a in result.alerts
        ],
        "fleet": {
            "total_agents": result.fleet_summary.total_agents_seen,
            "verified": result.fleet_summary.verified_agents,
            "shadow_attempts": result.fleet_summary.shadow_attempts,
            "with_violations": result.fleet_summary.agents_with_violations,
            "with_penalties": result.fleet_summary.agents_with_penalties,
            "avg_trust": result.fleet_summary.avg_trust_score,
            "risk_distribution": result.fleet_summary.risk_distribution,
        },
        "inventory": result.inventory_stats,
    }


@app.get("/gateway/audit/verify")
async def audit_verify(request: Request):
    """
    Verify the integrity of the gateway's audit chain.

    Returns whether the SHA-256 hash chain is intact in PostgreSQL.
    When running in-memory mode (no DATABASE_URL), reports storage type.
    """
    audit_mod = request.app.state.audit
    if hasattr(audit_mod, "verify_chain"):
        result = audit_mod.verify_chain()
        result["in_memory_count"] = len(audit_mod._events)
        # Surface any PG write failures so silent write loss is observable.
        result["write_failures"] = getattr(audit_mod, "_write_failures", 0)
        return result
    # In-memory GatewayAuditWriter — no chain, but still useful info
    events = audit_mod.get_recent_events(10000)
    return {
        "valid": True,
        "events_checked": len(events),
        "first_broken_at": None,
        "reason": None,
        "storage": "in-memory",
        "note": "Set DATABASE_URL to enable PostgreSQL hash-chain verification",
        "in_memory_count": len(events),
    }


@app.get("/gateway/inventory")
async def inventory(request: Request):
    """Return known agent inventory and recent shadow attempts."""
    detection_mod: DetectionEngine = request.app.state.detection
    inv = detection_mod.inventory
    agents = inv.get_known_agents()
    shadows = inv.get_shadow_attempts(since_minutes=60)
    return {
        "known_agents": [
            {
                "did": a.agent_did,
                "name": a.agent_name,
                "delegator": a.delegator_did,
                "requests": a.request_count,
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
            }
            for a in agents
        ],
        "shadow_attempts": [
            {
                "source_ip": s.source_ip,
                "reason": s.reason,
                "timestamp": s.timestamp_iso,
                "server_name": s.server_name,
            }
            for s in shadows
        ],
    }
