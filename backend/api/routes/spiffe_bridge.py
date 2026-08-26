"""SPIFFE Identity Bridge — turns infrastructure identity into application authority.

This module implements the SPIFFE-to-VC bridge:

    SPIFFE SVID (JWT) → Tesht-issued VC with application-layer authority

Workflow:
    1. Client presents a SPIFFE SVID (JWT format).
    2. Bridge verifies the SVID signature against a trust bundle (or demo key).
    3. Bridge creates or links a Tesht Agent with the SPIFFE ID stored.
    4. Bridge issues a W3C VC attesting the workload identity.
    5. Agent can now use the VC for delegation/commerce flows.

Endpoints:
    POST /v1/identity/attest     — SVID → VC
    GET  /v1/identity/{did}/spiffe — Return SPIFFE binding for an agent DID
    GET  /v1/identity/spiffe/{spiffe_id} — Return Tesht agent for a SPIFFE ID
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, Field

from api.middleware.authz import require_scopes
from core import did as did_core
from core.audit import write_audit
from core.crypto import encrypt_text
from core.db import db_session
from core.did import is_spiffe_id, parse_spiffe_id
from core.settings import settings
from core.status_list import allocate_index, get_or_create_default_list
from core.tenancy import ensure_tenant
from core.vc import issue_vc_jwt
from models import Agent, Key

router = APIRouter(prefix="/v1/identity", tags=["identity-bridge"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AttestRequest(BaseModel):
    """Attest a workload identity using a SPIFFE SVID JWT."""
    svid_jwt: str = Field(min_length=10, description="SPIFFE SVID in JWT format")
    trust_bundle_jwk: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "JWK of the SPIRE trust bundle public key. "
            "If omitted in demo mode, signature verification is relaxed "
            "and the SPIFFE ID is trusted on presentation."
        ),
    )
    agent_name: Optional[str] = Field(
        default=None,
        description="Human-readable name for the agent. Defaults to workload path.",
    )
    initial_scope: Optional[dict[str, Any]] = Field(
        default=None,
        description="Initial delegation scope to embed in the issued VC.",
    )


class AttestResponse(BaseModel):
    attested: bool
    spiffe_id: str
    agent_did: str
    vc_jwt: str
    vc_id: str
    trust_domain: str
    workload_path: str
    agent_created: bool   # True if new agent, False if existing


class SpiffeBindingResponse(BaseModel):
    agent_did: str
    spiffe_id: Optional[str]
    trust_domain: Optional[str]
    workload_path: Optional[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_svid_unverified(svid_jwt: str) -> dict[str, Any]:
    """Decode SVID JWT without signature check to extract claims."""
    try:
        return pyjwt.decode(svid_jwt, options={"verify_signature": False})
    except Exception as exc:
        raise ValueError(f"Malformed SVID JWT: {exc}") from exc


def _verify_svid(svid_jwt: str, trust_bundle_jwk: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Verify SVID JWT signature. In demo mode without a trust bundle, accept unverified."""
    claims = _decode_svid_unverified(svid_jwt)

    if trust_bundle_jwk:
        # Full verification against provided trust bundle key
        from core.vc import _public_key_from_jwk_multi
        header = pyjwt.get_unverified_header(svid_jwt)
        alg = header.get("alg", "RS256")
        try:
            pub = _public_key_from_jwk_multi(trust_bundle_jwk)
            claims = pyjwt.decode(svid_jwt, key=pub, algorithms=[alg])
        except Exception as exc:
            raise ValueError(f"SVID signature verification failed: {exc}") from exc
    elif not settings.demo_mode:
        # In production, trust bundle is mandatory
        raise ValueError(
            "trust_bundle_jwk is required in non-demo mode. "
            "Provide the SPIRE trust bundle public key."
        )
    # In demo mode without a trust bundle: accept the SPIFFE ID on presentation
    # (for local development and demo purposes only).

    return claims


def _get_or_create_agent(
    tenant_id: str,
    spiffe_id: str,
    agent_name: str,
) -> tuple[Agent, Key, bool]:
    """Return (agent, key, was_created). Idempotent — returns existing agent if SPIFFE ID already registered.

    The spiffe_id column has a GLOBAL unique constraint across all tenants.
    We search globally first, then try to create. On IntegrityError we re-fetch
    the globally-existing record (handles concurrent requests gracefully).
    """
    # 1. Check globally — spiffe_id unique constraint spans ALL tenants
    with db_session() as db:
        existing = db.query(Agent).filter(
            Agent.spiffe_id == spiffe_id,
        ).one_or_none()
        if existing:
            key = db.query(Key).filter(
                Key.agent_id == existing.id
            ).order_by(Key.created_at.desc()).first()
            if key:
                db.expunge(existing)
                db.expunge(key)
                return existing, key, False
            # Agent exists but has no key (e.g. seeded without one)
            existing_id = existing.id
            existing_did = existing.did
            existing_tenant = existing.tenant_id
            db.expunge(existing)
        else:
            existing_id = None
            existing_did = None
            existing_tenant = None

    if existing_id is not None:
        # Agent exists but has no key — generate and attach one
        private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
        kid = f"{existing_did}#key-1"
        new_key = Key(
            agent_id=existing_id,
            tenant_id=existing_tenant,
            kid=kid,
            public_jwk=public_jwk,
            private_key_enc=encrypt_text(private_pem),
        )
        with db_session() as db:
            db.add(new_key)
            db.commit()
            db.refresh(new_key)
        with db_session() as db:
            agent = db.query(Agent).filter(Agent.id == existing_id).one()
            db.expunge(agent)
        return agent, new_key, False

    # 2. Create brand-new agent with Ed25519 keypair
    agent_id = uuid.uuid4()
    new_did = did_core.create_did(agent_id)
    private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
    kid = f"{new_did}#key-1"

    agent = Agent(
        id=agent_id,
        name=agent_name,
        did=new_did,
        tenant_id=tenant_id,
        spiffe_id=spiffe_id,
    )
    key = Key(
        agent_id=agent_id,
        tenant_id=tenant_id,
        kid=kid,
        public_jwk=public_jwk,
        private_key_enc=encrypt_text(private_pem),
    )
    try:
        with db_session() as db:
            ensure_tenant(db, tenant_id)
            db.add(agent)
            db.add(key)
            db.commit()
            db.refresh(agent)
            db.refresh(key)
        return agent, key, True
    except IntegrityError:
        # Lost race to another concurrent request — fetch the winner
        with db_session() as db:
            existing = db.query(Agent).filter(Agent.spiffe_id == spiffe_id).one()
            key = db.query(Key).filter(
                Key.agent_id == existing.id
            ).order_by(Key.created_at.desc()).first()
            if key:
                db.expunge(existing)
                db.expunge(key)
                return existing, key, False
            db.expunge(existing)
        raise RuntimeError(f"SPIFFE agent exists but has no signing key: {spiffe_id}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/attest", response_model=AttestResponse)
def attest_workload(
    req: AttestRequest,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> AttestResponse:
    """Bridge endpoint: verify a SPIFFE SVID and issue a Tesht W3C VC.

    The agent receives a VC attesting its workload identity, which it can
    then use for delegation and commerce flows with Tesht's authorization layer.

    This is the key bridge: SPIFFE proves who the agent is → Tesht proves
    what it is allowed to do.
    """
    tenant_id = auth.get("tenant_id", "default")

    # 1. Decode and verify the SVID
    try:
        svid_claims = _verify_svid(req.svid_jwt, req.trust_bundle_jwk)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # 2. Extract SPIFFE ID from sub claim
    spiffe_id = svid_claims.get("sub") or svid_claims.get("spiffe_id", "")
    if not spiffe_id or not is_spiffe_id(spiffe_id):
        raise HTTPException(
            status_code=422,
            detail=f"SVID sub claim is not a valid SPIFFE ID: {spiffe_id!r}",
        )

    # 3. Parse trust domain and workload path
    try:
        trust_domain, workload_path = parse_spiffe_id(spiffe_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # 4. Get or create Tesht agent
    agent_name = req.agent_name or f"workload{workload_path.replace('/', '-')}"
    try:
        agent, key, was_created = _get_or_create_agent(tenant_id, spiffe_id, agent_name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Agent creation failed: {exc}")

    # 5. Issue a W3C VC attesting the workload identity
    sl = get_or_create_default_list(tenant_id=tenant_id)
    index = allocate_index(sl.id)
    status_list_url = (
        f"{settings.tesht_scheme}://{did_core.domain_decoded()}/v1/status/{sl.id}"
    )

    scope = req.initial_scope or {}
    extra_claims: dict[str, Any] = {
        "spiffeId": spiffe_id,
        "trustDomain": trust_domain,
        "workloadPath": workload_path,
        "attestedAt": datetime.utcnow().isoformat() + "Z",
        "attestationMethod": "spiffe-svid-jwt",
    }
    if scope:
        extra_claims["delegationScope"] = scope

    vc_jwt, jti, _, _ = issue_vc_jwt(
        issuer_agent_id=agent.id,
        subject_did=agent.did,
        credential_type="WorkloadAttestationCredential",
        status_list_url=status_list_url,
        status_list_index=index,
        ttl_seconds=3600,  # 1-hour attestation VC
        extra_claims=extra_claims,
    )

    write_audit(
        tenant_id=tenant_id,
        event_type="identity.workload.attested",
        actor="spiffe-bridge",
        resource_type="agent",
        resource_id=str(agent.id),
        payload={
            "spiffe_id": spiffe_id,
            "trust_domain": trust_domain,
            "workload_path": workload_path,
            "agent_did": agent.did,
            "agent_created": was_created,
            "vc_id": jti,
        },
    )

    return AttestResponse(
        attested=True,
        spiffe_id=spiffe_id,
        agent_did=agent.did,
        vc_jwt=vc_jwt,
        vc_id=jti,
        trust_domain=trust_domain,
        workload_path=workload_path,
        agent_created=was_created,
    )


@router.get("/{did}/spiffe", response_model=SpiffeBindingResponse)
def get_spiffe_binding(
    did: str,
    auth: dict = Depends(require_scopes(["credentials:verify"])),
) -> SpiffeBindingResponse:
    """Return the SPIFFE binding for a Tesht agent DID."""
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        agent = db.query(Agent).filter(
            Agent.did == did,
            Agent.tenant_id == tenant_id,
        ).one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail=f"Agent DID not found: {did!r}")

        spiffe_id = agent.spiffe_id

    trust_domain = workload_path = None
    if spiffe_id:
        try:
            trust_domain, workload_path = parse_spiffe_id(spiffe_id)
        except ValueError:
            pass

    return SpiffeBindingResponse(
        agent_did=did,
        spiffe_id=spiffe_id,
        trust_domain=trust_domain,
        workload_path=workload_path,
    )


@router.get("/spiffe/{spiffe_id:path}", response_model=SpiffeBindingResponse)
def get_agent_by_spiffe(
    spiffe_id: str,
    auth: dict = Depends(require_scopes(["credentials:verify"])),
) -> SpiffeBindingResponse:
    """Return the Tesht agent registered for a given SPIFFE ID."""
    tenant_id = auth.get("tenant_id", "default")
    # Reconstruct the full spiffe:// URI from path parameter
    full_spiffe = f"spiffe://{spiffe_id}"

    with db_session() as db:
        agent = db.query(Agent).filter(
            Agent.spiffe_id == full_spiffe,
            Agent.tenant_id == tenant_id,
        ).one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail=f"No agent registered for SPIFFE ID: {full_spiffe!r}")

    try:
        trust_domain, workload_path = parse_spiffe_id(full_spiffe)
    except ValueError:
        trust_domain = workload_path = None

    return SpiffeBindingResponse(
        agent_did=agent.did,
        spiffe_id=full_spiffe,
        trust_domain=trust_domain,
        workload_path=workload_path,
    )
