from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from typing import Optional

from pydantic import BaseModel, Field

from api.middleware.authz import require_scopes
from core import did as did_core
from core.audit import write_audit
from core.crypto import encrypt_text
from core.db import db_session
from core.resolver import resolve_did
from core.settings import settings
from core.status_list import allocate_index, get_or_create_default_list, set_revoked
from core.status_list_vc import (
    is_local_status_list_url,
    issue_status_list_vc_jwt,
    status_list_id_from_url,
    verify_and_extract_encoded_list,
)
from core.tenancy import ensure_tenant
from core.vc import issue_vc_jwt, verify_vc_jwt
from core.demo_metrics import inc, timer
from models import Agent, Credential, Key

import httpx

router = APIRouter(prefix="/v1/workflows", tags=["workflows"])


class DriftDemoRequest(BaseModel):
    issuer_name: str = Field(default="walmart-procurement-agent", min_length=1, max_length=200)
    subject_name: str = Field(default="supplier-api-agent", min_length=1, max_length=200)
    subject_did_override: Optional[str] = None


class DriftDemoResponse(BaseModel):
    tenant_id: str
    issuer_agent_id: uuid.UUID
    issuer_did: str
    subject_agent_id: uuid.UUID
    subject_did: str
    credential_id: uuid.UUID
    vc_jwt: str
    status_list_id: uuid.UUID
    status_list_index: int
    status_list_url: str
    verify_before: dict
    revoke: dict
    verify_after: dict


def _create_agent(*, tenant_id: str, name: str) -> tuple[Agent, Key, dict]:
    agent_id = uuid.uuid4()
    did = did_core.create_did(agent_id)

    private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
    kid = f"{did}#key-1"

    agent = Agent(id=agent_id, name=name, did=did, tenant_id=tenant_id)
    key = Key(agent_id=agent_id, tenant_id=tenant_id, kid=kid, public_jwk=public_jwk, private_key_enc=encrypt_text(private_pem))

    with db_session() as db:
        ensure_tenant(db, tenant_id)
        db.add(agent)
        db.add(key)
        db.commit()
        db.refresh(agent)

    doc = did_core.build_did_document(did=did, kid=kid, public_jwk=public_jwk)
    return agent, key, doc


def _verify_with_status(token: str) -> dict:
    def status_check(status_list_cred_url: str, index: int) -> bool:
        if is_local_status_list_url(status_list_cred_url):
            sl_id = status_list_id_from_url(status_list_cred_url)
            status_jwt, _ = issue_status_list_vc_jwt(sl_id)
        else:
            r = httpx.get(status_list_cred_url, timeout=10.0)
            r.raise_for_status()
            data = r.json()
            status_jwt = data.get("jwt")
            if not isinstance(status_jwt, str):
                raise ValueError("status list response missing jwt")

        raw_bits, _ = verify_and_extract_encoded_list(status_jwt)

        if index < 0 or index >= (len(raw_bits) * 8):
            return False
        byte_i = index // 8
        bit_i = index % 8
        return (raw_bits[byte_i] & (1 << bit_i)) != 0

    result = verify_vc_jwt(token=token, resolve_did_document=resolve_did, status_check=status_check)

    if result["status"].get("present") and result["status"].get("revoked"):
        return {"verified": False, "reason": "revoked", **result}

    return {"verified": True, **result}


@router.post(
    "/drift-demo",
    response_model=DriftDemoResponse,
)
def drift_demo(
    req: DriftDemoRequest,
    request: Request,
    auth: dict = Depends(require_scopes(["agents:create", "credentials:issue", "credentials:revoke"])),
):
    if settings.demo_mode:
        inc("drift_demo_started_total", 1)

    try:
        tenant_id = auth.get("tenant_id", "default")

        with timer("drift_demo_latency_ms"):
            # Create issuer + subject agents
            issuer, issuer_key, _ = _create_agent(tenant_id=tenant_id, name=req.issuer_name)
            subject, _, _ = _create_agent(tenant_id=tenant_id, name=req.subject_name)

            subject_did = req.subject_did_override or subject.did

            # Issue VC
            sl = get_or_create_default_list(tenant_id=tenant_id)
            index = allocate_index(sl.id)
            status_list_url = f"{settings.tesht_scheme}://{did_core.domain_decoded()}/v1/status/{sl.id}"

            token, jti, iat, exp = issue_vc_jwt(
                issuer_agent_id=issuer.id,
                subject_did=subject_did,
                credential_type="CapabilityCredential",
                status_list_url=status_list_url,
                status_list_index=index,
                ttl_seconds=3600,
                extra_claims={"capability": "negotiate_contracts", "max_amount": 100000},
            )

            cred = Credential(
                tenant_id=tenant_id,
                issuer_agent_id=issuer.id,
                subject_did=subject_did,
                credential_type="CapabilityCredential",
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
                event_type="workflow.drift_demo.issued",
                actor=str(issuer.id),
                resource_type="credential",
                resource_id=str(cred.id),
                payload={"jti": jti, "subject": subject_did, "status_list_index": index},
            )

            verify_before = _verify_with_status(token)

            # Revoke
            set_revoked(cred.status_list_id, cred.status_list_index)
            revoke = {"revoked": True, "credential_id": str(cred.id)}

            write_audit(
                tenant_id=tenant_id,
                event_type="workflow.drift_demo.revoked",
                actor="workflow",
                resource_type="credential",
                resource_id=str(cred.id),
                payload={"status_list_id": str(cred.status_list_id), "status_list_index": cred.status_list_index},
            )

            verify_after = _verify_with_status(token)

        if settings.demo_mode:
            inc("drift_demo_success_total", 1)

        return DriftDemoResponse(
            tenant_id=tenant_id,
            issuer_agent_id=issuer.id,
            issuer_did=issuer.did,
            subject_agent_id=subject.id,
            subject_did=subject_did,
            credential_id=cred.id,
            vc_jwt=token,
            status_list_id=sl.id,
            status_list_index=index,
            status_list_url=status_list_url,
            verify_before=verify_before,
            revoke=revoke,
            verify_after=verify_after,
        )
    except Exception:
        if settings.demo_mode:
            inc("drift_demo_error_total", 1)
        raise

