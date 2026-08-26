from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware.authz import require_scopes
from core import did as did_core
from core.audit import write_audit
from core.crypto import encrypt_text
from core.db import db_session
from core.resolver import resolve_did
from core.settings import settings
from core.status_list import allocate_index, get_or_create_default_list
from core.status_list_vc import (
    is_local_status_list_url,
    issue_status_list_vc_jwt,
    status_list_id_from_url,
    verify_and_extract_encoded_list,
)
from core.tenancy import ensure_tenant
from core.vc import issue_vc_jwt, verify_vc_jwt
from models import Agent, Credential, Key, RequirementIntent

import httpx

router = APIRouter(prefix="/v1/requirement_intents", tags=["requirement_intents"])


def _hash_payload(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _idempotency_key(request: Request) -> Optional[str]:
    k = request.headers.get("idempotency-key") or request.headers.get("Idempotency-Key")
    if isinstance(k, str) and k.strip():
        return k.strip()[:200]
    return None


class Requirement(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    type: str = Field(default="CapabilityCredential", min_length=1, max_length=200)
    claims: dict[str, Any] = Field(default_factory=dict)


class CreateRequirementIntentRequest(BaseModel):
    issuer_name: str = Field(default="issuer-agent", min_length=1, max_length=200)
    subject_name: str = Field(default="subject-agent", min_length=1, max_length=200)
    subject_did: Optional[str] = None
    requirements: list[Requirement] = Field(default_factory=list, min_length=1, max_length=25)
    options: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequirementIntentResponse(BaseModel):
    id: uuid.UUID
    status: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime
    decision: dict[str, Any]
    proof_bundle: dict[str, Any]


@router.post("", response_model=RequirementIntentResponse)
def create_intent(
    req: CreateRequirementIntentRequest,
    request: Request,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
):
    tenant_id = auth.get("tenant_id", "default")
    idem = _idempotency_key(request)
    req_hash = _hash_payload({"tenant_id": tenant_id, "body": req.model_dump()})

    with db_session() as db:
        ensure_tenant(db, tenant_id)

        if idem:
            existing = (
                db.query(RequirementIntent)
                .filter(RequirementIntent.tenant_id == tenant_id)
                .filter(RequirementIntent.idempotency_key == idem)
                .one_or_none()
            )
            if existing is not None:
                # Key reuse with different payload is an error (Stripe-like).
                if existing.request_hash and existing.request_hash != req_hash:
                    raise HTTPException(status_code=409, detail="Idempotency-Key reuse with different request")
                return RequirementIntentResponse(
                    id=existing.id,
                    status=existing.status,
                    tenant_id=existing.tenant_id,
                    created_at=existing.created_at,
                    updated_at=existing.updated_at,
                    decision=existing.decision or {},
                    proof_bundle=existing.proof_bundle or {},
                )

        intent = RequirementIntent(
            tenant_id=tenant_id,
            status="requires_confirmation",
            subject_did=req.subject_did,
            issuer_name=req.issuer_name,
            subject_name=req.subject_name,
            requirements={"items": [r.model_dump() for r in req.requirements]},
            options=req.options or {},
            metadata_json=req.metadata or {},
            idempotency_key=idem,
            request_hash=req_hash,
            decision={},
            proof_bundle={},
            updated_at=datetime.utcnow(),
        )
        db.add(intent)
        db.commit()
        db.refresh(intent)

    write_audit(
        tenant_id=tenant_id,
        event_type="requirement_intent.created",
        actor="api",
        resource_type="requirement_intent",
        resource_id=str(intent.id),
        payload={"status": intent.status, "requirements_count": len(req.requirements)},
    )

    return RequirementIntentResponse(
        id=intent.id,
        status=intent.status,
        tenant_id=intent.tenant_id,
        created_at=intent.created_at,
        updated_at=intent.updated_at,
        decision=intent.decision or {},
        proof_bundle=intent.proof_bundle or {},
    )


def _create_agent(*, tenant_id: str, name: str) -> tuple[Agent, Key]:
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
        db.refresh(key)
    return agent, key


def _verify_with_status(token: str) -> dict[str, Any]:
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


class ConfirmRequirementIntentRequest(BaseModel):
    return_mode: str = Field(default="both", pattern="^(decision|bundle|both)$")
    ttl_seconds: int = Field(default=3600, ge=60, le=60 * 60 * 24 * 365)


@router.post("/{intent_id}/confirm", response_model=RequirementIntentResponse)
def confirm_intent(
    intent_id: uuid.UUID,
    req: ConfirmRequirementIntentRequest,
    request: Request,
    auth: dict = Depends(require_scopes(["credentials:issue", "credentials:revoke"])),
):
    tenant_id = auth.get("tenant_id", "default")
    idem = _idempotency_key(request)
    req_hash = _hash_payload({"tenant_id": tenant_id, "body": req.model_dump(), "intent_id": str(intent_id)})

    # Extract fields we need before the session is closed (SQLAlchemy expires on commit).
    issuer_name: str
    subject_name: str
    subject_did: Optional[str]
    items: list[dict[str, Any]]

    with db_session() as db:
        intent = (
            db.query(RequirementIntent)
            .filter(RequirementIntent.id == intent_id)
            .filter(RequirementIntent.tenant_id == tenant_id)
            .one_or_none()
        )
        if intent is None:
            raise HTTPException(status_code=404, detail="RequirementIntent not found")

        if idem and intent.confirm_idempotency_key == idem:
            if intent.confirm_request_hash and intent.confirm_request_hash != req_hash:
                raise HTTPException(status_code=409, detail="Idempotency-Key reuse with different request")
            return RequirementIntentResponse(
                id=intent.id,
                status=intent.status,
                tenant_id=intent.tenant_id,
                created_at=intent.created_at,
                updated_at=intent.updated_at,
                decision=intent.decision or {},
                proof_bundle=intent.proof_bundle or {},
            )

        issuer_name = intent.issuer_name or "issuer-agent"
        subject_name = intent.subject_name or "subject-agent"
        subject_did = intent.subject_did
        raw_items = (intent.requirements or {}).get("items") or []
        items = [x for x in raw_items if isinstance(x, dict)]

        # Mark processing
        intent.status = "processing"
        intent.confirm_idempotency_key = idem
        intent.confirm_request_hash = req_hash
        intent.updated_at = datetime.utcnow()
        db.add(intent)
        db.commit()

    # Build fresh issuer + subject (demo-friendly)
    issuer, _issuer_key = _create_agent(tenant_id=tenant_id, name=issuer_name)
    subject, _subject_key = _create_agent(tenant_id=tenant_id, name=subject_name)
    subject_did = subject_did or subject.did

    # For v0: issue one VC per requirement
    issued: list[dict[str, Any]] = []
    per_req: list[dict[str, Any]] = []
    for r in items:
        r_id = r.get("id") or "req"
        r_claims = r.get("claims") if isinstance(r.get("claims"), dict) else {}

        sl = get_or_create_default_list(tenant_id=tenant_id)
        index = allocate_index(sl.id)
        status_list_url = f"{settings.tesht_scheme}://{did_core.domain_decoded()}/v1/status/{sl.id}"

        token, jti, iat, exp = issue_vc_jwt(
            issuer_agent_id=issuer.id,
            subject_did=subject_did,
            credential_type="CapabilityCredential",
            status_list_url=status_list_url,
            status_list_index=index,
            ttl_seconds=req.ttl_seconds,
            extra_claims=r_claims,
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

        verify = _verify_with_status(token)

        issued.append(
            {
                "requirement_id": r_id,
                "credential_id": str(cred.id),
                "vc_jwt": token,
                "status_list_url": status_list_url,
                "status_list_id": str(sl.id),
                "status_list_index": index,
                "verify": verify,
            }
        )
        per_req.append({"id": r_id, "satisfied": bool(verify.get("verified")), "reason": verify.get("reason")})

    decision = {
        "status": "satisfied" if all(x["satisfied"] for x in per_req) else "not_satisfied",
        "requirements": per_req,
    }
    proof_bundle = {"issuer_did": issuer.did, "subject_did": subject_did, "credentials": issued}

    # Persist
    with db_session() as db:
        intent = (
            db.query(RequirementIntent)
            .filter(RequirementIntent.id == intent_id)
            .filter(RequirementIntent.tenant_id == tenant_id)
            .one()
        )
        intent.status = "succeeded" if decision["status"] == "satisfied" else "failed"
        intent.decision = decision if req.return_mode in {"decision", "both"} else {}
        intent.proof_bundle = proof_bundle if req.return_mode in {"bundle", "both"} else {}
        intent.updated_at = datetime.utcnow()
        db.add(intent)
        db.commit()
        db.refresh(intent)

    write_audit(
        tenant_id=tenant_id,
        event_type="requirement_intent.confirmed",
        actor="api",
        resource_type="requirement_intent",
        resource_id=str(intent.id),
        payload={"status": intent.status, "return_mode": req.return_mode},
    )

    return RequirementIntentResponse(
        id=intent.id,
        status=intent.status,
        tenant_id=intent.tenant_id,
        created_at=intent.created_at,
        updated_at=intent.updated_at,
        decision=intent.decision or {},
        proof_bundle=intent.proof_bundle or {},
    )


@router.get("/{intent_id}", response_model=RequirementIntentResponse)
def get_intent(intent_id: uuid.UUID, auth: dict = Depends(require_scopes(["credentials:issue"]))):
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        intent = (
            db.query(RequirementIntent)
            .filter(RequirementIntent.id == intent_id)
            .filter(RequirementIntent.tenant_id == tenant_id)
            .one_or_none()
        )
        if intent is None:
            raise HTTPException(status_code=404, detail="RequirementIntent not found")

        return RequirementIntentResponse(
            id=intent.id,
            status=intent.status,
            tenant_id=intent.tenant_id,
            created_at=intent.created_at,
            updated_at=intent.updated_at,
            decision=intent.decision or {},
            proof_bundle=intent.proof_bundle or {},
        )


@router.post("/{intent_id}/cancel", response_model=RequirementIntentResponse)
def cancel_intent(intent_id: uuid.UUID, auth: dict = Depends(require_scopes(["credentials:issue"]))):
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        intent = (
            db.query(RequirementIntent)
            .filter(RequirementIntent.id == intent_id)
            .filter(RequirementIntent.tenant_id == tenant_id)
            .one_or_none()
        )
        if intent is None:
            raise HTTPException(status_code=404, detail="RequirementIntent not found")
        if intent.status in {"succeeded", "failed", "canceled"}:
            # no-op
            pass
        else:
            intent.status = "canceled"
            intent.updated_at = datetime.utcnow()
            db.add(intent)
            db.commit()
            db.refresh(intent)

    return RequirementIntentResponse(
        id=intent.id,
        status=intent.status,
        tenant_id=intent.tenant_id,
        created_at=intent.created_at,
        updated_at=intent.updated_at,
        decision=intent.decision or {},
        proof_bundle=intent.proof_bundle or {},
    )


