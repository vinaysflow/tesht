from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from api.middleware.authz import require_scopes
from core import did as did_core
from core.audit import write_audit
from core.crypto import encrypt_text
from core.db import db_session
from core.jti_dedup import check_and_record_jti
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
from models import Agent, Credential, Key, MandateSpend

import httpx

router = APIRouter(prefix="/v1/commerce", tags=["commerce"])


# ---------------------------------------------------------------------------
# Internal helpers (mirroring requirement_intents.py pattern)
# ---------------------------------------------------------------------------

def _create_agent(*, tenant_id: str, name: str) -> tuple[Agent, Key]:
    agent_id = uuid.uuid4()
    did = did_core.create_did(agent_id)
    private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
    kid = f"{did}#key-1"
    agent = Agent(id=agent_id, name=name, did=did, tenant_id=tenant_id)
    key = Key(
        agent_id=agent_id,
        tenant_id=tenant_id,
        kid=kid,
        public_jwk=public_jwk,
        private_key_enc=encrypt_text(private_pem),
    )
    with db_session() as db:
        ensure_tenant(db, tenant_id)
        db.add(agent)
        db.add(key)
        db.commit()
        db.refresh(agent)
        db.refresh(key)
    return agent, key


def _verify_with_status(token: str) -> dict[str, Any]:
    """Verify a VC-JWT and check revocation status."""
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


def _issue_mandate(
    *,
    tenant_id: str,
    agent_did: str,
    credential_type: str,
    extra_claims: dict[str, Any],
    ttl_seconds: int,
) -> tuple[str, str, str, Optional[int]]:
    """
    Create a server-side issuer agent, issue a mandate VC-JWT, store the
    credential record.  Returns (mandate_jwt, mandate_id, issuer_did, expires_at_epoch).
    """
    issuer, _ = _create_agent(tenant_id=tenant_id, name=f"commerce-issuer-{credential_type.lower()}")

    sl = get_or_create_default_list(tenant_id=tenant_id)
    index = allocate_index(sl.id)
    status_list_url = (
        f"{settings.tesht_scheme}://{did_core.domain_decoded()}/v1/status/{sl.id}"
    )

    token, jti, iat, exp = issue_vc_jwt(
        issuer_agent_id=issuer.id,
        subject_did=agent_did,
        credential_type=credential_type,
        status_list_url=status_list_url,
        status_list_index=index,
        ttl_seconds=ttl_seconds,
        extra_claims=extra_claims,
    )

    cred = Credential(
        tenant_id=tenant_id,
        issuer_agent_id=issuer.id,
        subject_did=agent_did,
        credential_type=credential_type,
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

    return token, jti, issuer.did, exp


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class IntentMandateRequest(BaseModel):
    issuer_agent_id: Optional[str] = None      # ignored; server creates ephemeral issuer
    agent_did: str = Field(min_length=4)
    intent: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class CartMandateRequest(BaseModel):
    issuer_agent_id: Optional[str] = None
    agent_did: str = Field(min_length=4)
    cart: dict[str, Any] = Field(default_factory=dict)
    intent_mandate_jwt: str = Field(min_length=10)
    ttl_seconds: int = Field(default=300, ge=60, le=3600)


class MandateResponse(BaseModel):
    mandate_jwt: str
    mandate_id: str
    issuer_did: str
    expires_at: Optional[int]      # unix timestamp, or null if no expiry


class VerifyMandateRequest(BaseModel):
    jwt: str = Field(min_length=10)
    mandate_type: Optional[str] = None


class MandateVerificationResponse(BaseModel):
    verified: bool
    mandate_type: str
    mandate_id: str
    delegator_did: str
    agent_did: str
    scope: dict[str, Any]
    reason: Optional[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/mandates/intent", response_model=MandateResponse)
def create_intent_mandate(
    req: IntentMandateRequest,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> MandateResponse:
    """Issue an AP2IntentMandate VC-JWT."""
    tenant_id = auth.get("tenant_id", "default")

    # Basic validation before hitting the DB
    intent = req.intent
    max_amount = intent.get("max_amount")
    if not isinstance(max_amount, int) or max_amount <= 0:
        raise HTTPException(status_code=422, detail="intent.max_amount must be a positive integer")
    currency = intent.get("currency", "")
    if len(str(currency)) != 3 or not str(currency).isalpha() or not str(currency).isupper():
        raise HTTPException(status_code=422, detail="intent.currency must be a 3-letter ISO 4217 code")

    mandate_id = intent.get("mandate_id") or str(uuid.uuid4())
    extra_claims: dict[str, Any] = {
        "mandateId": mandate_id,
        "mandateType": "AP2IntentMandate",
        "max_amount": max_amount,
        "currency": currency,
    }
    for opt in ("description", "merchants", "categories",
                "requires_refundability", "user_cart_confirmation_required", "intent_expiry"):
        if opt in intent:
            extra_claims[opt] = intent[opt]

    try:
        token, jti, issuer_did, exp = _issue_mandate(
            tenant_id=tenant_id,
            agent_did=req.agent_did,
            credential_type="AP2IntentMandate",
            extra_claims=extra_claims,
            ttl_seconds=req.ttl_seconds,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    write_audit(
        tenant_id=tenant_id,
        event_type="commerce.mandate.intent.created",
        actor="api",
        resource_type="mandate",
        resource_id=jti,
        payload={"mandate_type": "AP2IntentMandate", "agent_did": req.agent_did},
    )

    return MandateResponse(
        mandate_jwt=token,
        mandate_id=jti,
        issuer_did=issuer_did,
        expires_at=exp,
    )


@router.post("/mandates/cart", response_model=MandateResponse)
def create_cart_mandate(
    req: CartMandateRequest,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> MandateResponse:
    """Issue an AP2CartMandate VC-JWT referencing a parent intent mandate."""
    tenant_id = auth.get("tenant_id", "default")

    # Verify parent intent mandate (signature + structure)
    try:
        intent_verify = _verify_with_status(req.intent_mandate_jwt)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid intent mandate: {exc}") from exc

    if not intent_verify.get("verified"):
        raise HTTPException(
            status_code=422,
            detail=f"Intent mandate verification failed: {intent_verify.get('reason')}",
        )

    # Extract intent constraints
    intent_payload = intent_verify.get("payload") or {}
    intent_cs = (intent_payload.get("vc") or {}).get("credentialSubject") or {}
    intent_max_amount = intent_cs.get("max_amount", 0)

    cart = req.cart
    total = cart.get("total") or {}
    cart_value = total.get("value", 0)
    cart_currency = total.get("currency", "")
    if not isinstance(cart_value, int) or cart_value < 0:
        raise HTTPException(status_code=422, detail="cart.total.value must be a non-negative integer")
    if cart_value > intent_max_amount:
        raise HTTPException(
            status_code=422,
            detail=f"Cart total {cart_value} exceeds intent limit {intent_max_amount}",
        )

    # Currency must match between cart and intent
    intent_currency = intent_cs.get("currency", "")
    if intent_currency and cart_currency and cart_currency != intent_currency:
        raise HTTPException(
            status_code=422,
            detail=f"Cart currency '{cart_currency}' does not match intent currency '{intent_currency}'",
        )

    mandate_id = cart.get("mandate_id") or str(uuid.uuid4())
    extra_claims: dict[str, Any] = {
        "mandateId": mandate_id,
        "mandateType": "AP2CartMandate",
        "parentIntentMandate": req.intent_mandate_jwt,
        "total": total,
    }
    for opt in ("items", "merchant_did", "shipping_address_hash", "payment_method_type"):
        if opt in cart:
            extra_claims[opt] = cart[opt]

    try:
        token, jti, issuer_did, exp = _issue_mandate(
            tenant_id=tenant_id,
            agent_did=req.agent_did,
            credential_type="AP2CartMandate",
            extra_claims=extra_claims,
            ttl_seconds=req.ttl_seconds,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    write_audit(
        tenant_id=tenant_id,
        event_type="commerce.mandate.cart.created",
        actor="api",
        resource_type="mandate",
        resource_id=jti,
        payload={"mandate_type": "AP2CartMandate", "agent_did": req.agent_did, "cart_value": cart_value},
    )

    return MandateResponse(
        mandate_jwt=token,
        mandate_id=jti,
        issuer_did=issuer_did,
        expires_at=exp,
    )


@router.post("/mandates/verify", response_model=MandateVerificationResponse)
def verify_mandate_endpoint(
    req: VerifyMandateRequest,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
) -> MandateVerificationResponse:
    """Verify an AP2 mandate VC-JWT."""
    try:
        result = _verify_with_status(req.jwt)
    except Exception as exc:
        return MandateVerificationResponse(
            verified=False,
            mandate_type="",
            mandate_id="",
            delegator_did="",
            agent_did="",
            scope={},
            reason=str(exc),
        )

    if not result.get("verified"):
        return MandateVerificationResponse(
            verified=False,
            mandate_type="",
            mandate_id="",
            delegator_did="",
            agent_did="",
            scope={},
            reason=result.get("reason", "Verification failed"),
        )

    payload = result.get("payload") or {}

    # JTI deduplication for mandate verification (separate from cart single-use logic)
    jti = str(payload.get("jti", ""))
    exp = payload.get("exp")
    dedup_err = check_and_record_jti(jti, endpoint="commerce/mandates/verify", exp=exp)
    if dedup_err:
        return MandateVerificationResponse(
            verified=False,
            mandate_type="",
            mandate_id=jti,
            delegator_did="",
            agent_did="",
            scope={},
            reason=dedup_err,
        )
    vc = payload.get("vc") or {}
    cs = vc.get("credentialSubject") or {}
    types = vc.get("type") or []
    actual_type = types[1] if len(types) > 1 else ""

    if req.mandate_type and actual_type != req.mandate_type:
        return MandateVerificationResponse(
            verified=False,
            mandate_type=actual_type,
            mandate_id=cs.get("mandateId", payload.get("jti", "")),
            delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
            agent_did=payload.get("sub", ""),
            scope={},
            reason=f"Mandate type mismatch: expected '{req.mandate_type}', got '{actual_type}'",
        )

    scope: dict[str, Any] = {}
    for field_name in ("max_amount", "currency", "merchants", "categories"):
        if field_name in cs:
            scope[field_name] = cs[field_name]

    # For cart mandates: verify parent intent, enforce cumulative budget, record spend
    if actual_type == "AP2CartMandate":
        cart_jti = payload.get("jti", "")
        tenant_id = auth.get("tenant_id", "default")
        cart_total_dict = cs.get("total", {})
        cart_value = cart_total_dict.get("value", 0) if isinstance(cart_total_dict, dict) else 0
        cart_currency = cart_total_dict.get("currency", "") if isinstance(cart_total_dict, dict) else ""

        # Extract intent JTI from nested JWT for cumulative budget tracking
        raw_intent_mandate = cs.get("parentIntentMandate", "")
        intent_jti: str = ""
        if raw_intent_mandate and "." in raw_intent_mandate:
            try:
                import base64 as _b64
                import json as _json
                _parts = raw_intent_mandate.split(".")
                _padded = _parts[1] + "=" * ((4 - len(_parts[1]) % 4) % 4)
                intent_jti = _json.loads(_b64.urlsafe_b64decode(_padded)).get("jti", "")
            except Exception:
                pass

        parent_jwt = raw_intent_mandate or None
        intent_max = 0

        if parent_jwt:
            try:
                parent_result = _verify_with_status(parent_jwt)
                if not parent_result.get("verified"):
                    return MandateVerificationResponse(
                        verified=False,
                        mandate_type=actual_type,
                        mandate_id=cs.get("mandateId", payload.get("jti", "")),
                        delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
                        agent_did=payload.get("sub", ""),
                        scope=scope,
                        reason=f"Parent intent mandate invalid: {parent_result.get('reason')}",
                    )
                parent_cs = (
                    (parent_result.get("payload") or {}).get("vc") or {}
                ).get("credentialSubject") or {}
                intent_max = parent_cs.get("max_amount", 0)
                if cart_value > intent_max:
                    return MandateVerificationResponse(
                        verified=False,
                        mandate_type=actual_type,
                        mandate_id=cs.get("mandateId", payload.get("jti", "")),
                        delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
                        agent_did=payload.get("sub", ""),
                        scope=scope,
                        reason=f"Cart total {cart_value} exceeds intent limit {intent_max}",
                    )
                # Inherit parent scope fields
                for field_name in ("max_amount", "currency", "merchants", "categories"):
                    if field_name in parent_cs and field_name not in scope:
                        scope[field_name] = parent_cs[field_name]
            except Exception as exc:
                return MandateVerificationResponse(
                    verified=False,
                    mandate_type=actual_type,
                    mandate_id=cs.get("mandateId", payload.get("jti", "")),
                    delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
                    agent_did=payload.get("sub", ""),
                    scope=scope,
                    reason=f"Parent intent mandate check failed: {exc}",
                )

        # Atomically: check single-use, enforce cumulative budget, record spend.
        # Uses SELECT FOR UPDATE on the spend rows to serialize concurrent verifications.
        if cart_jti:
            try:
                with db_session() as db:
                    # Single-use: check if cart_jti already spent (also blocks concurrent dupes via FOR UPDATE)
                    already_used = (
                        db.query(MandateSpend)
                        .filter(
                            MandateSpend.cart_jti == cart_jti,
                            MandateSpend.tenant_id == tenant_id,
                        )
                        .with_for_update()
                        .one_or_none()
                    )
                    if already_used:
                        return MandateVerificationResponse(
                            verified=False,
                            mandate_type=actual_type,
                            mandate_id=cs.get("mandateId", cart_jti),
                            delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
                            agent_did=payload.get("sub", ""),
                            scope=scope,
                            reason="Cart mandate already fulfilled (single-use JTI)",
                        )

                    # Cumulative budget enforcement — lock intent spend rows before summing
                    if intent_jti and intent_max > 0:
                        cumulative = (
                            db.query(func.sum(MandateSpend.amount))
                            .filter(
                                MandateSpend.intent_jti == intent_jti,
                                MandateSpend.tenant_id == tenant_id,
                            )
                            .with_for_update()
                            .scalar()
                        ) or Decimal(0)
                        if Decimal(cart_value) + cumulative > Decimal(intent_max):
                            return MandateVerificationResponse(
                                verified=False,
                                mandate_type=actual_type,
                                mandate_id=cs.get("mandateId", payload.get("jti", "")),
                                delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
                                agent_did=payload.get("sub", ""),
                                scope=scope,
                                reason=f"Budget exhausted: cumulative spend {int(cumulative)} + cart {cart_value} > intent limit {intent_max}",
                            )

                    # Record spend atomically within same transaction
                    db.add(MandateSpend(
                        tenant_id=tenant_id,
                        intent_jti=intent_jti or "",
                        cart_jti=cart_jti,
                        amount=Decimal(cart_value),
                        currency=cart_currency,
                        merchant_did=cs.get("merchant_did"),
                        created_at=datetime.utcnow(),
                    ))
                    db.commit()
            except IntegrityError:
                # Unique constraint on cart_jti: concurrent request beat us — treat as already-used
                return MandateVerificationResponse(
                    verified=False,
                    mandate_type=actual_type,
                    mandate_id=cs.get("mandateId", cart_jti),
                    delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
                    agent_did=payload.get("sub", ""),
                    scope=scope,
                    reason="Cart mandate already fulfilled (concurrent submission rejected)",
                )

    return MandateVerificationResponse(
        verified=True,
        mandate_type=actual_type,
        mandate_id=cs.get("mandateId", payload.get("jti", "")),
        delegator_did=cs.get("delegatedBy", payload.get("iss", "")),
        agent_did=payload.get("sub", ""),
        scope=scope,
        reason=None,
    )


@router.get("/mandates/{intent_jti}/spend")
def get_mandate_spend(
    intent_jti: str,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
):
    """Get cumulative spend vs budget for an intent mandate."""
    tenant_id = auth.get("tenant_id", "default")
    with db_session() as db:
        spends = db.query(MandateSpend).filter(
            MandateSpend.intent_jti == intent_jti,
            MandateSpend.tenant_id == tenant_id,
        ).all()

    total_by_currency: dict[str, float] = {}
    for s in spends:
        c = s.currency or "USD"
        total_by_currency[c] = total_by_currency.get(c, 0) + float(s.amount)

    return {
        "intent_jti": intent_jti,
        "fulfillments": len(spends),
        "cumulative_spend": total_by_currency,
        "cart_jtis": [s.cart_jti for s in spends],
    }
