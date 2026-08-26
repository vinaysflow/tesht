"""Agent Marketplace — verified merchant agents with transaction history."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.middleware.authz import require_scopes
from core.db import db_session
from models import Agent, Credential, MandateSpend

router = APIRouter(prefix="/v1/marketplace", tags=["marketplace"])


class MerchantTransaction(BaseModel):
    cart_jti: str
    amount: float
    currency: str
    created_at: str


class MerchantInfo(BaseModel):
    name: str
    did: str
    spiffe_id: Optional[str]
    credential_count: int
    transaction_count: int
    total_volume: float
    currency: str
    verified: bool
    categories: list[str]
    credential_types: list[str]


class MerchantDetailResponse(BaseModel):
    merchant: MerchantInfo
    transactions: list[MerchantTransaction]


@router.get("/merchants", response_model=list[MerchantInfo])
def list_merchants(auth: dict = Depends(require_scopes(["credentials:verify"]))) -> list[MerchantInfo]:
    """List all verified merchant agents with transaction summary."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        # Find agents that appear as merchant_did in mandate spends or have MerchantCredential
        merchant_creds = db.query(Credential).filter(
            Credential.tenant_id == tenant_id,
            Credential.credential_type == "MerchantCredential",
        ).all()

        merchant_dids = {c.subject_did for c in merchant_creds}

        # Also include agents that received transactions
        spend_merchants = db.query(MandateSpend.merchant_did).filter(
            MandateSpend.tenant_id == tenant_id,
            MandateSpend.merchant_did.isnot(None),
        ).distinct().all()

        for (did,) in spend_merchants:
            if did:
                merchant_dids.add(did)

        merchants: list[MerchantInfo] = []
        for did in merchant_dids:
            agent = db.query(Agent).filter(Agent.did == did, Agent.tenant_id == tenant_id).one_or_none()
            if not agent:
                continue

            # Credentials for this merchant
            creds = db.query(Credential).filter(
                Credential.tenant_id == tenant_id,
                Credential.subject_did == did,
            ).all()
            cred_types = list({c.credential_type for c in creds})

            # Transactions
            spends = db.query(MandateSpend).filter(
                MandateSpend.tenant_id == tenant_id,
                MandateSpend.merchant_did == did,
            ).all()
            total_volume = sum(float(s.amount) for s in spends if s.currency == "USD") / 100.0
            currency = "USD"

            # Extract categories from MerchantCredential JWT if available
            categories: list[str] = []
            mc = next((c for c in creds if c.credential_type == "MerchantCredential"), None)
            if mc and mc.jwt:
                try:
                    import jwt as pyjwt
                    payload = pyjwt.decode(mc.jwt, options={"verify_signature": False})
                    cs = (payload.get("vc") or {}).get("credentialSubject") or {}
                    categories = cs.get("categories", [])
                except Exception:
                    pass

            merchants.append(MerchantInfo(
                name=agent.name,
                did=did,
                spiffe_id=getattr(agent, "spiffe_id", None),
                credential_count=len(creds),
                transaction_count=len(spends),
                total_volume=round(total_volume, 2),
                currency=currency,
                verified=mc is not None,
                categories=categories,
                credential_types=cred_types,
            ))

    merchants.sort(key=lambda m: m.transaction_count, reverse=True)
    return merchants


@router.get("/merchants/{did:path}/transactions", response_model=MerchantDetailResponse)
def merchant_transactions(
    did: str,
    auth: dict = Depends(require_scopes(["credentials:verify"])),
) -> MerchantDetailResponse:
    """Get transaction history and details for a specific merchant."""
    tenant_id = auth.get("tenant_id", "default")

    with db_session() as db:
        agent = db.query(Agent).filter(Agent.did == did, Agent.tenant_id == tenant_id).one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail=f"Merchant DID not found: {did!r}")

        creds = db.query(Credential).filter(
            Credential.tenant_id == tenant_id,
            Credential.subject_did == did,
        ).all()
        cred_types = list({c.credential_type for c in creds})
        mc = next((c for c in creds if c.credential_type == "MerchantCredential"), None)

        spends = db.query(MandateSpend).filter(
            MandateSpend.tenant_id == tenant_id,
            MandateSpend.merchant_did == did,
        ).order_by(MandateSpend.created_at.desc()).all()

    categories: list[str] = []
    if mc and mc.jwt:
        try:
            import jwt as pyjwt
            payload = pyjwt.decode(mc.jwt, options={"verify_signature": False})
            cs = (payload.get("vc") or {}).get("credentialSubject") or {}
            categories = cs.get("categories", [])
        except Exception:
            pass

    total_volume = sum(float(s.amount) for s in spends if s.currency == "USD") / 100.0

    txs = [
        MerchantTransaction(
            cart_jti=s.cart_jti,
            amount=float(s.amount) / 100.0,
            currency=s.currency or "USD",
            created_at=s.created_at.isoformat() if hasattr(s.created_at, "isoformat") else str(s.created_at),
        )
        for s in spends
    ]

    return MerchantDetailResponse(
        merchant=MerchantInfo(
            name=agent.name,
            did=did,
            spiffe_id=getattr(agent, "spiffe_id", None),
            credential_count=len(creds),
            transaction_count=len(spends),
            total_volume=round(total_volume, 2),
            currency="USD",
            verified=mc is not None,
            categories=categories,
            credential_types=cred_types,
        ),
        transactions=txs,
    )
