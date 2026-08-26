from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from api.middleware.authz import require_scopes
from core.audit import write_audit
from core.db import db_session
from core.resolver import resolve_did
from core.status_list import set_revoked
from core.vc import verify_vc_jwt
from core.webhooks import dispatch_webhook_event

router = APIRouter(prefix="/v1/delegations", tags=["delegations"])


# ── Models ────────────────────────────────────────────────────────────────────

class RegisterDelegationRequest(BaseModel):
    """Register a delegation JWT in the registry so it can be cascade-revoked."""
    jti: str
    issuer_did: str
    subject_did: str
    parent_jti: Optional[str] = None
    status_list_id: Optional[str] = None
    status_list_index: Optional[int] = None


class RevokeRequest(BaseModel):
    jti: str
    cascade: bool = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_delegation_registry_table():
    """Lazy import to avoid circular deps at module load."""
    from sqlalchemy import MetaData
    from core.db import engine
    meta = MetaData()
    meta.reflect(bind=engine, only=["delegation_registry"])
    return meta.tables.get("delegation_registry")


def _revoke_single(db, jti: str, tenant_id: str) -> bool:
    """Revoke a single delegation by JTI. Returns True if found and revoked."""
    tbl = _get_delegation_registry_table()
    if tbl is None:
        return False

    row = db.execute(
        tbl.select().where(tbl.c.jti == jti).where(tbl.c.tenant_id == tenant_id)
    ).fetchone()
    if row is None:
        return False

    # Mark revoked in registry
    db.execute(
        tbl.update()
        .where(tbl.c.jti == jti)
        .values(revoked_at=datetime.now(timezone.utc))
    )

    # Set status list bit if present
    if row.status_list_id and row.status_list_index is not None:
        try:
            set_revoked(row.status_list_id, row.status_list_index)
        except Exception:
            pass  # status list may have already been revoked

    return True


def _cascade_revoke(db, parent_jti: str, tenant_id: str, depth: int = 0) -> list[str]:
    """Recursively revoke all children of parent_jti. Returns list of revoked JTIs."""
    if depth > 15:
        return []  # safety guard

    tbl = _get_delegation_registry_table()
    if tbl is None:
        return []

    children = db.execute(
        tbl.select()
        .where(tbl.c.parent_jti == parent_jti)
        .where(tbl.c.tenant_id == tenant_id)
    ).fetchall()

    revoked = []
    for child in children:
        if _revoke_single(db, child.jti, tenant_id):
            revoked.append(child.jti)
        revoked.extend(_cascade_revoke(db, child.jti, tenant_id, depth + 1))

    return revoked


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register")
def register_delegation(
    req: RegisterDelegationRequest,
    auth: dict = Depends(require_scopes(["credentials:issue"])),
):
    """Register a delegation in the registry to enable cascade revocation."""
    tenant_id = auth.get("tenant_id", "default")

    tbl = _get_delegation_registry_table()
    if tbl is None:
        raise HTTPException(status_code=503, detail="Delegation registry not available (run migrations)")

    with db_session() as db:
        existing = db.execute(tbl.select().where(tbl.c.jti == req.jti)).fetchone()
        if existing:
            return {"registered": False, "reason": "JTI already registered"}

        db.execute(
            tbl.insert().values(
                jti=req.jti,
                tenant_id=tenant_id,
                issuer_did=req.issuer_did,
                subject_did=req.subject_did,
                parent_jti=req.parent_jti,
                status_list_id=req.status_list_id,
                status_list_index=req.status_list_index,
                created_at=datetime.now(timezone.utc),
                revoked_at=None,
            )
        )
        db.commit()

    return {"registered": True, "jti": req.jti}


@router.post("/revoke")
def revoke_delegation(
    req: RevokeRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_scopes(["credentials:revoke"])),
):
    """Revoke a delegation by JTI. With cascade=true, also revokes all child delegations."""
    tenant_id = auth.get("tenant_id", "default")

    tbl = _get_delegation_registry_table()
    if tbl is None:
        raise HTTPException(status_code=503, detail="Delegation registry not available (run migrations)")

    with db_session() as db:
        revoked_self = _revoke_single(db, req.jti, tenant_id)
        if not revoked_self:
            raise HTTPException(status_code=404, detail=f"Delegation JTI '{req.jti}' not found in registry")

        cascaded = []
        if req.cascade:
            cascaded = _cascade_revoke(db, req.jti, tenant_id)

        db.commit()

    all_revoked = [req.jti] + cascaded

    write_audit(
        tenant_id=tenant_id,
        event_type="delegation.revoked",
        actor="api",
        resource_type="delegation",
        resource_id=req.jti,
        payload={"cascade": req.cascade, "cascaded_count": len(cascaded), "all_revoked_jtis": all_revoked},
    )

    if req.cascade and cascaded:
        background_tasks.add_task(
            dispatch_webhook_event,
            tenant_id,
            "delegation.cascade_revoked",
            {"parent_jti": req.jti, "cascaded_jtis": cascaded},
        )

    return {
        "revoked": True,
        "jti": req.jti,
        "cascade": req.cascade,
        "cascaded_count": len(cascaded),
        "all_revoked": all_revoked,
    }


# ── Delegation chain verification ─────────────────────────────────────────────

def _validate_scope_narrowing(parent_scope: dict[str, Any], child_scope: dict[str, Any]) -> Optional[str]:
    """Validate child scope is a subset of parent. Returns error string or None."""
    p_actions = set(parent_scope.get("actions", []))
    c_actions = set(child_scope.get("actions", []))
    if c_actions and not c_actions.issubset(p_actions):
        return f"Scope escalation on 'actions': child {sorted(c_actions)} not subset of parent {sorted(p_actions)}"

    p_amount = parent_scope.get("max_amount", 0)
    c_amount = child_scope.get("max_amount", 0)
    if c_amount > p_amount:
        return f"Scope escalation on 'max_amount': child {c_amount} > parent {p_amount}"

    p_currency = parent_scope.get("currency", "USD")
    c_currency = child_scope.get("currency", "USD")
    if c_currency != p_currency:
        return f"Scope escalation on 'currency': child '{c_currency}' != parent '{p_currency}'"

    p_merchants = parent_scope.get("merchants", [])
    c_merchants = child_scope.get("merchants", [])
    if p_merchants != ["*"]:
        p_set = set(p_merchants)
        c_set = set(c_merchants)
        if c_set and not c_set.issubset(p_set):
            return f"Scope escalation on 'merchants': child {sorted(c_set)} not subset of parent {sorted(p_set)}"

    p_categories = set(parent_scope.get("categories", []))
    c_categories = set(child_scope.get("categories", []))
    if c_categories and not c_categories.issubset(p_categories):
        return f"Scope escalation on 'categories': child {sorted(c_categories)} not subset of parent {sorted(p_categories)}"

    # Attestation selector subset check (SPIFFE selectors)
    p_selectors = {(s.get("type"), s.get("value")) for s in parent_scope.get("attestation_selectors", [])}
    c_selectors = {(s.get("type"), s.get("value")) for s in child_scope.get("attestation_selectors", [])}
    if p_selectors and c_selectors and not c_selectors.issubset(p_selectors):
        return "Scope escalation on 'attestation_selectors': child selectors not subset of parent"

    return None


def _intersect_scopes(parent_scope: dict[str, Any], child_scope: dict[str, Any]) -> dict[str, Any]:
    p_actions = set(parent_scope.get("actions", []))
    c_actions = set(child_scope.get("actions", []))
    effective_actions = sorted(p_actions & c_actions) if c_actions else sorted(p_actions)

    effective_amount = min(
        parent_scope.get("max_amount", 0),
        child_scope.get("max_amount", parent_scope.get("max_amount", 0)),
    )

    p_merchants = parent_scope.get("merchants", [])
    c_merchants = child_scope.get("merchants", [])
    if p_merchants == ["*"] and c_merchants == ["*"]:
        effective_merchants: list = ["*"]
    elif p_merchants == ["*"]:
        effective_merchants = c_merchants
    elif c_merchants == ["*"]:
        effective_merchants = p_merchants
    else:
        effective_merchants = sorted(set(p_merchants) & set(c_merchants))

    p_categories = set(parent_scope.get("categories", []))
    c_categories = set(child_scope.get("categories", []))
    effective_categories = sorted(p_categories & c_categories) if c_categories else sorted(p_categories)

    # Attestation selectors: child selectors become the effective constraint
    c_selectors = child_scope.get("attestation_selectors", [])
    p_selectors = parent_scope.get("attestation_selectors", [])
    effective_selectors = c_selectors if c_selectors else p_selectors

    return {
        "actions": effective_actions,
        "max_amount": effective_amount,
        "currency": parent_scope.get("currency", "USD"),
        "merchants": effective_merchants,
        "categories": effective_categories,
        "constraints": {**parent_scope.get("constraints", {}), **child_scope.get("constraints", {})},
        "attestation_selectors": effective_selectors,
    }


def _status_check_fn(status_list_cred_url: str, index: int) -> bool:
    """Status check callback for verify_vc_jwt used in delegation chain verification."""
    try:
        from core.status_list_vc import (
            is_local_status_list_url,
            issue_status_list_vc_jwt,
            status_list_id_from_url,
            verify_and_extract_encoded_list,
        )
        import httpx as _httpx
        if is_local_status_list_url(status_list_cred_url):
            sl_id = status_list_id_from_url(status_list_cred_url)
            status_jwt, _ = issue_status_list_vc_jwt(sl_id)
        else:
            r = _httpx.get(status_list_cred_url, timeout=10.0)
            r.raise_for_status()
            data = r.json()
            status_jwt = data.get("jwt")
            if not isinstance(status_jwt, str):
                return False
        raw_bits, _ = verify_and_extract_encoded_list(status_jwt)
        if index < 0 or index >= (len(raw_bits) * 8):
            return False
        byte_i = index // 8
        bit_i = index % 8
        return (raw_bits[byte_i] & (1 << bit_i)) != 0
    except Exception:
        return False


def _verify_delegation_chain_backend(
    token: str,
    required_action: Optional[str] = None,
    _depth: int = 0,
    _max_depth: int = 10,
) -> dict[str, Any]:
    """Recursively verify a delegation chain server-side. Returns result dict."""
    if _depth > _max_depth:
        return {"verified": False, "chain": [], "effective_scope": {}, "depth": _depth,
                "reason": f"Recursion limit {_max_depth} exceeded"}

    try:
        result = verify_vc_jwt(
            token=token,
            resolve_did_document=resolve_did,
            status_check=_status_check_fn,
        )
    except Exception as exc:
        return {"verified": False, "chain": [], "effective_scope": {}, "depth": _depth,
                "reason": f"Signature verification failed: {exc}"}

    if result["status"].get("present") and result["status"].get("revoked"):
        return {"verified": False, "chain": [], "effective_scope": {}, "depth": _depth,
                "reason": "Delegation credential is revoked"}

    payload = result["payload"]
    vc = payload.get("vc") or {}
    cs = vc.get("credentialSubject") or {}
    this_scope = cs.get("delegationScope") or {}
    this_link = {
        "delegator": cs.get("delegatedBy", payload.get("iss", "")),
        "delegate": payload.get("sub", ""),
        "scope": this_scope,
        "depth": int(cs.get("delegationDepth", 0)),
        "jti": payload.get("jti", ""),
    }

    parent_jwt = cs.get("parentDelegation")
    if parent_jwt:
        parent_result = _verify_delegation_chain_backend(
            parent_jwt, _depth=_depth + 1, _max_depth=_max_depth
        )
        if not parent_result["verified"]:
            return {"verified": False, "chain": parent_result["chain"], "effective_scope": {},
                    "depth": _depth, "reason": f"Parent delegation invalid: {parent_result['reason']}"}

        scope_err = _validate_scope_narrowing(parent_result["effective_scope"], this_scope)
        if scope_err:
            return {"verified": False, "chain": parent_result["chain"] + [this_link],
                    "effective_scope": {}, "depth": _depth, "reason": scope_err}

        effective_scope = _intersect_scopes(parent_result["effective_scope"], this_scope)
        chain = parent_result["chain"] + [this_link]
    else:
        effective_scope = this_scope
        chain = [this_link]

    if required_action and required_action not in effective_scope.get("actions", []):
        return {"verified": False, "chain": chain, "effective_scope": effective_scope,
                "depth": len(chain),
                "reason": f"Action '{required_action}' not in effective scope: {effective_scope.get('actions', [])}"}

    return {"verified": True, "chain": chain, "effective_scope": effective_scope,
            "depth": len(chain), "reason": None}


class VerifyDelegationRequest(BaseModel):
    delegation_jwt: str
    required_action: Optional[str] = None


class DelegationChainLink(BaseModel):
    delegator: str
    delegate: str
    scope: dict[str, Any]
    depth: int
    jti: str = ""


class VerifyDelegationResponse(BaseModel):
    verified: bool
    chain: list[dict[str, Any]]
    effective_scope: dict[str, Any]
    depth: int
    reason: Optional[str]


@router.post("/verify", response_model=VerifyDelegationResponse)
def verify_delegation(
    req: VerifyDelegationRequest,
    auth: dict = Depends(require_scopes(["credentials:verify"])),
) -> VerifyDelegationResponse:
    """Server-side delegation chain verification with scope narrowing enforcement."""
    result = _verify_delegation_chain_backend(
        req.delegation_jwt,
        required_action=req.required_action,
    )

    write_audit(
        tenant_id=auth.get("tenant_id", "default"),
        event_type="delegation.chain.verified" if result["verified"] else "delegation.chain.rejected",
        actor="api",
        resource_type="delegation",
        resource_id=result["chain"][0].get("jti", "") if result["chain"] else "",
        payload={
            "verified": result["verified"],
            "depth": result["depth"],
            "required_action": req.required_action,
            "reason": result.get("reason"),
        },
    )

    return VerifyDelegationResponse(**result)
