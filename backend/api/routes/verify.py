from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.audit import write_audit
from core.resolver import resolve_did
from core.status_list_vc import (
    is_local_status_list_url,
    issue_status_list_vc_jwt,
    status_list_id_from_url,
    verify_and_extract_encoded_list,
)
from core.vc import verify_vc_jwt

import httpx

router = APIRouter(prefix="/v1/credentials", tags=["credentials"])


class VerifyRequest(BaseModel):
    jwt: str = Field(min_length=10)


@router.post("/verify")
def verify(req: VerifyRequest):
    try:
        def status_check(status_list_cred_url: str, index: int) -> bool:
            if is_local_status_list_url(status_list_cred_url):
                sl_id = status_list_id_from_url(status_list_cred_url)
                status_jwt, _ = issue_status_list_vc_jwt(sl_id)
            else:
                r = httpx.get(status_list_cred_url, timeout=10.0)
                r.raise_for_status()
                data = r.json()
                status_jwt = data.get('jwt')
                if not isinstance(status_jwt, str):
                    raise ValueError('status list response missing jwt')

            raw_bits, _ = verify_and_extract_encoded_list(status_jwt)

            if index < 0 or index >= (len(raw_bits) * 8):
                return False
            byte_i = index // 8
            bit_i = index % 8
            return (raw_bits[byte_i] & (1 << bit_i)) != 0

        result = verify_vc_jwt(token=req.jwt, resolve_did_document=resolve_did, status_check=status_check)

        jti = str(result["payload"].get("jti", ""))

        write_audit(
            tenant_id="public",
            event_type="credential.verified",
            actor="verifier",
            resource_type="credential",
            resource_id=jti,
            payload={"iss": result["payload"].get("iss"), "sub": result["payload"].get("sub"), "status": result["status"]},
        )

        if result["status"].get("present") and result["status"].get("revoked"):
            return {"verified": False, "reason": "revoked", **result}

        return {"verified": True, **result}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
