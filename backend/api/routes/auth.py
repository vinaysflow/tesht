from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.auth.jwt_auth import issue_admin_token
from core.settings import settings

router = APIRouter(prefix="/v1/auth", tags=["auth"])


class DevTokenRequest(BaseModel):
    subject: str = Field(default="dev", min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=lambda: ["agents:create", "credentials:issue", "credentials:revoke"])
    ttl_seconds: int = Field(default=3600, ge=60, le=60 * 60 * 24)


@router.post("/dev-token")
def dev_token(req: DevTokenRequest):
    if not settings.tesht_dev_mode:
        raise HTTPException(status_code=404, detail="Not found")

    token = issue_admin_token(scopes=req.scopes, subject=req.subject, ttl_seconds=req.ttl_seconds)
    return {"token": token, "token_type": "Bearer", "scopes": req.scopes, "expires_in": req.ttl_seconds}
