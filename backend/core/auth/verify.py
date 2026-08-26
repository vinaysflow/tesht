from __future__ import annotations

from typing import Any

from core.auth.demo import verify_demo_token
from core.auth.jwt_auth import extract_scopes as extract_scopes_hs256
from core.auth.jwt_auth import verify_token as verify_hs256
from core.auth.oidc import extract_scopes_from_keycloak, extract_tenant_from_groups, verify_oidc_token
from core.settings import settings


def verify_access_token(token: str) -> dict[str, Any]:
    # Demo mode: accept demo token regardless of AUTH_MODE
    if settings.demo_mode:
        try:
            return verify_demo_token(token)
        except Exception:
            pass

    if settings.auth_mode.lower() == 'oidc':
        return verify_oidc_token(token)
    return verify_hs256(token)


def extract_scopes(claims: dict[str, Any]) -> set[str]:
    if settings.auth_mode.lower() == 'oidc' and not claims.get('demo'):
        return extract_scopes_from_keycloak(claims, client_id=settings.oidc_client_id or None)
    return extract_scopes_hs256(claims)


def extract_tenant_id(claims: dict[str, Any]) -> str:
    if settings.auth_mode.lower() == 'oidc' and not claims.get('demo'):
        return extract_tenant_from_groups(claims) or 'default'
    t = claims.get('tenant')
    return str(t) if isinstance(t, str) and t else 'default'


def auth_context_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    scopes = extract_scopes(claims)
    tenant_id = extract_tenant_id(claims)
    return {"claims": claims, "scopes": scopes, "tenant_id": tenant_id}
