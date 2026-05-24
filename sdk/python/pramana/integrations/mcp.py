"""
pramana.integrations.mcp
~~~~~~~~~~~~~~~~~~~~~~~~
MCP (Model Context Protocol) authentication middleware.

Agents present a Verifiable Presentation as a Bearer token in the
Authorization header of every MCP request.  The server verifies the VP,
checks embedded VCs against its policy, and returns a rich auth context.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from pramana.credentials import (
    PresentationResult,
    VerificationResult,
    create_presentation,
    verify_presentation,
)
from pramana.delegation import DelegationResult, verify_delegation_chain
from pramana.identity import AgentIdentity


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class MCPAuthConfig:
    """Policy configuration for an MCP server or client."""

    identity: AgentIdentity
    """This server/client's own identity.  The DID is used as VP audience."""

    trusted_issuers: list[str] = field(default_factory=list)
    """DIDs of credential issuers that are trusted.  Empty list = trust all."""

    required_credential_types: list[str] = field(default_factory=list)
    """All listed credential types must be present in the VP.  Empty = no requirement."""

    require_delegation: bool = False
    """If True, at least one DelegationCredential VC must pass chain verification."""

    required_actions: list[str] = field(default_factory=list)
    """If require_delegation is True, each action must be in the effective scope."""

    resolver: Optional[Callable[[str], dict[str, Any]]] = None
    """Optional DID resolver for non-did:key issuers (e.g. did:web enterprise IdPs)."""

    status_checker: Optional[Callable[[str, int], bool]] = None
    """Optional revocation status checker callback."""

    require_delegator_identity: bool = False
    """If True, a credential whose subject matches the root delegator DID must be present."""

    delegator_credential_types: list[str] = field(default_factory=list)
    """If non-empty, the delegator identity credential type must be one of these."""


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class MCPAuthResult:
    """Result of authenticating an incoming MCP request."""

    authenticated: bool
    agent_did: Optional[str] = None
    agent_name: Optional[str] = None
    credentials: list[VerificationResult] = field(default_factory=list)
    delegation: Optional[DelegationResult] = None
    scopes: list[str] = field(default_factory=list)
    reason: Optional[str] = None
    delegator_did: Optional[str] = None
    delegator_claims: dict[str, Any] = field(default_factory=dict)
    delegator_credential_type: Optional[str] = None
    effective_scope: dict[str, Any] = field(default_factory=dict)
    blended: bool = False


# ---------------------------------------------------------------------------
# Core auth class
# ---------------------------------------------------------------------------

class PramanaMCPAuth:
    """MCP authentication helper — usable as middleware or standalone."""

    def __init__(self, config: MCPAuthConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Client side
    # ------------------------------------------------------------------

    def create_auth_headers(
        self,
        credentials: list[str],
        audience: str,
    ) -> dict[str, str]:
        """
        Create an Authorization header containing a signed VP-JWT.

        Args:
            credentials: List of VC-JWTs to embed in the presentation.
            audience:    Target MCP server's DID.

        Returns:
            {"Authorization": "Bearer <VP-JWT>"}
        """
        vp_jwt = create_presentation(
            holder=self.config.identity,
            credentials=credentials,
            audience=audience,
        )
        return {"Authorization": f"Bearer {vp_jwt}"}

    # ------------------------------------------------------------------
    # Server side
    # ------------------------------------------------------------------

    def verify_request(self, headers: dict[str, str]) -> MCPAuthResult:
        """
        Verify an incoming MCP request's Authorization header.

        Returns an MCPAuthResult — caller decides whether to reject (401)
        or proceed based on ``authenticated``.
        """
        # ── Step 1: extract Bearer token ──────────────────────────────
        auth_header = headers.get("Authorization") or headers.get("authorization")
        if not auth_header:
            return MCPAuthResult(
                authenticated=False,
                reason="Missing Authorization header",
            )

        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return MCPAuthResult(
                authenticated=False,
                reason="Invalid Authorization scheme: expected 'Bearer'",
            )

        vp_jwt = parts[1].strip()

        # ── Step 2: verify the VP ─────────────────────────────────────
        vp_result: PresentationResult = verify_presentation(
            vp_jwt,
            expected_audience=self.config.identity.did,
            resolver=self.config.resolver,
            status_checker=self.config.status_checker,
        )
        if not vp_result.verified:
            return MCPAuthResult(
                authenticated=False,
                reason=f"VP verification failed: {vp_result.reason}",
            )

        agent_did = vp_result.holder_did
        credential_results = vp_result.credentials

        # ── Step 3: issuer trust check ────────────────────────────────
        if self.config.trusted_issuers:
            for cr in credential_results:
                if cr.issuer_did not in self.config.trusted_issuers:
                    return MCPAuthResult(
                        authenticated=False,
                        agent_did=agent_did,
                        credentials=credential_results,
                        reason=f"Untrusted issuer: {cr.issuer_did}",
                    )

        # ── Step 4: collect types + scopes ────────────────────────────
        present_types: set[str] = set()
        scopes: list[str] = []
        for cr in credential_results:
            if cr.credential_type:
                present_types.add(cr.credential_type)
            actions = cr.claims.get("actions") or []
            for a in actions:
                if a not in scopes:
                    scopes.append(a)
            # Also collect from delegationScope
            del_scope = cr.claims.get("delegationScope") or {}
            for a in del_scope.get("actions", []):
                if a not in scopes:
                    scopes.append(a)

        # ── Step 5: required credential type check ────────────────────
        for required_type in self.config.required_credential_types:
            if required_type not in present_types:
                return MCPAuthResult(
                    authenticated=False,
                    agent_did=agent_did,
                    credentials=credential_results,
                    reason=f"Missing required credential type: {required_type}",
                )

        # ── Step 6: delegation chain check ───────────────────────────
        delegation_result: Optional[DelegationResult] = None
        if self.config.require_delegation:
            delegation_jwt: Optional[str] = None
            for cr in credential_results:
                if cr.credential_type == "DelegationCredential":
                    # Reconstruct the raw JWT from the VP's embedded list.
                    # verify_presentation already verified each VC; here we
                    # re-verify as a delegation chain (which recurses into
                    # parentDelegation claims).
                    delegation_jwt = _find_delegation_jwt(vp_jwt, cr)
                    break

            if delegation_jwt is None:
                return MCPAuthResult(
                    authenticated=False,
                    agent_did=agent_did,
                    credentials=credential_results,
                    reason="Delegation required but no DelegationCredential found",
                )

            for action in self.config.required_actions:
                del_result = verify_delegation_chain(
                    delegation_jwt,
                    required_action=action,
                    resolver=self.config.resolver,
                    status_checker=self.config.status_checker,
                )
                if not del_result.verified:
                    return MCPAuthResult(
                        authenticated=False,
                        agent_did=agent_did,
                        credentials=credential_results,
                        reason=f"Delegation chain invalid: {del_result.reason}",
                    )
                delegation_result = del_result

            if delegation_result is None:
                delegation_result = verify_delegation_chain(
                    delegation_jwt,
                    resolver=self.config.resolver,
                    status_checker=self.config.status_checker,
                )
                if not delegation_result.verified:
                    return MCPAuthResult(
                        authenticated=False,
                        agent_did=agent_did,
                        credentials=credential_results,
                        reason=f"Delegation chain invalid: {delegation_result.reason}",
                    )

        # ── Step 6b: delegator identity classification ────────────────
        delegator_did: Optional[str] = None
        delegator_claims: dict[str, Any] = {}
        delegator_credential_type: Optional[str] = None
        effective_scope: dict[str, Any] = {}
        blended = False

        if delegation_result and delegation_result.chain:
            root_delegator_did = delegation_result.chain[0]["delegator"]
            effective_scope = delegation_result.effective_scope

            # Find a VC whose subject is the root delegator
            for cr in credential_results:
                if cr.subject_did == root_delegator_did and cr.credential_type != "DelegationCredential":
                    delegator_did = root_delegator_did
                    delegator_claims = cr.claims
                    delegator_credential_type = cr.credential_type
                    blended = True
                    break

            # Policy: require_delegator_identity
            if self.config.require_delegator_identity and delegator_did is None:
                return MCPAuthResult(
                    authenticated=False,
                    agent_did=agent_did,
                    credentials=credential_results,
                    reason=(
                        f"Delegator identity required but no credential found "
                        f"for delegator DID {root_delegator_did}"
                    ),
                )

            # Policy: delegator_credential_types filter
            if (
                self.config.delegator_credential_types
                and delegator_credential_type is not None
                and delegator_credential_type not in self.config.delegator_credential_types
            ):
                return MCPAuthResult(
                    authenticated=False,
                    agent_did=agent_did,
                    credentials=credential_results,
                    reason=(
                        f"Delegator credential type '{delegator_credential_type}' "
                        f"not in allowed list: {self.config.delegator_credential_types}"
                    ),
                )

        # ── Step 7: extract agent_name from first VC claims ───────────
        agent_name: Optional[str] = None
        if credential_results:
            agent_name = credential_results[0].claims.get("name")

        return MCPAuthResult(
            authenticated=True,
            agent_did=agent_did,
            agent_name=agent_name,
            credentials=credential_results,
            delegation=delegation_result,
            scopes=scopes,
            delegator_did=delegator_did,
            delegator_claims=delegator_claims,
            delegator_credential_type=delegator_credential_type,
            effective_scope=effective_scope,
            blended=blended,
        )


# ---------------------------------------------------------------------------
# FastAPI middleware factory
# ---------------------------------------------------------------------------

def mcp_auth_middleware(auth: PramanaMCPAuth) -> Callable:
    """
    Return a FastAPI dependency that verifies MCP request credentials.

    Usage::

        auth = PramanaMCPAuth(config)

        @app.post("/mcp/tool/invoke")
        def invoke_tool(
            request: Request,
            agent_ctx: MCPAuthResult = Depends(mcp_auth_middleware(auth)),
        ):
            if not agent_ctx.authenticated:
                raise HTTPException(status_code=401, detail=agent_ctx.reason)
            # agent_ctx.agent_did is the verified agent DID
    """
    # Import inside function to keep FastAPI optional at import time.
    try:
        from fastapi import Request  # type: ignore[import]
    except ImportError:
        Request = None  # type: ignore[misc,assignment]

    async def _dependency(request: Any) -> MCPAuthResult:  # type: ignore[return]
        # Accept both FastAPI Request objects and plain dicts (for testing).
        if hasattr(request, "headers"):
            headers = dict(request.headers)
        else:
            headers = request  # plain dict passed directly
        return auth.verify_request(headers)

    return _dependency


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_delegation_jwt(vp_jwt: str, matching_cr: VerificationResult) -> Optional[str]:
    """
    Extract the raw VC-JWT for a DelegationCredential from the VP.

    We decode the VP's ``vp.verifiableCredential`` list and find the JWT
    whose ``jti`` or ``sub`` matches the verified VerificationResult.
    """
    import base64 as _b64
    import json as _json

    try:
        # Decode VP payload without signature check (already verified above)
        import jwt as _pyjwt
        vp_payload = _pyjwt.decode(vp_jwt, options={"verify_signature": False})
        vp_claim = vp_payload.get("vp") or {}
        vc_jwts: list[str] = vp_claim.get("verifiableCredential") or []

        target_subject = matching_cr.subject_did
        target_issuer = matching_cr.issuer_did

        for vc_jwt in vc_jwts:
            try:
                vc_payload = _pyjwt.decode(vc_jwt, options={"verify_signature": False})
                vc_claim = vc_payload.get("vc") or {}
                types = vc_claim.get("type") or []
                if "DelegationCredential" not in types:
                    continue
                if vc_payload.get("sub") == target_subject and vc_payload.get("iss") == target_issuer:
                    return vc_jwt
            except Exception:
                continue
    except Exception:
        pass
    return None
