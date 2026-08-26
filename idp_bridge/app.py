"""
idp_bridge.app
~~~~~~~~~~~~~~
Tesht Enterprise IdP Bridge — FastAPI application.

Converts enterprise OIDC tokens into W3C Verifiable Credentials and
optional DelegationCredentials, ready for use in Blended Identity VPs.

Two core endpoints:
  POST /attest  — OIDC token in, OrganizationalRoleCredential out
  POST /bind    — OIDC token in, enterprise VC + delegation VC out

Status list endpoints (for revocation demo):
  GET  /bridge/status-list      — returns bitstring for gateway status_checker
  POST /bridge/revoke           — revoke a credential by its jti

Shadow detection demo helpers:
  POST /bridge/shadow-test-vps  — returns expired VP and no-delegation VP for browser demo

Run standalone:
    uvicorn idp_bridge.app:app --host 0.0.0.0 --port 5053
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import asyncio

from tesht.credentials import create_blended_presentation, create_presentation, issue_vc
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity

from idp_bridge.config import load_idp_config
from idp_bridge.identity_store import HumanIdentityStore
from idp_bridge.validator import MultiIssuerOIDCValidator


# ---------------------------------------------------------------------------
# In-memory BitstringStatusList — no database dependency
# ---------------------------------------------------------------------------

class InMemoryStatusList:
    """Minimal W3C BitstringStatusList implementation backed by a bytearray.

    Thread-safety is not required because FastAPI's single-process async model
    serialises access in the demo context.
    """

    def __init__(self, size: int = 16384) -> None:
        self._bits = bytearray(size // 8)
        self._next_index = 0
        self.size = size
        self.list_id = str(uuid.uuid4())

    def allocate(self) -> int:
        """Reserve and return the next available index."""
        idx = self._next_index
        if idx >= self.size:
            raise ValueError("Status list is full")
        self._next_index += 1
        return idx

    def revoke(self, index: int) -> None:
        """Flip the bit at *index* to mark the credential as revoked."""
        if index < 0 or index >= self.size:
            raise ValueError(f"Index {index} out of bounds (size={self.size})")
        self._bits[index // 8] |= 1 << (index % 8)

    def is_revoked(self, index: int) -> bool:
        if index < 0 or index >= self.size:
            return False
        return bool(self._bits[index // 8] & (1 << (index % 8)))

    def bitstring_b64url(self) -> str:
        """Return the raw bitstring as unpadded base64url (for wire format)."""
        return base64.urlsafe_b64encode(bytes(self._bits)).rstrip(b"=").decode("ascii")


def _extract_jti(jwt_str: str) -> str:
    """Decode the JWT payload segment and return the 'jti' claim."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT")
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    jti = payload.get("jti") or payload.get("id")
    if not jti:
        raise ValueError("JWT has no 'jti' claim")
    return jti


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class RevokeRequest(BaseModel):
    credential_id: str = Field(description="The 'jti' of the credential to revoke")


class AttestRequest(BaseModel):
    oidc_token: str = Field(min_length=10, description="OIDC id_token (RS256 signed)")
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class AttestResponse(BaseModel):
    did: str
    credential: str
    provider: str
    provider_id: str
    claims: dict[str, Any]
    created: bool


class BindRequest(BaseModel):
    oidc_token: str = Field(min_length=10)
    agent_did: str = Field(min_length=10)
    scope: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    max_depth: int = Field(default=1, ge=1, le=5, description="Max sub-delegation depth allowed on this delegation")


class BindResponse(BaseModel):
    did: str
    enterprise_vc: str
    delegation_vc: str
    agent_did: str
    effective_scope: dict[str, Any]
    provider: str
    provider_id: str
    claims: dict[str, Any]


class BindWithVPRequest(BaseModel):
    oidc_token: str = Field(min_length=10)
    agent_did: str = Field(min_length=10)
    scope: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    gateway_did: str = Field(
        default="",
        description="Gateway DID used as VP audience. If empty, uses agent_did.",
    )


class BindWithVPResponse(BaseModel):
    did: str
    enterprise_vc: str
    delegation_vc: str
    agent_vc: str
    blended_vp: str
    agent_did: str
    effective_scope: dict[str, Any]
    provider: str
    provider_id: str
    claims: dict[str, Any]


# ---------------------------------------------------------------------------
# Lifespan: initialise all stateful components
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    config_path = os.environ.get(
        "IDP_BRIDGE_CONFIG",
        str(Path(__file__).resolve().parent / "config.yaml"),
    )
    registry = load_idp_config(config_path)

    application.state.registry = registry
    application.state.validator = MultiIssuerOIDCValidator(registry)
    application.state.identity_store = HumanIdentityStore()
    # The bridge itself is the VC issuer — equivalent to the platform IdP agent
    application.state.bridge_identity = AgentIdentity.create("tesht-idp-bridge")

    # In-memory BitstringStatusList for revocation tracking
    application.state.status_list = InMemoryStatusList()
    # Maps credential jti -> status list index for revocation lookups
    application.state.credential_index_map: dict[str, int] = {}

    yield


app = FastAPI(
    title="Tesht Enterprise IdP Bridge",
    version="0.1.0",
    lifespan=lifespan,
)

if os.getenv("TESHT_CORS_ENABLED", "").lower() in ("1", "true", "yes"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ---------------------------------------------------------------------------
# Internal logic (shared by /attest and /bind)
# ---------------------------------------------------------------------------

def _status_list_url(state) -> str:
    """Return the URL of this bridge's status list endpoint.

    Configurable via BRIDGE_STATUS_LIST_URL env var; defaults to localhost.
    """
    return os.environ.get(
        "BRIDGE_STATUS_LIST_URL",
        f"http://127.0.0.1:{os.environ.get('BRIDGE_PORT', '5053')}/bridge/status-list",
    )


def _do_attest(req: AttestRequest, state) -> AttestResponse:
    """Core attest logic: validate OIDC token → issue enterprise identity VC."""
    validator: MultiIssuerOIDCValidator = state.validator
    identity_store: HumanIdentityStore = state.identity_store
    bridge_identity: AgentIdentity = state.bridge_identity
    registry = state.registry

    # 1. Validate OIDC token against registry
    result = validator.validate_token(req.oidc_token)
    if not result.valid:
        raise HTTPException(
            status_code=401,
            detail=result.reason or "Invalid OIDC token",
        )

    # 2. Get or create platform-managed human identity
    name = result.mapped_claims.get("name") or result.subject or "unknown"
    human_identity, was_created = identity_store.get_or_create(
        issuer=result.issuer or "",
        subject=result.subject or "",
        name=name,
    )

    # 3. Build VC claims: enterprise claims + IdP provenance
    vc_claims: dict[str, Any] = dict(result.mapped_claims)
    vc_claims["idp_issuer"] = result.issuer
    vc_claims["idp_subject"] = result.subject

    # 4. Determine credential type from registry
    provider = registry.providers[result.provider_id or ""]
    credential_type = provider.default_credential_type

    # 5. Allocate a status list index for this enterprise VC
    sl: InMemoryStatusList = state.status_list
    sl_url = _status_list_url(state)
    sl_index = sl.allocate()
    credential_id = str(uuid.uuid4())

    # 6. Issue the enterprise identity VC signed by the bridge identity
    vc_jwt = issue_vc(
        issuer=bridge_identity,
        subject_did=human_identity.did,
        credential_type=credential_type,
        claims=vc_claims,
        ttl_seconds=req.ttl_seconds,
        credential_id=credential_id,
        status_list_url=sl_url,
        status_list_index=sl_index,
    )

    # Track jti → index for revocation
    state.credential_index_map[credential_id] = sl_index

    return AttestResponse(
        did=human_identity.did,
        credential=vc_jwt,
        provider=result.provider_name or "",
        provider_id=result.provider_id or "",
        claims=result.mapped_claims,
        created=was_created,
    )


# ---------------------------------------------------------------------------
# POST /attest — OIDC token in, enterprise identity VC out
# ---------------------------------------------------------------------------

@app.post("/attest", response_model=AttestResponse)
async def attest_oidc(req: AttestRequest, http_request: Request) -> AttestResponse:
    """Verify an enterprise OIDC token and issue a W3C VC binding the
    enterprise identity to a platform-managed DID.

    Idempotent: the same (issuer, sub) always gets the same DID.
    """
    return _do_attest(req, http_request.app.state)


# ---------------------------------------------------------------------------
# POST /bind — OIDC token in, enterprise VC + delegation VC out
# ---------------------------------------------------------------------------

@app.post("/bind", response_model=BindResponse)
async def bind_oidc(req: BindRequest, http_request: Request) -> BindResponse:
    """Attest enterprise identity AND issue a delegation to the specified agent.

    Returns everything the agent needs to build a Blended Identity VP:
    - ``enterprise_vc``:  OrganizationalRoleCredential proving the human's identity
    - ``delegation_vc``:  DelegationCredential authorising the agent to act on their behalf
    """
    state = http_request.app.state

    # 1. Attest — get enterprise VC + ensure human identity exists in store
    attest_req = AttestRequest(
        oidc_token=req.oidc_token, ttl_seconds=req.ttl_seconds
    )
    attest_result = _do_attest(attest_req, state)

    # 2. Re-validate to get issuer/sub for identity store lookup
    validation = state.validator.validate_token(req.oidc_token)
    human_identity = state.identity_store.get(
        validation.issuer or "", validation.subject or ""
    )
    if human_identity is None:
        raise HTTPException(
            status_code=500, detail="Human identity not found after attest"
        )

    # 3. Build scope with defaults for missing keys
    scope: dict[str, Any] = {
        "actions": [],
        "max_amount": 0,
        "currency": "USD",
        "merchants": [],
        "categories": [],
    }
    scope.update(req.scope)

    # 4. Allocate a status list index for the delegation VC
    sl: InMemoryStatusList = state.status_list
    sl_url = _status_list_url(state)
    del_sl_index = sl.allocate()

    # 5. Sign the delegation with the human's platform-managed private key
    delegation_jwt = issue_delegation(
        delegator=human_identity,
        delegate_did=req.agent_did,
        scope=scope,
        max_depth=req.max_depth,
        ttl_seconds=req.ttl_seconds,
        status_list_url=sl_url,
        status_list_index=del_sl_index,
    )

    # Track the delegation VC's jti → index for revocation
    try:
        del_jti = _extract_jti(delegation_jwt)
        state.credential_index_map[del_jti] = del_sl_index
    except Exception:
        pass

    return BindResponse(
        did=attest_result.did,
        enterprise_vc=attest_result.credential,
        delegation_vc=delegation_jwt,
        agent_did=req.agent_did,
        effective_scope=scope,
        provider=attest_result.provider,
        provider_id=attest_result.provider_id,
        claims=attest_result.claims,
    )


# ---------------------------------------------------------------------------
# POST /bind-with-vp — like /bind but also builds the blended VP server-side
# ---------------------------------------------------------------------------

@app.post("/bind-with-vp", response_model=BindWithVPResponse)
async def bind_with_vp(req: BindWithVPRequest, http_request: Request) -> BindWithVPResponse:
    """Like /bind, but additionally issues an AgentCredential and assembles
    a ready-to-use BlendedIdentityPresentation VP-JWT.

    The React demo app calls this in one shot because the browser cannot sign
    Ed25519 JWTs.  The bridge acts as the agent's credential issuer for demo
    purposes (platform-managed identity).
    """
    state = http_request.app.state
    bridge_identity: AgentIdentity = state.bridge_identity

    # 1. Run the normal bind flow to get enterprise + delegation VCs
    bind_req = BindRequest(
        oidc_token=req.oidc_token,
        agent_did=req.agent_did,
        scope=req.scope,
        ttl_seconds=req.ttl_seconds,
    )
    bind_resp_obj = await bind_oidc(bind_req, http_request)

    # 2. Issue an AgentCredential for the agent DID (signed by bridge identity)
    agent_vc = issue_vc(
        issuer=bridge_identity,
        subject_did=req.agent_did,
        credential_type="AgentCredential",
        claims={
            "agentName": "ShoppingBot",
            "ownerOrg": bind_resp_obj.claims.get("organization", "Enterprise"),
            "agentType": "LLM",
            "purpose": "Procurement automation (demo)",
        },
        ttl_seconds=req.ttl_seconds,
    )

    # 3. Build the blended VP
    audience = req.gateway_did or req.agent_did
    blended_vp = create_blended_presentation(
        agent=bridge_identity,  # bridge signs the VP as the platform agent
        delegation_jwt=bind_resp_obj.delegation_vc,
        delegator_identity_jwt=bind_resp_obj.enterprise_vc,
        additional_credentials=[agent_vc],
        audience=audience,
        ttl_seconds=300,  # 5 min VP TTL for the demo
    )

    return BindWithVPResponse(
        did=bind_resp_obj.did,
        enterprise_vc=bind_resp_obj.enterprise_vc,
        delegation_vc=bind_resp_obj.delegation_vc,
        agent_vc=agent_vc,
        blended_vp=blended_vp,
        agent_did=req.agent_did,
        effective_scope=bind_resp_obj.effective_scope,
        provider=bind_resp_obj.provider,
        provider_id=bind_resp_obj.provider_id,
        claims=bind_resp_obj.claims,
    )


# ---------------------------------------------------------------------------
# GET /bridge/status-list — return current bitstring for revocation checking
# ---------------------------------------------------------------------------

@app.get("/bridge/status-list")
async def get_status_list(http_request: Request) -> dict:
    """Return the bridge's BitstringStatusList in a format the gateway
    status_checker can decode.

    Response shape:
    {
        "list_id": "<uuid>",
        "bitstring": "<base64url-encoded bitstring>",
        "size": 16384
    }
    """
    sl: InMemoryStatusList = http_request.app.state.status_list
    return {
        "list_id": sl.list_id,
        "bitstring": sl.bitstring_b64url(),
        "size": sl.size,
    }


# ---------------------------------------------------------------------------
# POST /bridge/revoke — flip the revocation bit for a credential
# ---------------------------------------------------------------------------

@app.post("/bridge/revoke")
async def revoke_credential(req: RevokeRequest, http_request: Request) -> dict:
    """Revoke a credential by its jti (credential_id).

    The gateway's status_checker will detect the flipped bit on the next
    request that presents this credential, blocking the agent immediately.
    """
    state = http_request.app.state
    sl: InMemoryStatusList = state.status_list
    index_map: dict[str, int] = state.credential_index_map

    if req.credential_id not in index_map:
        raise HTTPException(
            status_code=404,
            detail=f"Credential '{req.credential_id}' not tracked by this bridge",
        )

    index = index_map[req.credential_id]
    sl.revoke(index)

    return {
        "revoked": True,
        "credential_id": req.credential_id,
        "status_list_index": index,
        "list_id": sl.list_id,
    }


# ---------------------------------------------------------------------------
# POST /bridge/shadow-test-vps — build test VPs for browser shadow demo
# ---------------------------------------------------------------------------

class ShadowTestVPsRequest(BaseModel):
    gateway_did: str = Field(default="", description="VP audience (gateway DID)")


@app.post("/bridge/shadow-test-vps")
async def shadow_test_vps(req: ShadowTestVPsRequest) -> dict:
    """Create two shadow-agent test VPs for the React demo's Act 5.

    The browser cannot sign Ed25519 JWTs, so this endpoint creates:
    - ``expired_vp``: a VP with ttl_seconds=1 that is already expired by
      the time the response arrives (enforced by asyncio.sleep(2)).
    - ``no_delegation_vp``: a VP that contains only an AgentCredential
      and no DelegationCredential — rejected by the gateway because
      require_delegation=True.

    These VPs are signed by throwaway one-shot keypairs, so they cannot
    be confused with legitimate credentials.
    """
    audience = req.gateway_did or "did:key:z6MkGatewayShadowTestAudience"

    # --- Expired VP ---
    expired_agent = AgentIdentity.create("ShadowExpiredBot")
    expired_vc = issue_vc(
        issuer=expired_agent,
        subject_did=expired_agent.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShadowExpiredBot"},
        ttl_seconds=60,
    )
    expired_vp = create_presentation(
        holder=expired_agent,
        credentials=[expired_vc],
        audience=audience,
        ttl_seconds=1,
        presentation_type="BlendedIdentityPresentation",
    )
    # Sleep so the 1-second VP is definitely expired before the gateway checks it
    await asyncio.sleep(2)

    # --- No-delegation VP ---
    rogue_agent = AgentIdentity.create("ShadowRogueBot")
    rogue_vc = issue_vc(
        issuer=rogue_agent,
        subject_did=rogue_agent.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShadowRogueBot"},
        ttl_seconds=300,
    )
    no_delegation_vp = create_presentation(
        holder=rogue_agent,
        credentials=[rogue_vc],
        audience=audience,
        ttl_seconds=300,
        presentation_type="BlendedIdentityPresentation",
    )

    return {
        "expired_vp": expired_vp,
        "no_delegation_vp": no_delegation_vp,
    }


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health(http_request: Request) -> dict:
    state = http_request.app.state
    return {
        "status": "healthy",
        "bridge_did": state.bridge_identity.did,
        "providers": list(state.registry.providers.keys()),
        "provider_count": len(state.registry.providers),
        "identity_count": len(state.identity_store),
    }
