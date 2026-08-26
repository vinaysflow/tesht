from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tesht.identity import AgentIdentity, resolve_did_key, _b58_decode

if TYPE_CHECKING:
    from tesht.delegation import DelegationResult


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of verifying a single Verifiable Credential JWT."""
    verified: bool
    payload: dict[str, Any]
    issuer_did: str
    subject_did: str
    credential_type: str
    claims: dict[str, Any]
    expired: bool
    revoked: Optional[bool]
    reason: Optional[str]


@dataclass
class PresentationResult:
    """Result of verifying a Verifiable Presentation JWT."""
    verified: bool
    holder_did: str
    credentials: list[VerificationResult]
    reason: Optional[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_credential_type(payload: dict) -> str:
    """Extract the specific credential type (second element of vc.type array)."""
    vc = payload.get("vc") or {}
    types = vc.get("type") or []
    return types[1] if len(types) > 1 else types[0] if types else ""


def _extract_claims(payload: dict) -> dict[str, Any]:
    """Extract credentialSubject claims, excluding the 'id' field."""
    vc = payload.get("vc") or {}
    cs = vc.get("credentialSubject") or {}
    return {k: v for k, v in cs.items() if k != "id"}


def _fail(reason: str, **kwargs: Any) -> VerificationResult:
    """Shorthand for building a failed VerificationResult with sensible defaults."""
    return VerificationResult(
        verified=False,
        payload=kwargs.get("payload", {}),
        issuer_did=kwargs.get("issuer_did", ""),
        subject_did=kwargs.get("subject_did", ""),
        credential_type=kwargs.get("credential_type", ""),
        claims=kwargs.get("claims", {}),
        expired=kwargs.get("expired", False),
        revoked=kwargs.get("revoked", None),
        reason=reason,
    )


def _resolve_pub_key(vm: dict[str, Any]) -> tuple[Optional[Ed25519PublicKey], Optional[str]]:
    """
    Extract an Ed25519 public key from a verification method dict.
    Returns (key, None) on success or (None, error_reason) on failure.
    Handles both publicKeyJwk (did:web) and publicKeyMultibase (did:key).
    """
    if "publicKeyJwk" in vm:
        jwk = vm["publicKeyJwk"]
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return None, f"Unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}"
        x = jwk.get("x", "")
        padded = x + "=" * ((4 - len(x) % 4) % 4)
        try:
            pub_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            return Ed25519PublicKey.from_public_bytes(pub_bytes), None
        except (ValueError, TypeError) as exc:
            return None, f"Failed to decode publicKeyJwk: {exc}"

    if "publicKeyMultibase" in vm:
        multibase = vm["publicKeyMultibase"]
        if not multibase.startswith("z"):
            return None, "Unsupported multibase prefix"
        try:
            decoded_bytes = _b58_decode(multibase[1:])
        except (ValueError, IndexError) as exc:
            return None, f"Failed to base58 decode publicKeyMultibase: {exc}"
        if len(decoded_bytes) < 2 or decoded_bytes[0] != 0xED or decoded_bytes[1] != 0x01:
            return None, "Invalid multicodec prefix in publicKeyMultibase"
        pub_bytes = decoded_bytes[2:]
        try:
            return Ed25519PublicKey.from_public_bytes(pub_bytes), None
        except (ValueError, TypeError) as exc:
            return None, f"Failed to reconstruct public key from multibase: {exc}"

    return None, "Verification method has neither publicKeyJwk nor publicKeyMultibase"


# ---------------------------------------------------------------------------
# issue_vc
# ---------------------------------------------------------------------------

def issue_vc(
    issuer: AgentIdentity,
    subject_did: str,
    credential_type: str = "AgentCredential",
    claims: Optional[dict[str, Any]] = None,
    ttl_seconds: Optional[int] = 3600,
    credential_id: Optional[str] = None,
    status_list_url: Optional[str] = None,
    status_list_index: Optional[int] = None,
) -> str:
    """Issue a W3C Verifiable Credential as a signed JWT. Compatible with backend/core/vc.py."""
    if not subject_did:
        raise ValueError("subject_did is required")
    if not subject_did.startswith("did:"):
        raise ValueError(f"subject_did must start with 'did:', got '{subject_did[:30]}'")
    if not credential_type:
        raise ValueError("credential_type is required")
    if ttl_seconds is not None and ttl_seconds <= 0:
        raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds}")

    jti = credential_id or str(uuid.uuid4())
    iat = int(time.time())

    vc: dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer.did,
        "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(iat)),
        "credentialSubject": {"id": subject_did, **(claims or {})},
    }

    if status_list_url is not None and status_list_index is not None:
        vc["credentialStatus"] = {
            "id": f"{status_list_url}#{status_list_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_list_index),
            "statusListCredential": status_list_url,
        }

    payload: dict[str, Any] = {
        "iss": issuer.did,
        "sub": subject_did,
        "jti": jti,
        "iat": iat,
        "vc": vc,
    }
    if ttl_seconds is not None:
        payload["exp"] = iat + ttl_seconds

    token = pyjwt.encode(
        payload,
        key=issuer.private_key,
        algorithm="EdDSA",
        headers={"kid": issuer.kid, "typ": "JWT"},
    )
    return token


# ---------------------------------------------------------------------------
# verify_vc
# ---------------------------------------------------------------------------

def verify_vc(
    token: str,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_checker: Optional[Callable[[str, int], bool]] = None,
) -> VerificationResult:
    """Verify a Verifiable Credential JWT. Handles both did:key and did:web issuers."""

    # Step 1: token format
    if token.count(".") != 2:
        return _fail("Invalid JWT format: expected 3 segments")

    # Steps 2-3: decode header + payload (unverified)
    try:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        decoded = pyjwt.decode(token, options={"verify_signature": False})
    except pyjwt.PyJWTError as exc:
        return _fail(f"JWT decode error: {exc}")

    issuer_did = decoded.get("iss", "")
    subject_did = decoded.get("sub", "")
    cred_type = _extract_credential_type(decoded)
    claims = _extract_claims(decoded)

    partial = dict(
        payload=decoded,
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=cred_type,
        claims=claims,
    )

    # Step 4: validate issuer DID
    if not issuer_did or not issuer_did.startswith("did:"):
        return _fail(f"Invalid issuer DID: '{issuer_did}'", **partial)

    # Step 5: resolve DID document
    try:
        if issuer_did.startswith("did:key:"):
            did_doc = resolve_did_key(issuer_did)
        elif resolver is not None:
            did_doc = resolver(issuer_did)
        else:
            return _fail(
                f"No resolver for DID method in '{issuer_did}'. "
                "Provide a resolver callback for non-did:key methods.",
                **partial,
            )
    except (ValueError, TypeError) as exc:
        return _fail(f"DID resolution failed: {exc}", **partial)

    # Step 6: find verification method matching kid
    vms = did_doc.get("verificationMethod") or []
    vm = None
    if kid:
        for m in vms:
            if m.get("id") == kid:
                vm = m
                break
    if vm is None and vms:
        vm = vms[0]
    if vm is None:
        return _fail("No verification method in DID document", **partial)

    # Step 7: extract public key
    pub_key, key_err = _resolve_pub_key(vm)
    if pub_key is None:
        return _fail(key_err or "Failed to extract public key", **partial)

    # Step 8: verify JWT signature
    expired = False
    try:
        verified_payload = pyjwt.decode(
            token,
            key=pub_key,
            algorithms=["EdDSA"],
            options={"require": ["iss", "sub", "iat", "jti"]},
        )
    except pyjwt.ExpiredSignatureError:
        verified_payload = pyjwt.decode(
            token,
            key=pub_key,
            algorithms=["EdDSA"],
            options={"require": ["iss", "sub", "iat", "jti"], "verify_exp": False},
        )
        expired = True
    except pyjwt.InvalidSignatureError:
        return _fail("Signature verification failed", **partial)
    except pyjwt.PyJWTError as exc:
        return _fail(f"JWT verification error: {exc}", **partial)

    # Refresh extracted fields from the now-verified payload
    cred_type = _extract_credential_type(verified_payload)
    claims = _extract_claims(verified_payload)

    # Step 9: check revocation status
    revoked: Optional[bool] = None
    vc = verified_payload.get("vc") or {}
    cs = vc.get("credentialStatus") or {}
    sl_url = cs.get("statusListCredential")
    sl_index = cs.get("statusListIndex")

    if status_checker and sl_url and sl_index is not None:
        try:
            is_revoked = status_checker(sl_url, int(sl_index))
            revoked = is_revoked
            if is_revoked:
                return VerificationResult(
                    verified=False,
                    payload=verified_payload,
                    issuer_did=issuer_did,
                    subject_did=subject_did,
                    credential_type=cred_type,
                    claims=claims,
                    expired=expired,
                    revoked=True,
                    reason="revoked",
                )
        except Exception:
            revoked = None
    elif status_checker:
        revoked = False

    # Step 10: build result
    if expired:
        return VerificationResult(
            verified=False,
            payload=verified_payload,
            issuer_did=issuer_did,
            subject_did=subject_did,
            credential_type=cred_type,
            claims=claims,
            expired=True,
            revoked=revoked,
            reason="expired",
        )

    return VerificationResult(
        verified=True,
        payload=verified_payload,
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=cred_type,
        claims=claims,
        expired=False,
        revoked=revoked,
        reason=None,
    )


# ---------------------------------------------------------------------------
# create_presentation
# ---------------------------------------------------------------------------

def create_presentation(
    holder: AgentIdentity,
    credentials: list[str],
    audience: str,
    nonce: Optional[str] = None,
    ttl_seconds: int = 300,
    presentation_type: Optional[str] = None,
) -> str:
    """Create a W3C Verifiable Presentation as a signed JWT."""
    if not credentials:
        raise ValueError("credentials list cannot be empty")
    if not audience:
        raise ValueError("audience is required")
    if not audience.startswith("did:"):
        raise ValueError(f"audience must be a DID starting with 'did:', got '{audience[:30]}'")

    vp_type = ["VerifiablePresentation"]
    if presentation_type:
        vp_type.append(presentation_type)

    vp = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": vp_type,
        "holder": holder.did,
        "verifiableCredential": credentials,
    }

    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": holder.did,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "vp": vp,
    }
    if nonce is not None:
        payload["nonce"] = nonce

    token = pyjwt.encode(
        payload,
        key=holder.private_key,
        algorithm="EdDSA",
        headers={"kid": holder.kid, "typ": "JWT"},
    )
    return token


# ---------------------------------------------------------------------------
# verify_presentation
# ---------------------------------------------------------------------------

def verify_presentation(
    token: str,
    expected_audience: str,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_checker: Optional[Callable[[str, int], bool]] = None,
    expected_nonce: Optional[str] = None,
) -> PresentationResult:
    """Verify a Verifiable Presentation JWT and each embedded VC."""

    def _pfail(reason: str, holder_did: str = "", creds: Optional[list] = None) -> PresentationResult:
        return PresentationResult(
            verified=False, holder_did=holder_did,
            credentials=creds or [], reason=reason,
        )

    # Step 1: decode header + payload (unverified)
    if token.count(".") != 2:
        return _pfail("Invalid JWT format: expected 3 segments")

    try:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        decoded = pyjwt.decode(token, options={"verify_signature": False})
    except pyjwt.PyJWTError as exc:
        return _pfail(f"JWT decode error: {exc}")

    holder_did = decoded.get("iss", "")

    if not holder_did or not holder_did.startswith("did:"):
        return _pfail(f"Invalid holder DID: '{holder_did}'", holder_did=holder_did)

    # Step 2: resolve holder DID and verify VP signature
    try:
        if holder_did.startswith("did:key:"):
            did_doc = resolve_did_key(holder_did)
        elif resolver is not None:
            did_doc = resolver(holder_did)
        else:
            return _pfail(
                f"No resolver for DID method in '{holder_did}'",
                holder_did=holder_did,
            )
    except (ValueError, TypeError) as exc:
        return _pfail(f"DID resolution failed: {exc}", holder_did=holder_did)

    vms = did_doc.get("verificationMethod") or []
    vm = None
    if kid:
        for m in vms:
            if m.get("id") == kid:
                vm = m
                break
    if vm is None and vms:
        vm = vms[0]
    if vm is None:
        return _pfail("No verification method in holder DID document", holder_did=holder_did)

    pub_key, key_err = _resolve_pub_key(vm)
    if pub_key is None:
        return _pfail(key_err or "Failed to extract holder public key", holder_did=holder_did)

    try:
        verified_payload = pyjwt.decode(
            token,
            key=pub_key,
            algorithms=["EdDSA"],
            audience=expected_audience,
            options={"require": ["iss", "aud", "iat", "jti"]},
        )
    except pyjwt.ExpiredSignatureError:
        return _pfail("Presentation expired", holder_did=holder_did)
    except pyjwt.InvalidAudienceError:
        # Decode again without aud check to extract the actual audience for the error message
        unverified = pyjwt.decode(
            token, key=pub_key, algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
        actual_aud = unverified.get("aud", "")
        return _pfail(
            f"Audience mismatch: expected '{expected_audience}', got '{actual_aud}'",
            holder_did=holder_did,
        )
    except pyjwt.InvalidSignatureError:
        return _pfail("VP signature verification failed", holder_did=holder_did)
    except pyjwt.PyJWTError as exc:
        return _pfail(f"VP JWT verification error: {exc}", holder_did=holder_did)

    # Step 5: nonce validation
    if expected_nonce is not None:
        actual_nonce = verified_payload.get("nonce")
        if actual_nonce != expected_nonce:
            return _pfail(
                f"Nonce mismatch: expected '{expected_nonce}', got '{actual_nonce}'",
                holder_did=holder_did,
            )

    # Step 6: extract and verify each embedded VC
    vp = verified_payload.get("vp") or {}
    vc_jwts = vp.get("verifiableCredential") or []
    if not vc_jwts:
        return _pfail("Presentation contains no credentials", holder_did=holder_did)

    credential_results: list[VerificationResult] = []
    for vc_jwt in vc_jwts:
        vc_result = verify_vc(vc_jwt, resolver=resolver, status_checker=status_checker)
        credential_results.append(vc_result)

    # Step 7: aggregate
    for idx, cr in enumerate(credential_results):
        if not cr.verified:
            return PresentationResult(
                verified=False,
                holder_did=holder_did,
                credentials=credential_results,
                reason=f"Credential {idx} failed: {cr.reason}",
            )

    return PresentationResult(
        verified=True,
        holder_did=holder_did,
        credentials=credential_results,
        reason=None,
    )


# ---------------------------------------------------------------------------
# create_blended_presentation
# ---------------------------------------------------------------------------

def create_blended_presentation(
    agent: AgentIdentity,
    delegation_jwt: str,
    delegator_identity_jwt: Optional[str] = None,
    additional_credentials: Optional[list[str]] = None,
    audience: str = "",
    nonce: Optional[str] = None,
    ttl_seconds: int = 300,
) -> str:
    """
    Create a Blended Identity VP — a VP that bundles a delegation credential
    together with the delegator's identity credential and optional agent credentials.

    Args:
        agent:                  The agent presenting the VP (VP holder + signer).
        delegation_jwt:         A DelegationCredential VC-JWT. Must actually be a
                                DelegationCredential — validated before bundling.
        delegator_identity_jwt: Optional VC-JWT for the delegator's identity
                                (e.g., OrganizationalRoleCredential).
        additional_credentials: Any extra VC-JWTs to bundle (e.g., AgentCredential).
        audience:               Target MCP server's DID.
        nonce:                  Optional replay-protection nonce.
        ttl_seconds:            VP lifetime (default 5 minutes).

    Returns:
        A signed VP-JWT with presentation_type="BlendedIdentityPresentation".

    Raises:
        ValueError: If delegation_jwt is not a valid DelegationCredential.
    """
    # Validate delegation_jwt is actually a DelegationCredential
    if delegation_jwt.count(".") != 2:
        raise ValueError("delegation_jwt must be a 3-segment JWT")
    try:
        delegation_payload = pyjwt.decode(
            delegation_jwt, options={"verify_signature": False}
        )
        vc_claim = delegation_payload.get("vc") or {}
        vc_types = vc_claim.get("type") or []
        if "DelegationCredential" not in vc_types:
            raise ValueError(
                f"delegation_jwt must contain a DelegationCredential; "
                f"got types: {vc_types}"
            )
    except pyjwt.PyJWTError as exc:
        raise ValueError(f"delegation_jwt is not a valid JWT: {exc}") from exc

    credentials: list[str] = [delegation_jwt]
    if delegator_identity_jwt is not None:
        credentials.append(delegator_identity_jwt)
    if additional_credentials:
        credentials.extend(additional_credentials)

    return create_presentation(
        holder=agent,
        credentials=credentials,
        audience=audience,
        nonce=nonce,
        ttl_seconds=ttl_seconds,
        presentation_type="BlendedIdentityPresentation",
    )


# ---------------------------------------------------------------------------
# BlendedIdentityResult
# ---------------------------------------------------------------------------

@dataclass
class BlendedIdentityResult:
    """
    Result of verifying a Blended Identity VP.

    Classifies each embedded credential as belonging to the agent, the delegator,
    or the delegation chain itself, and walks the full delegation chain to compute
    the effective scope.
    """
    verified: bool
    presentation: PresentationResult
    agent_did: str
    agent_credentials: list[VerificationResult]
    delegator_did: Optional[str]
    delegator_claims: dict[str, Any]
    delegator_credentials: list[VerificationResult]
    delegation: Optional[DelegationResult]
    effective_scope: dict[str, Any]
    blended: bool
    reason: Optional[str]


# ---------------------------------------------------------------------------
# verify_blended_presentation
# ---------------------------------------------------------------------------

def verify_blended_presentation(
    token: str,
    expected_audience: str,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_checker: Optional[Callable[[str, int], bool]] = None,
    expected_nonce: Optional[str] = None,
) -> BlendedIdentityResult:
    """
    Verify a Blended Identity VP and classify its embedded credentials.

    Performs two layers of verification:
    1. ``verify_presentation()`` — verifies the VP's outer signature, audience,
       nonce, and each embedded VC's individual signature + expiry + revocation.
    2. ``verify_delegation_chain()`` — walks the full delegation chain recursively,
       verifying scope narrowing, depth limits, and parent delegation integrity.

    Returns a BlendedIdentityResult with:
    - agent_did / agent_credentials  — the VP holder and their own VCs
    - delegator_did / delegator_claims — the root human who initiated the delegation
    - delegation / effective_scope — full chain + most-restrictive combined scope
    - blended=True when both delegation and delegator identity VCs are present
    """
    # Lazy import to avoid circular dependency (delegation imports credentials)
    from tesht.delegation import verify_delegation_chain as _verify_chain

    def _bfail(reason: str, pres: Optional[PresentationResult] = None) -> BlendedIdentityResult:
        return BlendedIdentityResult(
            verified=False,
            presentation=pres or PresentationResult(
                verified=False, holder_did="", credentials=[], reason=reason
            ),
            agent_did="",
            agent_credentials=[],
            delegator_did=None,
            delegator_claims={},
            delegator_credentials=[],
            delegation=None,
            effective_scope={},
            blended=False,
            reason=reason,
        )

    # ── Layer 1: VP + embedded VC signature verification ──────────────────
    pres = verify_presentation(
        token,
        expected_audience=expected_audience,
        resolver=resolver,
        status_checker=status_checker,
        expected_nonce=expected_nonce,
    )
    if not pres.verified:
        return _bfail(pres.reason or "VP verification failed", pres)

    agent_did = pres.holder_did
    credential_results = pres.credentials

    # ── Layer 2: find DelegationCredential + walk full chain ──────────────
    delegation_jwt: Optional[str] = None
    delegation_result: Optional[DelegationResult] = None

    # Extract the raw VP payload to get the original VC-JWT strings
    try:
        vp_payload = pyjwt.decode(token, options={"verify_signature": False})
        vc_jwts: list[str] = (vp_payload.get("vp") or {}).get("verifiableCredential") or []
    except pyjwt.PyJWTError:
        vc_jwts = []

    # Match each verified VerificationResult to its raw JWT string
    _vc_jwt_by_sub_iss: dict[tuple[str, str], str] = {}
    for raw_jwt in vc_jwts:
        try:
            p = pyjwt.decode(raw_jwt, options={"verify_signature": False})
            key = (p.get("sub", ""), p.get("iss", ""))
            _vc_jwt_by_sub_iss[key] = raw_jwt
        except pyjwt.PyJWTError:
            pass

    for cr in credential_results:
        if cr.credential_type == "DelegationCredential":
            raw = _vc_jwt_by_sub_iss.get((cr.subject_did, cr.issuer_did))
            if raw:
                delegation_jwt = raw
            break

    if delegation_jwt:
        delegation_result = _verify_chain(
            delegation_jwt,
            resolver=resolver,
            status_checker=status_checker,
        )
        if not delegation_result.verified:
            return _bfail(
                f"Delegation chain invalid: {delegation_result.reason}",
                pres,
            )

    # ── Classify credentials by role ──────────────────────────────────────
    root_delegator_did: Optional[str] = None
    if delegation_result and delegation_result.chain:
        root_delegator_did = delegation_result.chain[0]["delegator"]

    agent_credentials: list[VerificationResult] = []
    delegator_credentials: list[VerificationResult] = []

    for cr in credential_results:
        if cr.credential_type == "DelegationCredential":
            # Delegation VC is neither agent nor delegator identity — skip
            continue
        if root_delegator_did and cr.subject_did == root_delegator_did:
            delegator_credentials.append(cr)
        else:
            agent_credentials.append(cr)

    delegator_claims: dict[str, Any] = {}
    if delegator_credentials:
        delegator_claims = delegator_credentials[0].claims

    effective_scope = (
        delegation_result.effective_scope
        if delegation_result
        else {}
    )
    blended = bool(delegation_result and delegator_credentials)

    return BlendedIdentityResult(
        verified=True,
        presentation=pres,
        agent_did=agent_did,
        agent_credentials=agent_credentials,
        delegator_did=root_delegator_did,
        delegator_claims=delegator_claims,
        delegator_credentials=delegator_credentials,
        delegation=delegation_result,
        effective_scope=effective_scope,
        blended=blended,
        reason=None,
    )
