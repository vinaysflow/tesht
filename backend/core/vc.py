from __future__ import annotations

import time
import uuid
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from core.crypto import decrypt_text
from core.did import public_key_from_jwk
from core.db import db_session
from models import Agent, Key

# Algorithms accepted for VC/SVID verification.
# EdDSA = Tesht-issued VCs; RS256/ES256/ES384 = SPIFFE SVIDs and external JWTs.
_SUPPORTED_ALGORITHMS = ["EdDSA", "RS256", "PS256", "ES256", "ES384", "ES512"]


def _now() -> int:
    return int(time.time())


def _public_key_from_jwk_multi(jwk: dict[str, Any]):
    """Load a public key from a JWK. Supports OKP (Ed25519), EC (P-256/P-384/P-521), and RSA."""
    kty = jwk.get("kty")

    if kty == "OKP":
        # Ed25519 — existing implementation
        return public_key_from_jwk(jwk)

    if kty == "EC":
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers,
            SECP256R1, SECP384R1, SECP521R1,
        )
        import base64 as _b64

        crv = jwk.get("crv", "")
        curve_map = {"P-256": SECP256R1(), "P-384": SECP384R1(), "P-521": SECP521R1()}
        curve = curve_map.get(crv)
        if curve is None:
            raise ValueError(f"Unsupported EC curve: {crv!r}")

        def _decode(s: str) -> int:
            padded = s + "=" * ((4 - len(s) % 4) % 4)
            return int.from_bytes(_b64.urlsafe_b64decode(padded), "big")

        x_int = _decode(jwk["x"])
        y_int = _decode(jwk["y"])
        pub_nums = EllipticCurvePublicNumbers(x=x_int, y=y_int, curve=curve)
        return pub_nums.public_key()

    if kty == "RSA":
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers,
        )
        import base64 as _b64

        def _decode_int(s: str) -> int:
            padded = s + "=" * ((4 - len(s) % 4) % 4)
            return int.from_bytes(_b64.urlsafe_b64decode(padded), "big")

        n_int = _decode_int(jwk["n"])
        e_int = _decode_int(jwk["e"])
        return RSAPublicNumbers(e=e_int, n=n_int).public_key()

    raise ValueError(f"Unsupported JWK kty: {kty!r}")


def issue_vc_jwt(
    *,
    issuer_agent_id: uuid.UUID,
    subject_did: str,
    credential_type: str,
    status_list_url: str,
    status_list_index: int,
    ttl_seconds: Optional[int] = None,
    extra_claims: Optional[dict[str, Any]] = None,
) -> tuple[str, str, int, Optional[int]]:
    with db_session() as db:
        agent = db.query(Agent).filter(Agent.id == issuer_agent_id).one()
        key = db.query(Key).filter(Key.agent_id == agent.id).filter(Key.active == True).order_by(Key.created_at.desc()).first()  # noqa: E712
        if not key:
            key = db.query(Key).filter(Key.agent_id == agent.id).order_by(Key.created_at.desc()).first()
        if not key:
            raise ValueError("No key for agent")

    private_pem = decrypt_text(key.private_key_enc)
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)

    jti = str(uuid.uuid4())
    iat = _now()
    exp = iat + ttl_seconds if ttl_seconds else None

    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", credential_type],
        "issuer": agent.did,
        "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(iat)),
        "credentialSubject": {"id": subject_did},
        "credentialStatus": {
            "id": f"{status_list_url}#{status_list_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_list_index),
            "statusListCredential": status_list_url,
        },
    }

    if extra_claims:
        cs = vc.get("credentialSubject") or {}
        cs.update(extra_claims)
        vc["credentialSubject"] = cs

    payload: dict[str, Any] = {
        "iss": agent.did,
        "sub": subject_did,
        "jti": jti,
        "iat": iat,
        "vc": vc,
    }
    if exp:
        payload["exp"] = exp

    token = jwt.encode(payload, key=private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "JWT"})
    return token, jti, iat, exp


def verify_vc_jwt(*, token: str, resolve_did_document: Any, status_check: Any) -> dict[str, Any]:
    """Verify a VC-JWT or SPIFFE SVID JWT.

    Supports EdDSA (Ed25519), RS256/PS256 (RSA), ES256/ES384/ES512 (ECDSA).
    The algorithm is read from the JWT header; no algorithm is assumed.
    """
    # decode header to find kid and algorithm
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    alg = header.get("alg", "EdDSA")

    if alg not in _SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported JWT algorithm: {alg!r}. Supported: {_SUPPORTED_ALGORITHMS}")

    decoded = jwt.decode(token, options={"verify_signature": False})

    issuer = decoded.get("iss")
    if not issuer or not isinstance(issuer, str):
        raise ValueError("Missing iss")

    did_doc = resolve_did_document(issuer)

    # find verification method with matching kid (fallback to first)
    vms = did_doc.get("verificationMethod") or []
    vm = None
    if kid:
        for m in vms:
            if m.get("id") == kid:
                vm = m
                break
    if vm is None and vms:
        vm = vms[0]

    if not vm:
        raise ValueError("No verification method")

    jwk = vm.get("publicKeyJwk")
    pub = _public_key_from_jwk_multi(jwk)

    # For EdDSA, require standard VC claims. For SVID JWTs, only require iss+sub.
    if alg == "EdDSA":
        required_claims = ["iss", "sub", "iat", "jti"]
    else:
        # SPIFFE SVIDs require iss, sub, exp, aud — be permissive on jti/iat
        required_claims = ["iss", "sub"]

    payload = jwt.decode(
        token,
        key=pub,
        algorithms=[alg],
        options={"require": required_claims},
    )

    # status check (may not be present in SVIDs)
    vc = payload.get("vc") or {}
    cs = vc.get("credentialStatus") or {}
    status_list_cred = cs.get("statusListCredential")
    status_list_index = cs.get("statusListIndex")

    status = {"present": False}
    if status_list_cred and status_list_index is not None:
        status["present"] = True
        status["revoked"] = bool(status_check(status_list_cred, int(status_list_index)))

    return {"payload": payload, "status": status}
