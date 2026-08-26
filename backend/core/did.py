from __future__ import annotations

import base64
import uuid
from typing import Any
from urllib.parse import unquote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.settings import settings

DID_CONTEXT = "https://www.w3.org/ns/did/v1"

# ---------------------------------------------------------------------------
# SPIFFE ID support
# ---------------------------------------------------------------------------

def parse_spiffe_id(uri: str) -> tuple[str, str]:
    """Parse a SPIFFE ID into (trust_domain, workload_path).

    Example: spiffe://acme.corp/ns/prod/sa/billing-agent
    -> ("acme.corp", "/ns/prod/sa/billing-agent")
    """
    if not uri.startswith("spiffe://"):
        raise ValueError(f"Not a SPIFFE ID: {uri!r}")
    remainder = uri[len("spiffe://"):]
    slash = remainder.find("/")
    if slash == -1:
        return remainder, "/"
    return remainder[:slash], remainder[slash:]


def is_spiffe_id(identifier: str) -> bool:
    """Return True if the identifier is a SPIFFE URI."""
    return identifier.startswith("spiffe://")


def create_spiffe_id(trust_domain: str, workload_path: str) -> str:
    """Construct a canonical SPIFFE URI."""
    if not workload_path.startswith("/"):
        workload_path = "/" + workload_path
    return f"spiffe://{trust_domain}{workload_path}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def domain_decoded() -> str:
    return unquote(settings.tesht_domain)


def create_did(agent_id: uuid.UUID) -> str:
    return f"did:web:{settings.tesht_domain}:agents:{agent_id}"


def generate_ed25519_keypair() -> tuple[str, dict[str, Any], str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(pub_raw)}

    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return private_pem, public_jwk, "Ed25519"


def build_did_document(did: str, kid: str, public_jwk: dict[str, Any]) -> dict[str, Any]:
    return build_did_document_multi(did=did, keys=[{"kid": kid, "public_jwk": public_jwk}])


def build_did_document_multi(*, did: str, keys: list[dict[str, Any]]) -> dict[str, Any]:
    vms = []
    key_ids = []
    for k in keys:
        kid = k.get('kid')
        jwk = k.get('public_jwk')
        if not isinstance(kid, str) or not isinstance(jwk, dict):
            continue
        key_ids.append(kid)
        vms.append({
            "id": kid,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk,
        })

    return {
        "@context": [DID_CONTEXT],
        "id": did,
        "verificationMethod": vms,
        "authentication": key_ids,
        "assertionMethod": key_ids,
    }


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("Unsupported JWK")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("Invalid JWK")
    padded = x + "=" * ((4 - len(x) % 4) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)
