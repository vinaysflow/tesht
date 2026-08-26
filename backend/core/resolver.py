from __future__ import annotations

import base64
import logging
import threading
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import unquote

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.db import db_session
from core.did import build_did_document_multi
from core.settings import settings
from models import Agent, Key

logger = logging.getLogger(__name__)

# Thread-safe LRU cache for DID documents.
# Entry format: {did: (document_dict, cached_at_timestamp)}
_cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
_cache_lock = threading.Lock()


def flush_cache() -> None:
    """Clear all cached DID documents."""
    with _cache_lock:
        _cache.clear()
    logger.debug("DID resolution cache flushed")


def _cache_get(did: str) -> dict[str, Any] | None:
    with _cache_lock:
        if did not in _cache:
            logger.debug("DID cache miss: %s", did)
            return None
        doc, cached_at = _cache[did]
        age = time.monotonic() - cached_at
        if age > settings.did_cache_ttl_seconds:
            del _cache[did]
            logger.debug("DID cache expired (age=%.1fs): %s", age, did)
            return None
        # Move to end (most-recently-used)
        _cache.move_to_end(did)
        logger.debug("DID cache hit (age=%.1fs): %s", age, did)
        return doc


def _cache_set(did: str, doc: dict[str, Any]) -> None:
    with _cache_lock:
        if did in _cache:
            _cache.move_to_end(did)
        _cache[did] = (doc, time.monotonic())
        # Evict oldest entries when over max size
        while len(_cache) > settings.did_cache_max_size:
            evicted = next(iter(_cache))
            del _cache[evicted]
            logger.debug("DID cache evicted (LRU): %s", evicted)


def _b58_decode(s: str) -> bytes:
    """Decode a base58btc-encoded string to bytes."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for char in s:
        if char not in ALPHABET:
            raise ValueError(f"Invalid base58 character: '{char}'")
        n = n * 58 + ALPHABET.index(char)
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    # Leading '1' chars = leading zero bytes
    for char in s:
        if char == "1":
            result.append(0)
        else:
            break
    return bytes(reversed(result))


def _resolve_did_key(did: str) -> dict[str, Any]:
    """Resolve a did:key locally — pure computation, no network call."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: must start with 'did:key:z', got '{did[:25]}'")

    multibase_value = did[len("did:key:"):]
    b58_value = multibase_value[1:]  # strip leading 'z' (base58btc prefix)

    try:
        decoded = _b58_decode(b58_value)
    except (ValueError, IndexError) as exc:
        raise ValueError(f"Failed to base58btc decode DID fragment: {exc}") from exc

    if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
        raise ValueError(
            f"Invalid multicodec prefix: expected [0xed, 0x01], got [{decoded[0] if decoded else 'empty'}...]"
        )

    pub_bytes = decoded[2:]
    if len(pub_bytes) != 32:
        raise ValueError(f"Invalid public key length: expected 32 bytes, got {len(pub_bytes)}")

    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    pub_raw = pub.public_bytes_raw()

    vm_id = f"{did}#{multibase_value}"
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub_raw)}

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }


def did_web_to_url(did: str) -> str:
    # did:web:<domain>[:path...]
    if not did.startswith("did:web:"):
        raise ValueError("Only did:web supported")

    parts = did.split(":")
    if len(parts) < 3:
        raise ValueError("Invalid did:web")

    # Domain in did:web may be percent-encoded (e.g. localhost%3A8000)
    domain = unquote(parts[2])
    path_segments = [unquote(p) for p in parts[3:]]

    if not path_segments:
        return f"{settings.tesht_scheme}://{domain}/.well-known/did.json"

    path = "/".join(path_segments)
    return f"{settings.tesht_scheme}://{domain}/{path}/did.json"


def _resolve_local_did(did: str) -> dict[str, Any] | None:
    # If the DID domain matches this service, resolve from DB rather than HTTP.
    if not did.startswith("did:web:"):
        return None

    parts = did.split(":")
    if len(parts) < 3:
        return None

    did_domain = parts[2]
    if did_domain != settings.tesht_domain:
        return None

    with db_session() as db:
        agent = db.query(Agent).filter(Agent.did == did).one_or_none()
        if agent is None:
            return None
        keys = (
            db.query(Key)
            .filter(Key.agent_id == agent.id)
            .order_by(Key.created_at.asc())
            .all()
        )
        if not keys:
            return None

    return build_did_document_multi(did=agent.did, keys=[{"kid": k.kid, "public_jwk": k.public_jwk} for k in keys])


def _resolve_spiffe_id(spiffe_id: str) -> dict[str, Any] | None:
    """Bridge-mode SPIFFE resolution: look up agent by spiffe_id, return DID document.

    If the agent has a known DID keypair, we reconstruct a DID document from it
    so downstream JWT verification can use the stored Ed25519 public key.

    In production, this would be extended to call the SPIRE Workload API over a
    Unix socket to fetch the actual SVID and extract the public key.
    """
    try:
        with db_session() as db:
            agent = db.query(Agent).filter(Agent.spiffe_id == spiffe_id).one_or_none()
            if agent is None:
                return None
            keys = (
                db.query(Key)
                .filter(Key.agent_id == agent.id)
                .order_by(Key.created_at.asc())
                .all()
            )
            if not keys:
                return None

        # Build a synthetic DID document using the agent's stored keys.
        # The document id is the SPIFFE URI; verification methods reference the DID keys.
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": spiffe_id,
            "alsoKnownAs": [agent.did],
            "verificationMethod": [
                {
                    "id": k.kid,
                    "type": "JsonWebKey2020",
                    "controller": spiffe_id,
                    "publicKeyJwk": k.public_jwk,
                }
                for k in keys
            ],
            "authentication": [k.kid for k in keys],
            "assertionMethod": [k.kid for k in keys],
        }
    except Exception:
        return None


def resolve_did(did: str) -> dict[str, Any]:
    # SPIFFE URI: resolve via bridge-mode DB lookup
    if did.startswith("spiffe://"):
        doc = _resolve_spiffe_id(did)
        if doc is not None:
            return doc
        raise ValueError(f"SPIFFE ID not found in Tesht registry: {did!r}")

    # did:key is pure computation — no cache needed, always consistent
    if did.startswith("did:key:"):
        return _resolve_did_key(did)

    # Local DIDs (same domain, resolved from DB) are not cached — always fresh.
    local = _resolve_local_did(did)
    if local is not None:
        return local

    cached = _cache_get(did)
    if cached is not None:
        return cached

    url = did_web_to_url(did)
    r = httpx.get(url, timeout=10.0, headers={"accept": "application/json"})
    r.raise_for_status()
    doc = r.json()
    _cache_set(did, doc)
    return doc
