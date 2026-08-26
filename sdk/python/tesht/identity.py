from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# ---------------------------------------------------------------------------
# Base58btc encoder/decoder (no external dependency)
# ---------------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_encode(data: bytes) -> str:
    """Base58btc encode. Leading zero bytes become '1' characters."""
    if not data:
        return ""
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r : r + 1])
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _b58_decode(s: str) -> bytes:
    """Base58btc decode."""
    if not s:
        return b""
    n = 0
    for c in s.encode("ascii"):
        n = n * 58 + _B58_ALPHABET.index(c)
    leading_zeros = len(s) - len(s.lstrip("1"))
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * leading_zeros + result


# ---------------------------------------------------------------------------
# Base64url helper (no padding, matching backend/core/did.py)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# DID document context constants
# ---------------------------------------------------------------------------

_DID_CONTEXT_V1 = "https://www.w3.org/ns/did/v1"
_ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"

# Multicodec varint prefix for ed25519-pub
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])


# ---------------------------------------------------------------------------
# did:key encoding helpers
# ---------------------------------------------------------------------------

def _pub_key_to_did_key(pub: Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key as a did:key DID."""
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    multibase_value = _b58_encode(_ED25519_MULTICODEC_PREFIX + pub_raw)
    return f"did:key:z{multibase_value}"


def _pub_key_to_multibase(pub: Ed25519PublicKey) -> str:
    """Return the multibase-encoded public key string (the 'z...' part without 'did:key:')."""
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "z" + _b58_encode(_ED25519_MULTICODEC_PREFIX + pub_raw)


# ---------------------------------------------------------------------------
# DID document builders
# ---------------------------------------------------------------------------

def _build_did_key_document(did: str, pub: Ed25519PublicKey) -> dict[str, Any]:
    """Build a did:key DID document per the W3C did:key specification."""
    multibase = _pub_key_to_multibase(pub)
    kid = f"{did}#{did}"
    return {
        "@context": [_DID_CONTEXT_V1, _ED25519_2020_CONTEXT],
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [kid],
        "assertionMethod": [kid],
    }


def _build_did_web_document(did: str, kid: str, public_jwk: dict[str, Any]) -> dict[str, Any]:
    """Build a did:web DID document matching backend/core/did.py build_did_document_multi."""
    return {
        "@context": [_DID_CONTEXT_V1],
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwk,
            }
        ],
        "authentication": [kid],
        "assertionMethod": [kid],
    }


# ---------------------------------------------------------------------------
# AgentIdentity dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    did: str
    method: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    public_jwk: dict[str, Any]
    kid: str
    _name: str = field(default="", repr=False)
    _domain: Optional[str] = field(default=None, repr=False)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        name: str,
        method: str = "key",
        domain: Optional[str] = None,
    ) -> "AgentIdentity":
        if method not in ("key", "web"):
            raise ValueError(
                f"Unsupported DID method: '{method}'. Use 'key' or 'web'."
            )
        if method == "web" and domain is None:
            raise ValueError("domain is required for did:web method")

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_jwk: dict[str, Any] = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(pub_raw),
        }

        if method == "key":
            did = _pub_key_to_did_key(pub)
            kid = f"{did}#{did}"
            return cls(
                did=did,
                method=method,
                private_key=priv,
                public_key=pub,
                public_jwk=public_jwk,
                kid=kid,
                _name=name,
                _domain=None,
            )

        # method == "web"
        agent_uuid = uuid.uuid4()
        did = f"did:web:{domain}:agents:{agent_uuid}"
        kid = f"{did}#key-1"
        return cls(
            did=did,
            method=method,
            private_key=priv,
            public_key=pub,
            public_jwk=public_jwk,
            kid=kid,
            _name=name,
            _domain=domain,
        )

    @classmethod
    def from_private_key(cls, pem: str, did: str) -> "AgentIdentity":
        """Reconstruct an AgentIdentity from a PEM-encoded private key and a DID."""
        try:
            priv = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Failed to parse PEM private key: {exc}") from exc

        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("PEM key is not an Ed25519 private key")

        pub = priv.public_key()
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_jwk: dict[str, Any] = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(pub_raw),
        }

        if did.startswith("did:key:"):
            derived_did = _pub_key_to_did_key(pub)
            if derived_did != did:
                raise ValueError(
                    f"Private key does not match DID: derived {derived_did}, expected {did}"
                )
            kid = f"{did}#{did}"
            return cls(
                did=did,
                method="key",
                private_key=priv,
                public_key=pub,
                public_jwk=public_jwk,
                kid=kid,
            )

        if did.startswith("did:web:"):
            kid = f"{did}#key-1"
            # Extract domain from did:web:{domain}:agents:{uuid}
            parts = did.split(":")
            domain: Optional[str] = parts[2] if len(parts) >= 3 else None
            return cls(
                did=did,
                method="web",
                private_key=priv,
                public_key=pub,
                public_jwk=public_jwk,
                kid=kid,
                _domain=domain,
            )

        raise ValueError(f"Unsupported DID method in: {did}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentIdentity":
        """Reconstruct an AgentIdentity from a serialized dict."""
        for required_key in ("did", "method", "private_key_pem"):
            if required_key not in data:
                raise ValueError(f"Missing required key in identity dict: '{required_key}'")

        identity = cls.from_private_key(pem=data["private_key_pem"], did=data["did"])
        identity._name = data.get("name", "")
        # Restore domain for did:web if present in dict
        if data.get("domain"):
            identity._domain = data["domain"]
        return identity

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict representation."""
        return {
            "did": self.did,
            "method": self.method,
            "name": self._name,
            "private_key_pem": self.export_private(),
            "domain": self._domain,
        }

    def export_private(self, password: Optional[str] = None) -> str:
        """Export the private key as a PEM string."""
        encryption: serialization.KeySerializationEncryption
        if password is None:
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        ).decode("utf-8")

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def did_document(self) -> dict[str, Any]:
        """Return the DID document for this identity."""
        if self.method == "key":
            return _build_did_key_document(self.did, self.public_key)
        return _build_did_web_document(self.did, self.kid, self.public_jwk)

    @property
    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # ------------------------------------------------------------------
    # Crypto operations
    # ------------------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """Sign data with the private key. Returns a 64-byte Ed25519 signature."""
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature against data. Returns True/False, never raises."""
        try:
            self.public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False


# ---------------------------------------------------------------------------
# Standalone did:key resolver
# ---------------------------------------------------------------------------

def resolve_did_key(did: str) -> dict[str, Any]:
    """Resolve a did:key locally — no network call. Extracts public key from DID string."""
    if not did.startswith("did:key:z"):
        raise ValueError(
            f"Invalid did:key format: must start with 'did:key:z', got '{did[:25]}...'"
        )

    # Strip "did:key:" and then the 'z' multibase prefix
    multibase_value = did[len("did:key:"):]
    b58_value = multibase_value[1:]  # strip leading 'z'

    try:
        decoded = _b58_decode(b58_value)
    except (ValueError, IndexError) as exc:
        raise ValueError(f"Failed to base58btc decode DID fragment: {exc}") from exc

    if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
        if len(decoded) >= 2:
            raise ValueError(
                f"Invalid multicodec prefix: expected [0xed, 0x01], "
                f"got [{decoded[0]:02x}, {decoded[1]:02x}]"
            )
        raise ValueError(
            f"Invalid multicodec prefix: decoded data too short ({len(decoded)} bytes)"
        )

    pub_bytes = decoded[2:]
    if len(pub_bytes) != 32:
        raise ValueError(
            f"Invalid public key length: expected 32 bytes, got {len(pub_bytes)}"
        )

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Failed to reconstruct Ed25519 public key: {exc}") from exc

    return _build_did_key_document(did, pub)
