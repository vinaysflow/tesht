from __future__ import annotations

import base64

import pytest

from tesht.identity import (
    AgentIdentity,
    _b58_decode,
    _b58_encode,
    resolve_did_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


# ---------------------------------------------------------------------------
# TestBase58 (4 tests)
# ---------------------------------------------------------------------------

class TestBase58:
    def test_encode_known_vector(self):
        # RFC 8032 test vector #1 public key with ed25519-pub multicodec prefix [0xed, 0x01]
        # Correct base58btc encoding verified against canonical base58 library
        data = bytes.fromhex(
            "ed01d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7e21c7a34e0"
        )
        assert _b58_encode(data) == "6MktwupdmLXVVqTzCw4i46r4uGyosGXRmsfabYstcpGo6ib"

    def test_roundtrip_arbitrary(self):
        original = b"\x00\x01\x02\x03hello"
        assert _b58_decode(_b58_encode(original)) == original

    def test_empty(self):
        assert _b58_encode(b"") == ""
        assert _b58_decode("") == b""

    def test_leading_zeros(self):
        data = b"\x00\x00\x01"
        encoded = _b58_encode(data)
        # Two leading zero bytes → two '1' characters
        assert encoded[:2] == "11"


# ---------------------------------------------------------------------------
# TestAgentIdentityCreate (6 tests)
# ---------------------------------------------------------------------------

class TestAgentIdentityCreate:
    def test_create_did_key_format(self):
        identity = AgentIdentity.create("test-agent")
        assert identity.did.startswith("did:key:z6Mk")
        assert identity.method == "key"
        assert identity.kid == f"{identity.did}#{identity.did}"
        assert len(identity.public_key_bytes) == 32

    def test_create_did_web_format(self):
        identity = AgentIdentity.create("web-agent", method="web", domain="example.com")
        assert identity.did.startswith("did:web:example.com:agents:")
        assert identity.method == "web"
        assert identity.kid.endswith("#key-1")

    def test_create_did_web_requires_domain(self):
        with pytest.raises(ValueError, match="domain.*required"):
            AgentIdentity.create("web-agent", method="web")

    def test_create_invalid_method(self):
        with pytest.raises(ValueError, match="Unsupported.*method"):
            AgentIdentity.create("agent", method="ethereum")

    def test_two_identities_differ(self):
        a = AgentIdentity.create("agent-a")
        b = AgentIdentity.create("agent-b")
        assert a.did != b.did
        assert a.public_key_bytes != b.public_key_bytes

    def test_public_jwk_structure(self):
        identity = AgentIdentity.create("jwk-agent")
        jwk = identity.public_jwk
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert len(_b64url_decode(jwk["x"])) == 32


# ---------------------------------------------------------------------------
# TestDIDDocument (4 tests)
# ---------------------------------------------------------------------------

class TestDIDDocument:
    def test_did_key_document_context(self):
        identity = AgentIdentity.create("ctx-agent")
        doc = identity.did_document
        assert doc["@context"] == [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ]

    def test_did_key_document_vm(self):
        identity = AgentIdentity.create("vm-agent")
        doc = identity.did_document
        vm = doc["verificationMethod"][0]
        assert vm["type"] == "Ed25519VerificationKey2020"
        assert "publicKeyMultibase" in vm
        assert vm["publicKeyMultibase"].startswith("z6Mk")

    def test_did_web_document_vm(self):
        identity = AgentIdentity.create("web-vm-agent", method="web", domain="example.com")
        doc = identity.did_document
        vm = doc["verificationMethod"][0]
        assert vm["type"] == "JsonWebKey2020"
        assert vm["publicKeyJwk"]["kty"] == "OKP"

    def test_document_id_matches_did(self):
        identity = AgentIdentity.create("id-agent")
        doc = identity.did_document
        assert doc["id"] == identity.did


# ---------------------------------------------------------------------------
# TestResolveDIDKey (4 tests)
# ---------------------------------------------------------------------------

class TestResolveDIDKey:
    def test_resolve_roundtrip(self):
        identity = AgentIdentity.create("resolve-agent")
        doc = resolve_did_key(identity.did)
        vm = doc["verificationMethod"][0]
        assert vm["controller"] == identity.did

    def test_resolve_invalid_prefix(self):
        with pytest.raises(ValueError, match="must start with"):
            resolve_did_key("did:key:abc")

    def test_resolve_wrong_multicodec(self):
        # Build a DID with [0xee, 0x01] prefix instead of [0xed, 0x01]
        bad_prefix = bytes([0xEE, 0x01]) + bytes(32)
        bad_b58 = _b58_encode(bad_prefix)
        bad_did = f"did:key:z{bad_b58}"
        with pytest.raises(ValueError, match="multicodec prefix"):
            resolve_did_key(bad_did)

    def test_resolve_short_key(self):
        # Build a DID with correct multicodec prefix but only 16 bytes of public key
        short = bytes([0xED, 0x01]) + bytes(16)
        short_b58 = _b58_encode(short)
        short_did = f"did:key:z{short_b58}"
        with pytest.raises(ValueError, match="public key length"):
            resolve_did_key(short_did)


# ---------------------------------------------------------------------------
# TestExportImport (6 tests)
# ---------------------------------------------------------------------------

class TestExportImport:
    def test_roundtrip_pem(self):
        original = AgentIdentity.create("pem-agent")
        pem = original.export_private()
        restored = AgentIdentity.from_private_key(pem, original.did)
        assert restored.did == original.did
        assert restored.public_key_bytes == original.public_key_bytes

    def test_roundtrip_dict(self):
        original = AgentIdentity.create("dict-agent")
        d = original.to_dict()
        restored = AgentIdentity.from_dict(d)
        assert restored.did == original.did
        assert restored.public_key_bytes == original.public_key_bytes
        for expected_key in ("did", "method", "name", "private_key_pem", "domain"):
            assert expected_key in d

    def test_roundtrip_did_web(self):
        original = AgentIdentity.create("web-roundtrip", method="web", domain="myorg.io")
        d = original.to_dict()
        restored = AgentIdentity.from_dict(d)
        assert restored.method == "web"
        assert restored._domain == "myorg.io"
        assert restored.did == original.did

    def test_from_dict_missing_keys(self):
        with pytest.raises(ValueError, match="Missing required key"):
            AgentIdentity.from_dict({"did": "did:key:z6Mk...", "method": "key"})

    def test_from_private_key_wrong_key(self):
        agent_a = AgentIdentity.create("agent-a")
        agent_b = AgentIdentity.create("agent-b")
        pem_b = agent_b.export_private()
        with pytest.raises(ValueError, match="does not match"):
            AgentIdentity.from_private_key(pem_b, agent_a.did)

    def test_encrypted_export(self):
        identity = AgentIdentity.create("encrypted-agent")
        encrypted_pem = identity.export_private(password="test123")
        assert "ENCRYPTED" in encrypted_pem
        # Loading without password raises (the key is encrypted)
        with pytest.raises(Exception):
            AgentIdentity.from_private_key(encrypted_pem, identity.did)


# ---------------------------------------------------------------------------
# TestSignVerify (3 tests)
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_sign_verify_roundtrip(self):
        identity = AgentIdentity.create("sign-agent")
        message = b"hello world"
        signature = identity.sign(message)
        assert len(signature) == 64
        assert identity.verify(signature, message) is True

    def test_verify_wrong_message(self):
        identity = AgentIdentity.create("sign-agent-2")
        signature = identity.sign(b"hello")
        assert identity.verify(signature, b"world") is False

    def test_verify_tampered_signature(self):
        identity = AgentIdentity.create("sign-agent-3")
        message = b"tamper test"
        signature = bytearray(identity.sign(message))
        signature[0] ^= 0xFF  # flip first byte
        assert identity.verify(bytes(signature), message) is False
