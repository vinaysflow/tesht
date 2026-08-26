
from core import did as did_core


def test_create_did_format():
    import uuid

    agent_id = uuid.uuid4()
    did = did_core.create_did(agent_id)

    assert did.startswith("did:web:")
    assert ":agents:" in did


def test_did_document_w3c_context_and_structure():
    import uuid

    agent_id = uuid.uuid4()
    did = did_core.create_did(agent_id)
    kid = f"{did}#key-1"
    _, public_jwk, _ = did_core.generate_ed25519_keypair()

    doc = did_core.build_did_document(did=did, kid=kid, public_jwk=public_jwk)

    assert doc.get("@context") == ["https://www.w3.org/ns/did/v1"]
    assert doc.get("id") == did
    assert "verificationMethod" in doc
    assert len(doc["verificationMethod"]) >= 1

    vm = doc["verificationMethod"][0]
    assert vm["id"] == kid
    assert vm["type"] == "JsonWebKey2020"
    assert vm["controller"] == did
    assert "publicKeyJwk" in vm


def test_public_key_from_jwk_roundtrip():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _, public_jwk, _ = did_core.generate_ed25519_keypair()
    pub = did_core.public_key_from_jwk(public_jwk)
    assert isinstance(pub, Ed25519PublicKey)
