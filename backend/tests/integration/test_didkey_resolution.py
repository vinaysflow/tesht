"""Functional tests for did:key resolution through backend credential verify.

Tests that the backend can verify offline-issued did:key credentials — the entire
offline-first security model depends on this working.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the Python SDK importable
SDK_PYTHON = Path(__file__).resolve().parents[3] / "sdk" / "python"
sys.path.insert(0, str(SDK_PYTHON))


def test_backend_verifies_didkey_credential(client):
    """A did:key credential issued offline with the Python SDK verifies via the backend API."""
    from tesht.identity import AgentIdentity
    from tesht.credentials import issue_vc

    issuer = AgentIdentity.create("test-issuer", method="key")
    subject = AgentIdentity.create("test-subject", method="key")

    vc = issue_vc(
        issuer=issuer,
        subject_did=subject.did,
        credential_type="TestCredential",
        claims={"role": "tester", "level": 3},
        ttl_seconds=3600,
    )

    r = client.post("/v1/credentials/verify", json={"jwt": vc})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["verified"] is True, f"Verification failed: {data}"


def test_backend_rejects_tampered_didkey_credential(client):
    """A tampered did:key VC is rejected by the backend."""
    import base64
    import json

    from tesht.identity import AgentIdentity
    from tesht.credentials import issue_vc

    issuer = AgentIdentity.create("tamper-issuer", method="key")
    subject = AgentIdentity.create("tamper-subject", method="key")

    vc = issue_vc(issuer, subject.did, "TestCredential", claims={"role": "user"}, ttl_seconds=3600)

    # Tamper the payload
    parts = vc.split(".")
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    payload["vc"]["credentialSubject"]["role"] = "admin"  # escalate
    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    tampered = f"{parts[0]}.{new_payload}.{parts[2]}"

    r = client.post("/v1/credentials/verify", json={"jwt": tampered})
    # Should fail with 400 (signature invalid) or 200 with verified=false
    if r.status_code == 200:
        assert r.json()["verified"] is False
    else:
        assert r.status_code == 400


def test_didkey_resolver_produces_valid_doc(client):
    """Direct unit test: _resolve_did_key returns a valid DID document."""
    from tesht.identity import AgentIdentity
    from core.resolver import _resolve_did_key

    a = AgentIdentity.create("resolver-test", method="key")
    doc = _resolve_did_key(a.did)

    assert doc["id"] == a.did
    assert len(doc["verificationMethod"]) == 1
    vm = doc["verificationMethod"][0]
    assert "publicKeyJwk" in vm
    assert vm["publicKeyJwk"]["crv"] == "Ed25519"
    assert vm["publicKeyJwk"]["kty"] == "OKP"
    assert vm["type"] == "JsonWebKey2020"


def test_didkey_resolver_rejects_invalid_did():
    """_resolve_did_key raises ValueError for malformed DIDs."""
    from core.resolver import _resolve_did_key
    import pytest

    with pytest.raises(ValueError, match="Invalid did:key"):
        _resolve_did_key("did:web:example.com")

    with pytest.raises(ValueError, match="Invalid did:key"):
        _resolve_did_key("did:key:notbase58")
