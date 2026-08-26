"""Tests for VC issuance, verification, and presentations.

Uses did:key identities throughout — no server dependency.
"""
from __future__ import annotations

import base64
import time

import pytest
import jwt as pyjwt

from tesht.identity import AgentIdentity
from tesht.credentials import (
    issue_vc,
    verify_vc,
    create_presentation,
    verify_presentation,
)


# ─── Fixtures ──────────────────────────────────────────────


@pytest.fixture
def issuer():
    return AgentIdentity.create("test-issuer", method="key")


@pytest.fixture
def subject():
    return AgentIdentity.create("test-subject", method="key")


@pytest.fixture
def holder():
    return AgentIdentity.create("test-holder", method="key")


@pytest.fixture
def verifier():
    return AgentIdentity.create("test-verifier", method="key")


@pytest.fixture
def sample_vc(issuer, subject):
    """A simple valid VC for reuse across tests."""
    return issue_vc(
        issuer=issuer,
        subject_did=subject.did,
        credential_type="CapabilityCredential",
        claims={"capability": "negotiate_contracts", "max_amount": 100000},
        ttl_seconds=3600,
    )


# ─── TestIssueVC ──────────────────────────────────────────


class TestIssueVC:
    def test_returns_valid_jwt_format(self, issuer, subject):
        token = issue_vc(issuer=issuer, subject_did=subject.did)
        segments = token.split(".")
        assert len(segments) == 3, f"JWT should have 3 segments, got {len(segments)}"
        for i, seg in enumerate(segments):
            assert len(seg) > 0, f"Segment {i} is empty"

    def test_jwt_header_fields(self, issuer, subject):
        token = issue_vc(issuer=issuer, subject_did=subject.did)
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "JWT"
        assert header["kid"] == issuer.kid

    def test_jwt_payload_structure(self, issuer, subject):
        token = issue_vc(issuer=issuer, subject_did=subject.did)
        payload = pyjwt.decode(token, options={"verify_signature": False})

        assert payload["iss"] == issuer.did
        assert payload["sub"] == subject.did
        assert "jti" in payload and len(payload["jti"]) > 0
        assert "iat" in payload and isinstance(payload["iat"], int)
        assert "exp" in payload and payload["exp"] == payload["iat"] + 3600

        vc = payload["vc"]
        assert vc["@context"] == ["https://www.w3.org/ns/credentials/v2"]
        assert vc["type"] == ["VerifiableCredential", "AgentCredential"]
        assert vc["issuer"] == issuer.did
        assert "validFrom" in vc
        assert vc["credentialSubject"]["id"] == subject.did

    def test_custom_claims_in_credential_subject(self, issuer, subject):
        token = issue_vc(
            issuer=issuer,
            subject_did=subject.did,
            credential_type="CapabilityCredential",
            claims={"capability": "trade", "limit": 5000},
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        cs = payload["vc"]["credentialSubject"]
        assert cs["capability"] == "trade"
        assert cs["limit"] == 5000
        assert cs["id"] == subject.did

    def test_status_list_included_when_provided(self, issuer, subject):
        token = issue_vc(
            issuer=issuer,
            subject_did=subject.did,
            status_list_url="https://example.com/status/abc-123",
            status_list_index=42,
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        cs_status = payload["vc"]["credentialStatus"]
        assert cs_status["type"] == "BitstringStatusListEntry"
        assert cs_status["statusPurpose"] == "revocation"
        assert cs_status["statusListIndex"] == "42"
        assert cs_status["statusListCredential"] == "https://example.com/status/abc-123"
        assert cs_status["id"] == "https://example.com/status/abc-123#42"

    def test_no_status_list_when_not_provided(self, issuer, subject):
        token = issue_vc(issuer=issuer, subject_did=subject.did)
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert "credentialStatus" not in payload["vc"]

    def test_no_ttl_means_no_exp(self, issuer, subject):
        token = issue_vc(issuer=issuer, subject_did=subject.did, ttl_seconds=None)
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert "exp" not in payload

    def test_custom_credential_id(self, issuer, subject):
        token = issue_vc(
            issuer=issuer, subject_did=subject.did, credential_id="my-custom-jti-123"
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload["jti"] == "my-custom-jti-123"

    def test_validation_empty_subject(self, issuer):
        with pytest.raises(ValueError, match="subject_did is required"):
            issue_vc(issuer=issuer, subject_did="")

    def test_validation_bad_subject_format(self, issuer):
        with pytest.raises(ValueError, match="must start with 'did:'"):
            issue_vc(issuer=issuer, subject_did="not-a-did")

    def test_validation_empty_credential_type(self, issuer, subject):
        with pytest.raises(ValueError, match="credential_type is required"):
            issue_vc(issuer=issuer, subject_did=subject.did, credential_type="")

    def test_validation_negative_ttl(self, issuer, subject):
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            issue_vc(issuer=issuer, subject_did=subject.did, ttl_seconds=-1)


# ─── TestVerifyVC ──────────────────────────────────────────


class TestVerifyVC:
    def test_verify_valid_did_key_credential(self, issuer, subject, sample_vc):
        """Happy path: issue and verify a VC where both parties use did:key."""
        result = verify_vc(sample_vc)

        assert result.verified is True
        assert result.issuer_did == issuer.did
        assert result.subject_did == subject.did
        assert result.credential_type == "CapabilityCredential"
        assert result.claims["capability"] == "negotiate_contracts"
        assert result.claims["max_amount"] == 100000
        assert "id" not in result.claims
        assert result.expired is False
        assert result.revoked is None
        assert result.reason is None

    def test_did_key_needs_no_resolver(self, sample_vc):
        """did:key VCs should verify without providing a resolver callback."""
        result = verify_vc(sample_vc, resolver=None)
        assert result.verified is True

    def test_signature_mismatch_fails(self, issuer, subject):
        """Forge a VC: sign with issuer A's key but claim issuer B's DID."""
        import json as _json

        other_issuer = AgentIdentity.create("other-issuer", method="key")
        token = issue_vc(issuer=issuer, subject_did=subject.did)

        parts = token.split(".")
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        payload = _json.loads(payload_bytes)
        payload["iss"] = other_issuer.did
        payload["vc"]["issuer"] = other_issuer.did
        new_payload_b64 = (
            base64.urlsafe_b64encode(
                _json.dumps(payload, separators=(",", ":")).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        tampered = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

        result = verify_vc(tampered)
        assert result.verified is False
        assert "ignature" in result.reason or "verif" in result.reason.lower()

    def test_expired_vc(self, issuer, subject):
        """Issue with 1-second TTL, wait, verify shows expired."""
        token = issue_vc(issuer=issuer, subject_did=subject.did, ttl_seconds=1)
        time.sleep(2)

        result = verify_vc(token)
        assert result.verified is False
        assert result.expired is True
        assert result.reason == "expired"
        assert result.issuer_did == issuer.did
        assert result.subject_did == subject.did

    def test_status_checker_not_revoked(self, sample_vc):
        """Provide a status checker that says 'not revoked'."""

        def not_revoked(url: str, index: int) -> bool:
            return False

        result = verify_vc(sample_vc, status_checker=not_revoked)
        assert result.verified is True
        assert result.revoked is False

    def test_status_checker_revoked(self, issuer, subject):
        """Provide a status checker that says 'revoked'."""
        token = issue_vc(
            issuer=issuer,
            subject_did=subject.did,
            status_list_url="https://example.com/status/1",
            status_list_index=5,
        )

        def is_revoked(url: str, index: int) -> bool:
            return True

        result = verify_vc(token, status_checker=is_revoked)
        assert result.verified is False
        assert result.revoked is True
        assert result.reason == "revoked"

    def test_did_web_without_resolver(self, subject):
        """did:web issuer without a resolver should fail with clear message."""
        web_issuer = AgentIdentity.create(
            "web-issuer", method="web", domain="example.com"
        )
        token = issue_vc(issuer=web_issuer, subject_did=subject.did)

        result = verify_vc(token, resolver=None)
        assert result.verified is False
        assert "No resolver" in result.reason

    def test_did_web_with_resolver(self, subject):
        """did:web issuer WITH a resolver should work."""
        web_issuer = AgentIdentity.create(
            "web-issuer", method="web", domain="example.com"
        )
        token = issue_vc(issuer=web_issuer, subject_did=subject.did)

        def my_resolver(did: str) -> dict:
            if did == web_issuer.did:
                return web_issuer.did_document
            raise ValueError(f"Unknown DID: {did}")

        result = verify_vc(token, resolver=my_resolver)
        assert result.verified is True
        assert result.issuer_did == web_issuer.did

    def test_garbage_token(self):
        """Completely invalid token string."""
        result = verify_vc("not.a.jwt")
        assert result.verified is False

    def test_two_segment_token(self):
        """Token with only 2 segments."""
        result = verify_vc("only.two")
        assert result.verified is False
        assert "3 segments" in result.reason or "format" in result.reason.lower()


# ─── TestPresentation ──────────────────────────────────────


class TestPresentation:
    def test_roundtrip_single_vc(self, issuer, holder, verifier):
        """Create VP with 1 VC, verify it."""
        vc = issue_vc(issuer=issuer, subject_did=holder.did)
        vp = create_presentation(
            holder=holder, credentials=[vc], audience=verifier.did
        )

        result = verify_presentation(vp, expected_audience=verifier.did)
        assert result.verified is True
        assert result.holder_did == holder.did
        assert len(result.credentials) == 1
        assert result.credentials[0].verified is True

    def test_roundtrip_multiple_vcs(self, holder, verifier):
        """VP with 2 VCs from different issuers."""
        issuer_a = AgentIdentity.create("issuer-a", method="key")
        issuer_b = AgentIdentity.create("issuer-b", method="key")

        vc_a = issue_vc(
            issuer=issuer_a,
            subject_did=holder.did,
            credential_type="CapabilityCredential",
            claims={"capability": "read"},
        )
        vc_b = issue_vc(
            issuer=issuer_b,
            subject_did=holder.did,
            credential_type="MerchantCredential",
            claims={"merchant_id": "M-001"},
        )

        vp = create_presentation(
            holder=holder, credentials=[vc_a, vc_b], audience=verifier.did
        )

        result = verify_presentation(vp, expected_audience=verifier.did)
        assert result.verified is True
        assert len(result.credentials) == 2
        assert result.credentials[0].credential_type == "CapabilityCredential"
        assert result.credentials[1].credential_type == "MerchantCredential"

    def test_wrong_audience_fails(self, issuer, holder, verifier):
        """VP created for verifier A, verified against verifier B."""
        vc = issue_vc(issuer=issuer, subject_did=holder.did)
        other_verifier = AgentIdentity.create("other-verifier", method="key")

        vp = create_presentation(
            holder=holder, credentials=[vc], audience=verifier.did
        )

        result = verify_presentation(vp, expected_audience=other_verifier.did)
        assert result.verified is False
        assert "Audience mismatch" in result.reason

    def test_vp_with_invalid_vc(self, issuer, holder, verifier):
        """VP containing one valid VC and one tampered VC."""
        valid_vc = issue_vc(issuer=issuer, subject_did=holder.did)
        tampered_vc = valid_vc[:-5] + "XXXXX"

        vp = create_presentation(
            holder=holder,
            credentials=[valid_vc, tampered_vc],
            audience=verifier.did,
        )

        result = verify_presentation(vp, expected_audience=verifier.did)
        assert result.verified is False
        assert "Credential 1 failed" in result.reason

    def test_vp_with_nonce(self, issuer, holder, verifier):
        """VP with nonce is included in JWT payload."""
        vc = issue_vc(issuer=issuer, subject_did=holder.did)
        vp = create_presentation(
            holder=holder,
            credentials=[vc],
            audience=verifier.did,
            nonce="random-nonce-123",
        )

        payload = pyjwt.decode(vp, options={"verify_signature": False})
        assert payload["nonce"] == "random-nonce-123"

        result = verify_presentation(vp, expected_audience=verifier.did)
        assert result.verified is True

    def test_create_presentation_empty_credentials(self, holder, verifier):
        with pytest.raises(ValueError, match="cannot be empty"):
            create_presentation(holder=holder, credentials=[], audience=verifier.did)

    def test_create_presentation_invalid_audience(self, holder):
        with pytest.raises(ValueError, match="audience is required"):
            create_presentation(holder=holder, credentials=["fake"], audience="")

    def test_create_presentation_bad_audience_format(self, holder):
        with pytest.raises(ValueError, match="must be a DID"):
            create_presentation(
                holder=holder, credentials=["fake"], audience="not-a-did"
            )


# ─── TestCrossCompatibility ────────────────────────────────


class TestCrossCompatibility:
    """Verify that SDK-issued VCs are structurally compatible with the backend."""

    def test_vc_has_all_required_w3c_fields(self, sample_vc):
        """Verify the VC matches W3C VC 2.0 structure."""
        payload = pyjwt.decode(sample_vc, options={"verify_signature": False})
        vc = payload["vc"]

        assert "@context" in vc
        assert "https://www.w3.org/ns/credentials/v2" in vc["@context"]
        assert "type" in vc
        assert "VerifiableCredential" in vc["type"]
        assert "issuer" in vc
        assert "validFrom" in vc
        assert "credentialSubject" in vc
        assert "id" in vc["credentialSubject"]

    def test_jwt_has_required_header_fields(self, sample_vc):
        """Verify JWT header matches what backend/core/vc.py produces."""
        header = pyjwt.get_unverified_header(sample_vc)
        assert "kid" in header
        assert "typ" in header
        assert header["typ"] == "JWT"
        assert header["alg"] == "EdDSA"

    def test_jwt_has_required_payload_claims(self, sample_vc):
        """Verify JWT payload has all claims that backend verification expects."""
        payload = pyjwt.decode(sample_vc, options={"verify_signature": False})
        for required in ["iss", "sub", "iat", "jti"]:
            assert required in payload, f"Missing required claim: {required}"
