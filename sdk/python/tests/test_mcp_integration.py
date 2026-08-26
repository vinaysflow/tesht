"""
Tests for tesht.integrations.mcp — MCP authentication middleware.

All 8 tests follow the spec exactly:
  1. test_create_and_verify_auth_roundtrip
  2. test_missing_auth_header
  3. test_invalid_scheme
  4. test_untrusted_issuer
  5. test_trusted_issuer_passes
  6. test_missing_credential_type
  7. test_empty_trusted_issuers_allows_all
  8. test_with_delegation_requirement
"""
import pytest

from tesht.credentials import issue_vc
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity
from tesht.integrations.mcp import MCPAuthConfig, TeshtMCPAuth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def server_identity() -> AgentIdentity:
    return AgentIdentity.create("mcp-server")


@pytest.fixture()
def client_identity() -> AgentIdentity:
    return AgentIdentity.create("mcp-client")


@pytest.fixture()
def issuer_identity() -> AgentIdentity:
    return AgentIdentity.create("trusted-issuer")


def _make_vc(issuer: AgentIdentity, subject_did: str, credential_type: str = "AgentCredential") -> str:
    return issue_vc(
        issuer=issuer,
        subject_did=subject_did,
        credential_type=credential_type,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMCPAuthRoundtrip:
    def test_create_and_verify_auth_roundtrip(
        self, server_identity: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        """Client creates headers; server verifies → authenticated=True."""
        # The issuer can be the client itself (self-issued) — valid for did:key
        vc = _make_vc(client_identity, client_identity.did)

        client_config = MCPAuthConfig(identity=client_identity)
        client_auth = TeshtMCPAuth(client_config)
        headers = client_auth.create_auth_headers(
            credentials=[vc],
            audience=server_identity.did,
        )

        server_config = MCPAuthConfig(identity=server_identity)
        server_auth = TeshtMCPAuth(server_config)
        result = server_auth.verify_request(headers)

        assert result.authenticated is True
        assert result.agent_did == client_identity.did
        assert result.reason is None


class TestMissingOrMalformedHeader:
    def test_missing_auth_header(self, server_identity: AgentIdentity) -> None:
        """Empty headers dict → authenticated=False, reason contains 'Missing Authorization'."""
        auth = TeshtMCPAuth(MCPAuthConfig(identity=server_identity))
        result = auth.verify_request({})

        assert result.authenticated is False
        assert result.reason is not None
        assert "Missing Authorization" in result.reason

    def test_invalid_scheme(self, server_identity: AgentIdentity) -> None:
        """Basic scheme → authenticated=False, reason contains 'scheme'."""
        auth = TeshtMCPAuth(MCPAuthConfig(identity=server_identity))
        result = auth.verify_request({"Authorization": "Basic abc123"})

        assert result.authenticated is False
        assert result.reason is not None
        assert "scheme" in result.reason.lower()


class TestIssuerTrust:
    def test_untrusted_issuer(
        self,
        server_identity: AgentIdentity,
        client_identity: AgentIdentity,
        issuer_identity: AgentIdentity,
    ) -> None:
        """
        Server trusts only "did:key:zTRUSTED"; VC is issued by a different identity.
        → authenticated=False, reason contains 'Untrusted'.
        """
        vc = _make_vc(issuer_identity, client_identity.did)

        client_config = MCPAuthConfig(identity=client_identity)
        client_auth = TeshtMCPAuth(client_config)
        headers = client_auth.create_auth_headers(
            credentials=[vc],
            audience=server_identity.did,
        )

        server_config = MCPAuthConfig(
            identity=server_identity,
            trusted_issuers=["did:key:zTRUSTED"],  # issuer_identity.did not in this list
        )
        server_auth = TeshtMCPAuth(server_config)
        result = server_auth.verify_request(headers)

        assert result.authenticated is False
        assert result.reason is not None
        assert "Untrusted" in result.reason

    def test_trusted_issuer_passes(
        self,
        server_identity: AgentIdentity,
        client_identity: AgentIdentity,
        issuer_identity: AgentIdentity,
    ) -> None:
        """trusted_issuers includes actual issuer DID → authenticated=True."""
        vc = _make_vc(issuer_identity, client_identity.did)

        client_config = MCPAuthConfig(identity=client_identity)
        client_auth = TeshtMCPAuth(client_config)
        headers = client_auth.create_auth_headers(
            credentials=[vc],
            audience=server_identity.did,
        )

        server_config = MCPAuthConfig(
            identity=server_identity,
            trusted_issuers=[issuer_identity.did],
        )
        server_auth = TeshtMCPAuth(server_config)
        result = server_auth.verify_request(headers)

        assert result.authenticated is True

    def test_empty_trusted_issuers_allows_all(
        self,
        server_identity: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        """trusted_issuers=[] (default) → any issuer is accepted."""
        random_issuer = AgentIdentity.create("random-issuer")
        vc = _make_vc(random_issuer, client_identity.did)

        client_config = MCPAuthConfig(identity=client_identity)
        client_auth = TeshtMCPAuth(client_config)
        headers = client_auth.create_auth_headers(
            credentials=[vc],
            audience=server_identity.did,
        )

        # trusted_issuers not set → empty list → all issuers pass
        server_config = MCPAuthConfig(identity=server_identity)
        server_auth = TeshtMCPAuth(server_config)
        result = server_auth.verify_request(headers)

        assert result.authenticated is True


class TestCredentialTypeRequirement:
    def test_missing_credential_type(
        self,
        server_identity: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        """
        Server requires 'AdminCredential'; agent presents 'AgentCredential'.
        → authenticated=False, reason contains 'Missing required'.
        """
        vc = _make_vc(client_identity, client_identity.did, credential_type="AgentCredential")

        client_config = MCPAuthConfig(identity=client_identity)
        client_auth = TeshtMCPAuth(client_config)
        headers = client_auth.create_auth_headers(
            credentials=[vc],
            audience=server_identity.did,
        )

        server_config = MCPAuthConfig(
            identity=server_identity,
            required_credential_types=["AdminCredential"],
        )
        server_auth = TeshtMCPAuth(server_config)
        result = server_auth.verify_request(headers)

        assert result.authenticated is False
        assert result.reason is not None
        assert "Missing required" in result.reason


class TestDelegationRequirement:
    def test_with_delegation_requirement(
        self,
        server_identity: AgentIdentity,
        client_identity: AgentIdentity,
        issuer_identity: AgentIdentity,
    ) -> None:
        """
        Server requires delegation (require_delegation=True).
        Agent presents a DelegationCredential → chain is verified, authenticated=True.
        """
        scope = {"actions": ["read", "write"], "max_amount": 100, "currency": "USD"}
        delegation_vc = issue_delegation(
            delegator=issuer_identity,
            delegate_did=client_identity.did,
            scope=scope,
        )

        client_config = MCPAuthConfig(identity=client_identity)
        client_auth = TeshtMCPAuth(client_config)
        headers = client_auth.create_auth_headers(
            credentials=[delegation_vc],
            audience=server_identity.did,
        )

        server_config = MCPAuthConfig(
            identity=server_identity,
            require_delegation=True,
        )
        server_auth = TeshtMCPAuth(server_config)
        result = server_auth.verify_request(headers)

        assert result.authenticated is True
        assert result.delegation is not None
        assert result.delegation.verified is True
