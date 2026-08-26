"""
Tests for VP-Based Blended Identity.

Covers:
- create_presentation() TTL + type parameterization
- create_blended_presentation() validation + bundling
- verify_blended_presentation() classification logic
- MCPAuthConfig delegator identity enforcement
- Backward compatibility with existing tests
"""
from __future__ import annotations

import time
import uuid

import jwt as pyjwt
import pytest

from tesht.credentials import (
    BlendedIdentityResult,
    PresentationResult,
    create_blended_presentation,
    create_presentation,
    issue_vc,
    verify_blended_presentation,
    verify_presentation,
)
from tesht.delegation import (
    delegate_further,
    issue_delegation,
    verify_delegation_chain,
)
from tesht.identity import AgentIdentity
from tesht.integrations.mcp import MCPAuthConfig, MCPAuthResult, TeshtMCPAuth


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def idp() -> AgentIdentity:
    return AgentIdentity.create("test-idp")


@pytest.fixture(scope="module")
def human(idp: AgentIdentity) -> tuple[AgentIdentity, str]:
    """Returns (identity, org_role_vc_jwt)."""
    alice = AgentIdentity.create("alice")
    org_vc = issue_vc(
        issuer=idp,
        subject_did=alice.did,
        credential_type="OrganizationalRoleCredential",
        claims={"name": "Alice", "role": "Senior Buyer", "organization": "Acme Corp"},
        ttl_seconds=3600,
    )
    return alice, org_vc


@pytest.fixture(scope="module")
def agent(idp: AgentIdentity) -> tuple[AgentIdentity, str]:
    """Returns (identity, agent_vc_jwt)."""
    bot = AgentIdentity.create("shopping-agent")
    agent_vc = issue_vc(
        issuer=idp,
        subject_did=bot.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShoppingBot", "ownerOrg": "Acme Corp"},
        ttl_seconds=3600,
    )
    return bot, agent_vc


@pytest.fixture(scope="module")
def server() -> AgentIdentity:
    return AgentIdentity.create("mcp-server")


@pytest.fixture(scope="module")
def delegation(human, agent) -> str:
    alice, _ = human
    bot, _ = agent
    return issue_delegation(
        delegator=alice,
        delegate_did=bot.did,
        scope={
            "actions": ["purchase", "browse_products"],
            "max_amount": 50000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": ["electronics"],
        },
        max_depth=3,
        ttl_seconds=3600,
    )


# ---------------------------------------------------------------------------
# 1. create_presentation() parameterization
# ---------------------------------------------------------------------------

class TestCreatePresentationParameterized:
    def test_create_presentation_ttl_parameterized(self, agent, server):
        bot, agent_vc = agent
        vp = create_presentation(
            holder=bot,
            credentials=[agent_vc],
            audience=server.did,
            ttl_seconds=600,
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        assert payload["exp"] == payload["iat"] + 600

    def test_create_presentation_default_ttl_still_300(self, agent, server):
        bot, agent_vc = agent
        vp = create_presentation(
            holder=bot,
            credentials=[agent_vc],
            audience=server.did,
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        assert payload["exp"] == payload["iat"] + 300

    def test_create_presentation_custom_type(self, agent, server):
        bot, agent_vc = agent
        vp = create_presentation(
            holder=bot,
            credentials=[agent_vc],
            audience=server.did,
            presentation_type="BlendedIdentityPresentation",
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        types = payload["vp"]["type"]
        assert "VerifiablePresentation" in types
        assert "BlendedIdentityPresentation" in types

    def test_create_presentation_no_custom_type_keeps_single_type(self, agent, server):
        bot, agent_vc = agent
        vp = create_presentation(
            holder=bot,
            credentials=[agent_vc],
            audience=server.did,
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        assert payload["vp"]["type"] == ["VerifiablePresentation"]


# ---------------------------------------------------------------------------
# 2. create_blended_presentation()
# ---------------------------------------------------------------------------

class TestCreateBlendedPresentation:
    def test_create_blended_presentation_bundles_multiple_vcs(
        self, human, agent, delegation, server
    ):
        alice, org_vc = human
        bot, agent_vc = agent
        vp = create_blended_presentation(
            agent=bot,
            delegation_jwt=delegation,
            delegator_identity_jwt=org_vc,
            additional_credentials=[agent_vc],
            audience=server.did,
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        creds = payload["vp"]["verifiableCredential"]
        assert len(creds) == 3
        assert creds[0] == delegation
        assert creds[1] == org_vc
        assert creds[2] == agent_vc

    def test_create_blended_presentation_delegation_only(
        self, agent, delegation, server
    ):
        bot, _ = agent
        vp = create_blended_presentation(
            agent=bot,
            delegation_jwt=delegation,
            audience=server.did,
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        creds = payload["vp"]["verifiableCredential"]
        assert len(creds) == 1
        assert creds[0] == delegation

    def test_create_blended_presentation_sets_blended_type(
        self, agent, delegation, server
    ):
        bot, _ = agent
        vp = create_blended_presentation(
            agent=bot,
            delegation_jwt=delegation,
            audience=server.did,
        )
        payload = pyjwt.decode(vp, options={"verify_signature": False})
        assert "BlendedIdentityPresentation" in payload["vp"]["type"]

    def test_create_blended_presentation_invalid_delegation_raises(
        self, agent, server, idp
    ):
        bot, _ = agent
        # Issue a plain AgentCredential (not DelegationCredential)
        non_delegation = issue_vc(
            issuer=idp,
            subject_did=bot.did,
            credential_type="AgentCredential",
        )
        with pytest.raises(ValueError, match="DelegationCredential"):
            create_blended_presentation(
                agent=bot,
                delegation_jwt=non_delegation,
                audience=server.did,
            )

    def test_create_blended_presentation_not_a_jwt_raises(self, agent, server):
        bot, _ = agent
        with pytest.raises(ValueError, match="3-segment"):
            create_blended_presentation(
                agent=bot,
                delegation_jwt="not.a.valid.jwt.string",
                audience=server.did,
            )


# ---------------------------------------------------------------------------
# 3. verify_blended_presentation()
# ---------------------------------------------------------------------------

class TestVerifyBlendedPresentation:
    def test_verify_blended_presentation_extracts_both_identities(
        self, human, agent, delegation, server
    ):
        alice, org_vc = human
        bot, agent_vc = agent
        vp = create_blended_presentation(
            agent=bot,
            delegation_jwt=delegation,
            delegator_identity_jwt=org_vc,
            additional_credentials=[agent_vc],
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=server.did)

        assert result.verified is True
        assert result.blended is True
        assert result.agent_did == bot.did
        assert result.delegator_did == alice.did
        assert result.delegator_claims.get("name") == "Alice"
        assert result.delegator_claims.get("role") == "Senior Buyer"
        assert len(result.agent_credentials) == 1
        assert result.agent_credentials[0].credential_type == "AgentCredential"
        assert len(result.delegator_credentials) == 1
        assert result.delegator_credentials[0].credential_type == "OrganizationalRoleCredential"
        assert result.delegation is not None
        assert result.delegation.verified is True
        assert "purchase" in result.effective_scope.get("actions", [])
        assert result.reason is None

    def test_verify_blended_presentation_with_scope_narrowing(
        self, human, agent, server
    ):
        alice, org_vc = human
        bot, agent_vc = agent

        # Root: Alice → bot (broad scope)
        root = issue_delegation(
            delegator=alice,
            delegate_did=bot.did,
            scope={
                "actions": ["purchase", "browse_products", "return"],
                "max_amount": 100000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics", "books"],
            },
            max_depth=2,
            ttl_seconds=3600,
        )
        # Sub: bot → sub-agent (narrowed scope)
        sub_agent = AgentIdentity.create("sub-agent")
        narrowed = delegate_further(
            holder=bot,
            parent_delegation_jwt=root,
            sub_delegate_did=sub_agent.did,
            narrowed_scope={
                "actions": ["browse_products"],
                "max_amount": 5000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["books"],
            },
        )

        vp = create_blended_presentation(
            agent=sub_agent,
            delegation_jwt=narrowed,
            delegator_identity_jwt=org_vc,
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=server.did)

        assert result.verified is True
        assert result.delegation is not None
        assert result.delegation.depth == 2
        # Effective scope should be the most restricted (narrowed)
        assert result.effective_scope.get("max_amount") == 5000
        assert result.effective_scope.get("actions") == ["browse_products"]
        # Root delegator is Alice
        assert result.delegator_did == alice.did

    def test_verify_blended_presentation_expired_delegation_rejected(
        self, human, agent, server
    ):
        alice, org_vc = human
        bot, _ = agent

        # Manually craft an expired delegation JWT
        past = int(time.time()) - 7200
        exp_payload = {
            "iss": alice.did,
            "sub": bot.did,
            "jti": str(uuid.uuid4()),
            "iat": past,
            "exp": past - 60,
            "vc": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DelegationCredential"],
                "issuer": alice.did,
                "validFrom": "2020-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": bot.did,
                    "delegatedBy": alice.did,
                    "delegationScope": {
                        "actions": ["purchase"],
                        "max_amount": 1000,
                        "currency": "USD",
                        "merchants": ["*"],
                        "categories": [],
                    },
                    "delegationDepth": 0,
                    "maxDelegationDepth": 1,
                },
            },
        }
        expired_jwt = pyjwt.encode(
            exp_payload,
            key=alice.private_key,
            algorithm="EdDSA",
            headers={"kid": alice.kid, "typ": "JWT"},
        )

        vp = create_presentation(
            holder=bot,
            credentials=[expired_jwt, org_vc],
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=server.did)

        assert result.verified is False
        assert result.reason is not None

    def test_verify_blended_presentation_audience_mismatch(
        self, agent, delegation, server
    ):
        bot, agent_vc = agent
        other_server = AgentIdentity.create("other-mcp-server")
        vp = create_blended_presentation(
            agent=bot,
            delegation_jwt=delegation,
            additional_credentials=[agent_vc],
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=other_server.did)
        assert result.verified is False
        assert "Audience" in (result.reason or "") or "audience" in (result.reason or "").lower()

    def test_verify_blended_presentation_single_credential_backward_compat(
        self, agent, server, idp
    ):
        """A VP with a single non-delegation VC still verifies; delegation=None."""
        bot, agent_vc = agent
        vp = create_presentation(
            holder=bot,
            credentials=[agent_vc],
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=server.did)
        assert result.verified is True
        assert result.delegation is None
        assert result.delegator_did is None
        assert result.blended is False
        assert len(result.agent_credentials) == 1

    def test_verify_blended_presentation_no_delegation_returns_none_delegator(
        self, human, agent, server, idp
    ):
        alice, org_vc = human
        bot, agent_vc = agent
        # VP with org VC and agent VC but NO delegation credential
        vp = create_presentation(
            holder=bot,
            credentials=[org_vc, agent_vc],
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=server.did)
        assert result.verified is True
        assert result.delegation is None
        assert result.delegator_did is None
        assert result.blended is False

    def test_verify_blended_presentation_nonce_mismatch(
        self, agent, delegation, server
    ):
        bot, _ = agent
        vp = create_blended_presentation(
            agent=bot,
            delegation_jwt=delegation,
            audience=server.did,
            nonce="correct-nonce",
        )
        result = verify_blended_presentation(
            vp,
            expected_audience=server.did,
            expected_nonce="wrong-nonce",
        )
        assert result.verified is False
        assert "Nonce" in (result.reason or "")

    def test_blended_vp_delegation_chain_scope_escalation_rejected(
        self, human, agent, server
    ):
        """
        A child delegation that claims extra actions beyond the parent's scope.

        verify_delegation_chain uses intersect_scopes (W3C behavior) — the
        effective_scope is silently narrowed to the intersection. The blended
        VP verifies, but the effective_scope only contains parent-allowed actions.

        delegate_further enforces scope narrowing at issuance (raises ScopeEscalationError).
        verify_delegation_chain enforces it by intersection at verification time.
        """
        alice, org_vc = human
        bot, _ = agent
        sub = AgentIdentity.create("sub-agent-escalation")

        # Root: Alice → bot  (read:catalog only)
        root = issue_delegation(
            delegator=alice,
            delegate_did=bot.did,
            scope={
                "actions": ["read:catalog"],
                "max_amount": 1000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": [],
            },
            max_depth=2,
            ttl_seconds=3600,
        )

        # delegate_further must raise ScopeEscalationError at issuance time
        from tesht.delegation import ScopeEscalationError
        with pytest.raises(ScopeEscalationError):
            delegate_further(
                holder=bot,
                parent_delegation_jwt=root,
                sub_delegate_did=sub.did,
                narrowed_scope={
                    "actions": ["read:catalog", "delete_account"],  # escalation
                    "max_amount": 1000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": [],
                },
            )

        # Craft the escalated JWT manually (bypasses issuance guard)
        escalated_payload = {
            "iss": bot.did,
            "sub": sub.did,
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "vc": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DelegationCredential"],
                "issuer": bot.did,
                "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "credentialSubject": {
                    "id": sub.did,
                    "delegatedBy": bot.did,
                    "delegationScope": {
                        "actions": ["read:catalog", "delete_account"],
                        "max_amount": 1000,
                        "currency": "USD",
                        "merchants": ["*"],
                        "categories": [],
                    },
                    "delegationDepth": 1,
                    "maxDelegationDepth": 2,
                    "parentDelegation": root,
                },
            },
        }
        escalated_jwt = pyjwt.encode(
            escalated_payload,
            key=bot.private_key,
            algorithm="EdDSA",
            headers={"kid": bot.kid, "typ": "JWT"},
        )

        vp = create_presentation(
            holder=sub,
            credentials=[escalated_jwt, org_vc],
            audience=server.did,
        )
        result = verify_blended_presentation(vp, expected_audience=server.did)

        # verify_delegation_chain uses intersect_scopes (W3C behavior): the claimed
        # "delete_account" action is silently dropped to the intersection.
        # The blended presentation VERIFIES — but effective_scope is narrowed.
        assert result.verified is True
        assert result.delegation is not None
        assert result.delegation.verified is True
        # "delete_account" must NOT appear in effective_scope (parent never allowed it)
        effective_actions = result.effective_scope.get("actions", [])
        assert "delete_account" not in effective_actions
        assert "read:catalog" in effective_actions


# ---------------------------------------------------------------------------
# 4. MCP delegator classification
# ---------------------------------------------------------------------------

class TestMCPDelegatorClassification:
    def _make_blended_headers(
        self,
        agent_identity: AgentIdentity,
        delegation_jwt: str,
        delegator_identity_jwt: str | None,
        server_identity: AgentIdentity,
        extra_creds: list[str] | None = None,
    ) -> dict[str, str]:
        from tesht.credentials import create_presentation as _cp
        creds = [delegation_jwt]
        if delegator_identity_jwt:
            creds.append(delegator_identity_jwt)
        if extra_creds:
            creds.extend(extra_creds)
        vp = _cp(holder=agent_identity, credentials=creds, audience=server_identity.did)
        return {"Authorization": f"Bearer {vp}"}

    def test_mcp_auth_delegator_fields_populated(
        self, human, agent, delegation, server
    ):
        alice, org_vc = human
        bot, agent_vc = agent
        headers = self._make_blended_headers(bot, delegation, org_vc, server, [agent_vc])

        auth = TeshtMCPAuth(MCPAuthConfig(
            identity=server,
            require_delegation=True,
        ))
        result = auth.verify_request(headers)

        assert result.authenticated is True
        assert result.delegator_did == alice.did
        assert result.delegator_claims.get("name") == "Alice"
        assert result.delegator_credential_type == "OrganizationalRoleCredential"
        assert result.blended is True
        assert result.effective_scope.get("max_amount") == 50000

    def test_mcp_auth_delegation_without_identity_vc_delegator_claims_empty(
        self, human, agent, delegation, server
    ):
        alice, _ = human
        bot, _ = agent
        headers = self._make_blended_headers(bot, delegation, None, server)

        auth = TeshtMCPAuth(MCPAuthConfig(
            identity=server,
            require_delegation=True,
        ))
        result = auth.verify_request(headers)

        assert result.authenticated is True
        # delegator_did is NOT set because no identity VC exists for root delegator
        assert result.delegator_did is None
        assert result.delegator_claims == {}
        assert result.blended is False

    def test_mcp_auth_require_delegator_identity_true_no_vc_rejected(
        self, human, agent, delegation, server
    ):
        alice, _ = human
        bot, _ = agent
        headers = self._make_blended_headers(bot, delegation, None, server)

        auth = TeshtMCPAuth(MCPAuthConfig(
            identity=server,
            require_delegation=True,
            require_delegator_identity=True,
        ))
        result = auth.verify_request(headers)

        assert result.authenticated is False
        assert "Delegator identity required" in (result.reason or "")

    def test_mcp_auth_delegator_credential_type_mismatch_rejected(
        self, human, agent, delegation, server
    ):
        alice, org_vc = human
        bot, _ = agent
        headers = self._make_blended_headers(bot, delegation, org_vc, server)

        auth = TeshtMCPAuth(MCPAuthConfig(
            identity=server,
            require_delegation=True,
            require_delegator_identity=True,
            delegator_credential_types=["EnterpriseIdentityCredential"],
        ))
        result = auth.verify_request(headers)

        assert result.authenticated is False
        assert "not in allowed list" in (result.reason or "")
        assert "OrganizationalRoleCredential" in (result.reason or "")

    def test_mcp_auth_delegator_credential_type_matching_passes(
        self, human, agent, delegation, server
    ):
        alice, org_vc = human
        bot, _ = agent
        headers = self._make_blended_headers(bot, delegation, org_vc, server)

        auth = TeshtMCPAuth(MCPAuthConfig(
            identity=server,
            require_delegation=True,
            require_delegator_identity=True,
            delegator_credential_types=["OrganizationalRoleCredential"],
        ))
        result = auth.verify_request(headers)
        assert result.authenticated is True
        assert result.blended is True

    def test_mcp_auth_resolver_passed_through(self, agent, server):
        """did:web issuer verifies when resolver is provided on MCPAuthConfig."""
        bot, _ = agent
        web_issuer = AgentIdentity.create("web-idp", method="web", domain="idp.acme.com")
        web_vc = issue_vc(
            issuer=web_issuer,
            subject_did=bot.did,
            credential_type="AgentCredential",
            claims={"agentName": "bot"},
        )

        from tesht.credentials import create_presentation as _cp
        vp = _cp(holder=bot, credentials=[web_vc], audience=server.did)
        headers = {"Authorization": f"Bearer {vp}"}

        def resolver(did: str) -> dict:
            if did == web_issuer.did:
                return web_issuer.did_document
            raise ValueError(f"Unknown DID: {did}")

        auth = TeshtMCPAuth(MCPAuthConfig(
            identity=server,
            resolver=resolver,
        ))
        result = auth.verify_request(headers)
        assert result.authenticated is True

    def test_mcp_auth_resolver_without_did_web_fails(self, agent, server):
        """did:web issuer fails without resolver (backward compat)."""
        bot, _ = agent
        web_issuer = AgentIdentity.create("web-idp", method="web", domain="idp.acme.com")
        web_vc = issue_vc(
            issuer=web_issuer,
            subject_did=bot.did,
            credential_type="AgentCredential",
            claims={"agentName": "bot"},
        )
        from tesht.credentials import create_presentation as _cp
        vp = _cp(holder=bot, credentials=[web_vc], audience=server.did)
        headers = {"Authorization": f"Bearer {vp}"}

        auth = TeshtMCPAuth(MCPAuthConfig(identity=server))  # no resolver
        result = auth.verify_request(headers)
        assert result.authenticated is False

    def test_mcp_auth_backward_compat_no_delegation(self, agent, server, idp):
        """Existing test pattern still works: simple VC, no delegation."""
        bot, _ = agent
        vc = issue_vc(issuer=idp, subject_did=bot.did, credential_type="AgentCredential")
        from tesht.credentials import create_presentation as _cp
        vp = _cp(holder=bot, credentials=[vc], audience=server.did)
        headers = {"Authorization": f"Bearer {vp}"}

        auth = TeshtMCPAuth(MCPAuthConfig(identity=server))
        result = auth.verify_request(headers)

        assert result.authenticated is True
        assert result.delegation is None
        assert result.delegator_did is None
        assert result.blended is False
        # New fields have sensible defaults
        assert result.delegator_claims == {}
        assert result.effective_scope == {}


# ---------------------------------------------------------------------------
# 5. LangChain integration
# ---------------------------------------------------------------------------

class TestLangChainBlendedHeaders:
    def test_get_blended_auth_headers_returns_bearer(
        self, human, agent, delegation, server
    ):
        alice, org_vc = human
        bot, agent_vc = agent

        from tesht.integrations.langchain import TeshtAgentContext
        ctx = TeshtAgentContext(identity=bot, credentials=[agent_vc])
        headers = ctx.get_blended_auth_headers(
            audience=server.did,
            delegation_jwt=delegation,
            delegator_identity_jwt=org_vc,
        )
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")

        # The returned VP should verify
        vp_jwt = headers["Authorization"].split(" ", 1)[1]
        result = verify_blended_presentation(vp_jwt, expected_audience=server.did)
        assert result.verified is True
        assert result.blended is True

    def test_system_prompt_mentions_blended_when_delegation_held(
        self, human, agent, delegation
    ):
        bot, agent_vc = agent
        from tesht.integrations.langchain import TeshtAgentContext
        ctx = TeshtAgentContext(identity=bot, credentials=[agent_vc, delegation])
        prompt = ctx.get_system_prompt_addition()
        assert "blended" in prompt.lower() or "delegation" in prompt.lower()

    def test_system_prompt_no_blended_mention_without_delegation(
        self, agent
    ):
        bot, agent_vc = agent
        from tesht.integrations.langchain import TeshtAgentContext
        ctx = TeshtAgentContext(identity=bot, credentials=[agent_vc])
        prompt = ctx.get_system_prompt_addition()
        assert "blended" not in prompt.lower() or "get_blended_auth_headers" not in prompt
