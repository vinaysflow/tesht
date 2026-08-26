"""Shared fixtures for gateway tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tesht.credentials import create_blended_presentation, create_presentation, issue_vc
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity

from gateway.config import GatewayConfig, TrustConfig, UpstreamServer, AuthSettings


@pytest.fixture(scope="module")
def idp() -> AgentIdentity:
    return AgentIdentity.create("test-idp")


@pytest.fixture(scope="module")
def alice(idp) -> tuple[AgentIdentity, str]:
    a = AgentIdentity.create("alice")
    vc = issue_vc(
        issuer=idp, subject_did=a.did,
        credential_type="OrganizationalRoleCredential",
        claims={"name": "Alice", "role": "Buyer", "organization": "Acme"},
        ttl_seconds=3600,
    )
    return a, vc


@pytest.fixture(scope="module")
def bot(idp) -> tuple[AgentIdentity, str]:
    b = AgentIdentity.create("bot")
    vc = issue_vc(
        issuer=idp, subject_did=b.did,
        credential_type="AgentCredential",
        claims={"agentName": "ShopBot", "ownerOrg": "Acme"},
        ttl_seconds=3600,
    )
    return b, vc


@pytest.fixture(scope="module")
def gateway_identity() -> AgentIdentity:
    return AgentIdentity.create("gateway")


@pytest.fixture(scope="module")
def delegation(alice, bot) -> str:
    a, _ = alice
    b, _ = bot
    return issue_delegation(
        delegator=a, delegate_did=b.did,
        scope={
            "actions": ["read_data", "write_data"],
            "max_amount": 50000, "currency": "USD",
            "merchants": ["*"], "categories": [],
        },
        max_depth=2, ttl_seconds=3600,
    )


@pytest.fixture(scope="module")
def blended_vp(alice, bot, delegation, gateway_identity) -> str:
    _, alice_vc = alice
    b, agent_vc = bot
    return create_blended_presentation(
        agent=b, delegation_jwt=delegation,
        delegator_identity_jwt=alice_vc,
        additional_credentials=[agent_vc],
        audience=gateway_identity.did,
    )


@pytest.fixture(scope="module")
def rogue_vp(gateway_identity) -> str:
    rogue = AgentIdentity.create("rogue")
    vc = issue_vc(
        issuer=rogue, subject_did=rogue.did,
        credential_type="AgentCredential",
        claims={"agentName": "RogueBot"},
    )
    return create_presentation(
        holder=rogue, credentials=[vc],
        audience=gateway_identity.did,
    )


@pytest.fixture(scope="module")
def gateway_config() -> GatewayConfig:
    return GatewayConfig(
        upstream_servers={
            "mock_database": UpstreamServer(
                name="mock_database",
                url="http://localhost:9100/mcp",
                auth_type="api_key",
                credential="secret-key",
                credential_header="X-API-Key",
                tool_scope_mapping={
                    "query_database": "read_data",
                    "insert_record": "write_data",
                    "delete_record": "admin",
                },
            ),
        },
        trust=TrustConfig(allow_threshold=75, step_up_threshold=50),
        auth=AuthSettings(
            require_delegation=True,
            require_delegator_identity=True,
        ),
    )
