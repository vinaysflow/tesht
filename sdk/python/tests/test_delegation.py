"""Tests for delegation chains: scope narrowing, depth limits, chain verification."""
from __future__ import annotations

import time

import pytest

from tesht.identity import AgentIdentity
from tesht.delegation import (
    ScopeEscalationError,
    DelegationResult,
    validate_scope_narrowing,
    intersect_scopes,
    issue_delegation,
    delegate_further,
    verify_delegation_chain,
)


# ─── Fixtures ──────────────────────────────────────────────


@pytest.fixture
def agent_a():
    return AgentIdentity.create("agent-a", method="key")


@pytest.fixture
def agent_b():
    return AgentIdentity.create("agent-b", method="key")


@pytest.fixture
def agent_c():
    return AgentIdentity.create("agent-c", method="key")


@pytest.fixture
def agent_d():
    return AgentIdentity.create("agent-d", method="key")


@pytest.fixture
def full_scope():
    return {
        "actions": ["negotiate", "purchase"],
        "max_amount": 10000,
        "currency": "USD",
        "merchants": ["*"],
        "categories": ["electronics", "office"],
        "constraints": {},
    }


# ─── TestScopeIntersection ────────────────────────────────


class TestScopeIntersection:
    def test_actions_intersection(self):
        parent = {"actions": ["negotiate", "purchase"], "max_amount": 10000,
                  "currency": "USD", "merchants": ["*"], "categories": ["electronics"]}
        child = {"actions": ["purchase", "view"], "max_amount": 5000,
                 "currency": "USD", "merchants": ["*"], "categories": ["electronics"]}

        # validate_scope_narrowing should fail because "view" is not in parent
        with pytest.raises(ScopeEscalationError, match="actions"):
            validate_scope_narrowing(parent, child)

        # With a valid child, intersection works
        valid_child = {"actions": ["purchase"], "max_amount": 5000,
                       "currency": "USD", "merchants": ["*"], "categories": ["electronics"]}
        validate_scope_narrowing(parent, valid_child)
        effective = intersect_scopes(parent, valid_child)
        assert effective["actions"] == ["purchase"]

    def test_amount_minimum(self):
        parent = {"actions": ["purchase"], "max_amount": 10000,
                  "currency": "USD", "merchants": ["*"], "categories": []}
        child_ok = {"actions": ["purchase"], "max_amount": 5000,
                    "currency": "USD", "merchants": ["*"], "categories": []}
        child_bad = {"actions": ["purchase"], "max_amount": 15000,
                     "currency": "USD", "merchants": ["*"], "categories": []}

        validate_scope_narrowing(parent, child_ok)
        effective = intersect_scopes(parent, child_ok)
        assert effective["max_amount"] == 5000

        with pytest.raises(ScopeEscalationError, match="max_amount"):
            validate_scope_narrowing(parent, child_bad)

    def test_merchants_narrowing(self):
        parent_star = {"actions": ["purchase"], "max_amount": 10000,
                       "currency": "USD", "merchants": ["*"], "categories": []}
        child_specific = {"actions": ["purchase"], "max_amount": 5000,
                          "currency": "USD", "merchants": ["did:web:acme"], "categories": []}

        validate_scope_narrowing(parent_star, child_specific)
        effective = intersect_scopes(parent_star, child_specific)
        assert effective["merchants"] == ["did:web:acme"]

        parent_acme = {"actions": ["purchase"], "max_amount": 10000,
                       "currency": "USD", "merchants": ["did:web:acme"], "categories": []}
        child_beta = {"actions": ["purchase"], "max_amount": 5000,
                      "currency": "USD", "merchants": ["did:web:beta"], "categories": []}

        with pytest.raises(ScopeEscalationError, match="merchants"):
            validate_scope_narrowing(parent_acme, child_beta)

    def test_currency_mismatch(self):
        parent = {"actions": ["purchase"], "max_amount": 10000,
                  "currency": "USD", "merchants": ["*"], "categories": []}
        child = {"actions": ["purchase"], "max_amount": 5000,
                 "currency": "EUR", "merchants": ["*"], "categories": []}

        with pytest.raises(ScopeEscalationError, match="currency"):
            validate_scope_narrowing(parent, child)


# ─── TestDelegation ────────────────────────────────────────


class TestDelegation:
    def test_simple_delegation(self, agent_a, agent_b, full_scope):
        """A delegates to B. Verify chain. depth=1, effective_scope matches."""
        token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=full_scope,
            max_depth=2,
        )

        result = verify_delegation_chain(token)
        assert result.verified is True
        assert result.depth == 1
        assert result.chain[0]["delegator"] == agent_a.did
        assert result.chain[0]["delegate"] == agent_b.did
        assert set(result.effective_scope["actions"]) == {"negotiate", "purchase"}
        assert result.effective_scope["max_amount"] == 10000

    def test_two_level_chain(self, agent_a, agent_b, agent_c, full_scope):
        """A -> B -> C. Verify C's credential. Chain has 2 entries."""
        ab_token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=full_scope,
            max_depth=3,
        )

        narrowed = {
            "actions": ["purchase"],
            "max_amount": 5000,
            "currency": "USD",
            "merchants": ["did:web:acme"],
            "categories": ["electronics"],
            "constraints": {},
        }
        bc_token = delegate_further(
            holder=agent_b,
            parent_delegation_jwt=ab_token,
            sub_delegate_did=agent_c.did,
            narrowed_scope=narrowed,
        )

        result = verify_delegation_chain(bc_token)
        assert result.verified is True
        assert result.depth == 2
        assert result.chain[0]["delegator"] == agent_a.did
        assert result.chain[1]["delegator"] == agent_b.did

    def test_scope_narrows_through_chain(self, agent_a, agent_b, agent_c, full_scope):
        """A gives broad scope to B; B narrows for C. Effective scope is narrowest."""
        ab_token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=full_scope,
            max_depth=3,
        )

        narrowed = {
            "actions": ["purchase"],
            "max_amount": 5000,
            "currency": "USD",
            "merchants": ["did:web:acme"],
            "categories": ["electronics"],
            "constraints": {},
        }
        bc_token = delegate_further(
            holder=agent_b,
            parent_delegation_jwt=ab_token,
            sub_delegate_did=agent_c.did,
            narrowed_scope=narrowed,
        )

        result = verify_delegation_chain(bc_token)
        assert result.verified is True
        assert result.effective_scope["actions"] == ["purchase"]
        assert result.effective_scope["max_amount"] == 5000
        assert result.effective_scope["merchants"] == ["did:web:acme"]

    def test_escalation_blocked_actions(self, agent_a, agent_b, agent_c):
        """B tries to escalate actions beyond what A granted."""
        scope_a = {
            "actions": ["purchase"],
            "max_amount": 10000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
            "constraints": {},
        }
        ab_token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=scope_a,
            max_depth=2,
        )

        escalated = {
            "actions": ["purchase", "admin"],
            "max_amount": 10000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
            "constraints": {},
        }
        with pytest.raises(ScopeEscalationError) as exc_info:
            delegate_further(
                holder=agent_b,
                parent_delegation_jwt=ab_token,
                sub_delegate_did=agent_c.did,
                narrowed_scope=escalated,
            )
        assert exc_info.value.field == "actions"

    def test_escalation_blocked_amount(self, agent_a, agent_b, agent_c):
        """B tries to increase max_amount beyond what A granted."""
        scope_a = {
            "actions": ["purchase"],
            "max_amount": 5000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
            "constraints": {},
        }
        ab_token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=scope_a,
            max_depth=2,
        )

        escalated = {
            "actions": ["purchase"],
            "max_amount": 10000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
            "constraints": {},
        }
        with pytest.raises(ScopeEscalationError) as exc_info:
            delegate_further(
                holder=agent_b,
                parent_delegation_jwt=ab_token,
                sub_delegate_did=agent_c.did,
                narrowed_scope=escalated,
            )
        assert exc_info.value.field == "max_amount"

    def test_max_depth_exceeded(self, agent_a, agent_b, agent_c, agent_d):
        """A sets max_depth=1: A->B (depth 0), B->C (depth 1) OK, C->D (depth 2) FAIL."""
        scope = {
            "actions": ["purchase"],
            "max_amount": 10000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
            "constraints": {},
        }

        ab_token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=scope,
            max_depth=1,
        )

        # B->C at depth 1 == max_depth: should succeed
        bc_token = delegate_further(
            holder=agent_b,
            parent_delegation_jwt=ab_token,
            sub_delegate_did=agent_c.did,
            narrowed_scope=scope,
        )
        assert bc_token  # did not raise

        # C->D at depth 2 > max_depth=1: should fail
        with pytest.raises(ValueError, match="exceeds maximum"):
            delegate_further(
                holder=agent_c,
                parent_delegation_jwt=bc_token,
                sub_delegate_did=agent_d.did,
                narrowed_scope=scope,
            )

    def test_expired_parent_invalidates_child(self, agent_a, agent_b, agent_c):
        """Parent delegation expired -> delegate_further raises ValueError."""
        scope = {
            "actions": ["purchase"],
            "max_amount": 10000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": [],
            "constraints": {},
        }
        ab_token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=scope,
            max_depth=2,
            ttl_seconds=1,
        )
        time.sleep(2)

        with pytest.raises(ValueError, match="invalid"):
            delegate_further(
                holder=agent_b,
                parent_delegation_jwt=ab_token,
                sub_delegate_did=agent_c.did,
                narrowed_scope=scope,
            )

    def test_required_action_check(self, agent_a, agent_b, full_scope):
        """Chain has effective actions=["negotiate","purchase"]. required_action="admin" fails."""
        token = issue_delegation(
            delegator=agent_a,
            delegate_did=agent_b.did,
            scope=full_scope,
            max_depth=1,
        )

        result = verify_delegation_chain(token, required_action="admin")
        assert result.verified is False
        assert "not in effective scope" in result.reason

        result_ok = verify_delegation_chain(token, required_action="purchase")
        assert result_ok.verified is True
