from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from tesht.credentials import issue_vc, verify_vc
from tesht.identity import AgentIdentity


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ScopeEscalationError(ValueError):
    """Raised when a child delegation scope exceeds the parent's scope."""

    def __init__(self, field: str, parent_value: Any, child_value: Any):
        super().__init__(
            f"Scope escalation on '{field}': "
            f"child value {child_value} exceeds parent {parent_value}"
        )
        self.field = field
        self.parent_value = parent_value
        self.child_value = child_value


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DelegationResult:
    """Result of verifying a delegation chain."""
    verified: bool
    chain: list[dict[str, Any]]
    effective_scope: dict[str, Any]
    depth: int
    reason: Optional[str]


# ---------------------------------------------------------------------------
# Scope intersection
# ---------------------------------------------------------------------------

def _default_scope() -> dict[str, Any]:
    return {
        "actions": [],
        "max_amount": 0,
        "currency": "USD",
        "merchants": [],
        "categories": [],
        "constraints": {},
    }


def validate_scope_narrowing(parent_scope: dict[str, Any], child_scope: dict[str, Any]) -> None:
    """
    Validate that child_scope is a subset of (or equal to) parent_scope.
    Raises ScopeEscalationError on any violation.
    """
    p_actions = set(parent_scope.get("actions", []))
    c_actions = set(child_scope.get("actions", []))
    if c_actions and not c_actions.issubset(p_actions):
        raise ScopeEscalationError("actions", sorted(p_actions), sorted(c_actions))

    p_amount = parent_scope.get("max_amount", 0)
    c_amount = child_scope.get("max_amount", 0)
    if c_amount > p_amount:
        raise ScopeEscalationError("max_amount", p_amount, c_amount)

    p_currency = parent_scope.get("currency", "USD")
    c_currency = child_scope.get("currency", "USD")
    if c_currency != p_currency:
        raise ScopeEscalationError("currency", p_currency, c_currency)

    p_merchants = parent_scope.get("merchants", [])
    c_merchants = child_scope.get("merchants", [])
    if p_merchants != ["*"]:
        p_set = set(p_merchants)
        c_set = set(c_merchants)
        if c_set and not c_set.issubset(p_set):
            raise ScopeEscalationError("merchants", sorted(p_set), sorted(c_set))

    p_categories = set(parent_scope.get("categories", []))
    c_categories = set(child_scope.get("categories", []))
    if c_categories and not c_categories.issubset(p_categories):
        raise ScopeEscalationError("categories", sorted(p_categories), sorted(c_categories))


def intersect_scopes(parent_scope: dict[str, Any], child_scope: dict[str, Any]) -> dict[str, Any]:
    """
    Compute the effective scope (most restrictive combination).
    Assumes validate_scope_narrowing has already passed.
    """
    p_actions = set(parent_scope.get("actions", []))
    c_actions = set(child_scope.get("actions", []))
    effective_actions = sorted(p_actions & c_actions) if c_actions else sorted(p_actions)

    effective_amount = min(
        parent_scope.get("max_amount", 0),
        child_scope.get("max_amount", parent_scope.get("max_amount", 0)),
    )

    effective_currency = parent_scope.get("currency", "USD")

    p_merchants = parent_scope.get("merchants", [])
    c_merchants = child_scope.get("merchants", [])
    if p_merchants == ["*"] and c_merchants == ["*"]:
        effective_merchants = ["*"]
    elif p_merchants == ["*"]:
        effective_merchants = c_merchants
    elif c_merchants == ["*"]:
        effective_merchants = p_merchants
    else:
        effective_merchants = sorted(set(p_merchants) & set(c_merchants))

    p_categories = set(parent_scope.get("categories", []))
    c_categories = set(child_scope.get("categories", []))
    effective_categories = sorted(p_categories & c_categories) if c_categories else sorted(p_categories)

    p_constraints = dict(parent_scope.get("constraints", {}))
    c_constraints = dict(child_scope.get("constraints", {}))
    effective_constraints = {**p_constraints, **c_constraints}

    return {
        "actions": effective_actions,
        "max_amount": effective_amount,
        "currency": effective_currency,
        "merchants": effective_merchants,
        "categories": effective_categories,
        "constraints": effective_constraints,
    }


# ---------------------------------------------------------------------------
# issue_delegation
# ---------------------------------------------------------------------------

def issue_delegation(
    delegator: AgentIdentity,
    delegate_did: str,
    scope: dict[str, Any],
    max_depth: int = 1,
    ttl_seconds: int = 3600,
    status_list_url: Optional[str] = None,
    status_list_index: Optional[int] = None,
) -> str:
    """Issue a DelegationCredential VC-JWT."""
    extra: dict[str, Any] = {}
    if status_list_url is not None and status_list_index is not None:
        extra["status_list_url"] = status_list_url
        extra["status_list_index"] = status_list_index
    return issue_vc(
        issuer=delegator,
        subject_did=delegate_did,
        credential_type="DelegationCredential",
        claims={
            "delegatedBy": delegator.did,
            "delegationScope": scope,
            "delegationDepth": 0,
            "maxDelegationDepth": max_depth,
        },
        ttl_seconds=ttl_seconds,
        **extra,
    )


# ---------------------------------------------------------------------------
# delegate_further
# ---------------------------------------------------------------------------

def delegate_further(
    holder: AgentIdentity,
    parent_delegation_jwt: str,
    sub_delegate_did: str,
    narrowed_scope: dict[str, Any],
    ttl_seconds: int = 3600,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_list_url: Optional[str] = None,
    status_list_index: Optional[int] = None,
) -> str:
    """
    Create a sub-delegation. The new credential references the parent.

    Raises:
    - ScopeEscalationError if narrowed_scope exceeds parent's scope
    - ValueError if delegation depth would exceed maxDelegationDepth
    - ValueError if parent_delegation_jwt is invalid or expired
    """
    parent_result = verify_vc(parent_delegation_jwt, resolver=resolver)
    if not parent_result.verified:
        raise ValueError(
            f"Parent delegation credential is invalid: {parent_result.reason}"
        )

    parent_claims = parent_result.claims
    parent_scope = parent_claims.get("delegationScope", {})
    parent_depth = int(parent_claims.get("delegationDepth", 0))
    max_depth = int(parent_claims.get("maxDelegationDepth", 0))

    new_depth = parent_depth + 1
    if new_depth > max_depth:
        raise ValueError(
            f"Delegation depth {new_depth} exceeds maximum {max_depth}"
        )

    validate_scope_narrowing(parent_scope, narrowed_scope)

    # Parent-bound TTL: child cannot outlive parent
    import time as _time
    now = int(_time.time())
    # Decode exp directly from parent jwt without verification (payload attr may not exist)
    parent_exp: Optional[int] = None
    import base64 as _b64, json as _json
    parts = parent_delegation_jwt.split(".")
    if len(parts) == 3:
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        try:
            parent_exp = _json.loads(_b64.urlsafe_b64decode(padded)).get("exp")
        except Exception:
            parent_exp = None

    effective_ttl = ttl_seconds
    if parent_exp is not None:
        child_exp = now + ttl_seconds
        if child_exp > parent_exp:
            effective_ttl = max(0, parent_exp - now)

    extra: dict[str, Any] = {}
    if status_list_url is not None and status_list_index is not None:
        extra["status_list_url"] = status_list_url
        extra["status_list_index"] = status_list_index

    return issue_vc(
        issuer=holder,
        subject_did=sub_delegate_did,
        credential_type="DelegationCredential",
        claims={
            "delegatedBy": holder.did,
            "delegationScope": narrowed_scope,
            "delegationDepth": new_depth,
            "maxDelegationDepth": max_depth,
            "parentDelegation": parent_delegation_jwt,
        },
        ttl_seconds=effective_ttl,
        **extra,
    )


# ---------------------------------------------------------------------------
# verify_delegation_chain
# ---------------------------------------------------------------------------

def verify_delegation_chain(
    token: str,
    required_action: Optional[str] = None,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_checker: Optional[Callable[[str, int], bool]] = None,
    _depth: int = 0,
    _max_recursion: int = 10,
) -> DelegationResult:
    """
    Recursively verify a delegation chain.

    If required_action is provided, checks that the action is in the effective scope.
    _depth and _max_recursion are internal — prevent infinite recursion on malicious chains.
    """
    if _depth > _max_recursion:
        return DelegationResult(
            verified=False,
            chain=[],
            effective_scope={},
            depth=_depth,
            reason=f"Recursion limit {_max_recursion} exceeded",
        )

    vc_result = verify_vc(token, resolver=resolver, status_checker=status_checker)
    if not vc_result.verified:
        return DelegationResult(
            verified=False,
            chain=[],
            effective_scope={},
            depth=_depth,
            reason=vc_result.reason,
        )

    claims = vc_result.claims
    this_scope = claims.get("delegationScope", {})
    this_link = {
        "delegator": claims.get("delegatedBy", vc_result.issuer_did),
        "delegate": vc_result.subject_did,
        "scope": this_scope,
        "depth": int(claims.get("delegationDepth", 0)),
    }

    parent_jwt = claims.get("parentDelegation")

    if parent_jwt:
        parent_result = verify_delegation_chain(
            parent_jwt,
            resolver=resolver,
            status_checker=status_checker,
            _depth=_depth + 1,
            _max_recursion=_max_recursion,
        )
        if not parent_result.verified:
            return DelegationResult(
                verified=False,
                chain=parent_result.chain,
                effective_scope={},
                depth=_depth,
                reason=f"Parent delegation invalid: {parent_result.reason}",
            )

        try:
            effective_scope = intersect_scopes(parent_result.effective_scope, this_scope)
        except ScopeEscalationError as exc:
            return DelegationResult(
                verified=False,
                chain=parent_result.chain + [this_link],
                effective_scope={},
                depth=len(parent_result.chain) + 1,
                reason=str(exc),
            )

        chain = parent_result.chain + [this_link]
    else:
        effective_scope = this_scope
        chain = [this_link]

    if required_action and required_action not in effective_scope.get("actions", []):
        return DelegationResult(
            verified=False,
            chain=chain,
            effective_scope=effective_scope,
            depth=len(chain),
            reason=f"Action '{required_action}' not in effective scope: {effective_scope.get('actions', [])}",
        )

    return DelegationResult(
        verified=True,
        chain=chain,
        effective_scope=effective_scope,
        depth=len(chain),
        reason=None,
    )
