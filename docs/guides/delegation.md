# Delegation Chains Guide

Tesht (Pramana) implements W3C Verifiable Credential-based delegation. A user can delegate authority to an AI agent, that agent can further sub-delegate with narrowed scope, and any verifier can traverse the entire chain to confirm provenance.

## Core concepts

| Term | Description |
|---|---|
| **Delegator** | The identity granting authority |
| **Delegate** | The identity receiving authority |
| **Scope** | What the delegate is permitted to do |
| **max_depth** | How many additional sub-delegations are allowed |
| **Chain** | The linked sequence of delegation credentials |

## Scope model

Every delegation carries a scope dict. The SDK recognises these standard fields:

| Field | Type | Description |
|---|---|---|
| `actions` | `list[str]` | Permitted operation names (e.g. `["purchase", "refund"]`) |
| `max_amount` | `int` | Maximum transaction amount (integer, smallest currency unit) |
| `currency` | `str` | ISO 4217 code |
| `merchants` | `list[str]` | Restrict to specific merchants |
| `categories` | `list[str]` | Restrict to product categories |
| `constraints` | `dict` | Arbitrary key-value constraints |

You can include custom fields — they will be preserved and included in `effective_scope` after chain verification.

## Issuing a root delegation

```python
from tesht.identity import AgentIdentity
from tesht.delegation import issue_delegation

user  = AgentIdentity.create("alice")
agent = AgentIdentity.create("alice-shopping-agent")

delegation_jwt = issue_delegation(
    delegator=user,
    delegate_did=agent.did,
    scope={
        "actions": ["purchase", "return"],
        "max_amount": 50000,    # $500.00 in cents
        "currency": "USD",
        "categories": ["footwear", "apparel"],
    },
    max_depth=2,        # agent may sub-delegate up to 2 levels deep
    ttl_seconds=86400,  # valid for 24 hours
)
```

## Sub-delegating further

A delegate can pass part of their authority to another agent, but only within their own scope:

```python
from tesht.delegation import delegate_further

sub_agent = AgentIdentity.create("specialist-sub-agent")

sub_delegation_jwt = delegate_further(
    holder=agent,
    parent_delegation_jwt=delegation_jwt,
    sub_delegate_did=sub_agent.did,
    narrowed_scope={
        "actions": ["purchase"],         # subset of parent ["purchase", "return"]
        "max_amount": 10000,             # $100.00 ≤ parent $500.00
        "currency": "USD",
        "categories": ["footwear"],      # subset of parent categories
    },
    ttl_seconds=3600,
)
```

## Scope narrowing rules

`delegate_further` enforces **scope can only narrow, never escalate**. The SDK raises `ScopeEscalationError` if:

- `actions` contains an action not in the parent scope
- `max_amount` exceeds the parent's `max_amount`
- `categories` contains a category not in the parent

```python
from tesht.delegation import ScopeEscalationError

try:
    delegate_further(
        holder=agent,
        parent_delegation_jwt=delegation_jwt,
        sub_delegate_did=sub_agent.did,
        narrowed_scope={
            "actions": ["purchase", "admin"],  # "admin" not in parent scope ❌
            "max_amount": 10000,
        },
    )
except ScopeEscalationError as e:
    print(e.field)          # "actions"
    print(e.parent_value)   # ["purchase", "return"]
    print(e.child_value)    # ["purchase", "admin"]
```

## Depth limits

`max_depth` is set by the original delegator and propagated through the chain. An attempt to sub-delegate beyond the limit raises `ValueError`:

```python
# Root delegation: max_depth=1 (one sub-delegation allowed)
root_jwt = issue_delegation(delegator=user, delegate_did=agent.did,
    scope={...}, max_depth=1)

# First sub-delegation: OK (depth=1, at limit)
d1_jwt = delegate_further(holder=agent, parent_delegation_jwt=root_jwt,
    sub_delegate_did=agent2.did, narrowed_scope={...})

# Second sub-delegation: raises ValueError — exceeds maximum
# ValueError: delegation depth 2 exceeds maximum allowed depth 1
delegate_further(holder=agent2, parent_delegation_jwt=d1_jwt,
    sub_delegate_did=agent3.did, narrowed_scope={...})
```

## Verifying a delegation chain

`verify_delegation_chain` recursively verifies every link in the chain:

```python
from tesht.delegation import verify_delegation_chain

result = verify_delegation_chain(
    sub_delegation_jwt,
    required_action="purchase",  # optional: assert action is in effective scope
)

print(result.verified)         # True
print(result.depth)            # 2
print(result.effective_scope)  # intersection of all scopes in the chain
print(result.chain)            # list of decoded payload dicts
print(result.reason)           # None (or error message if not verified)
```

### `DelegationResult` fields

| Field | Type | Description |
|---|---|---|
| `verified` | `bool` | True if all links are valid and non-expired |
| `chain` | `list[dict]` | Decoded payloads of each delegation in the chain |
| `effective_scope` | `dict` | Intersection of all scopes from root to tip |
| `depth` | `int` | Number of delegation hops |
| `reason` | `str \| None` | Failure reason if not verified |

## Expiry propagation

If a parent delegation expires, all children become invalid:

```python
import time

root_jwt = issue_delegation(delegator=user, delegate_did=agent.did,
    scope={...}, ttl_seconds=1)       # expires in 1 second

child_jwt = delegate_further(holder=agent, parent_delegation_jwt=root_jwt,
    sub_delegate_did=sub_agent.did, narrowed_scope={...})

time.sleep(2)

result = verify_delegation_chain(child_jwt)
print(result.verified)  # False
print(result.reason)    # "parent delegation … is invalid"
```

## Multi-hop example (3 agents)

```
Walmart Procurement
    │
    ├── issue_delegation(scope: verify_supplier, max_depth=2)
    ▼
Supplier Verification Agent  (depth 1)
    │
    ├── delegate_further(narrowed: verify_supplier only)
    ▼
Specialist Auditor           (depth 2)
    │
    └── verify_delegation_chain(required_action="verify_supplier")
        → DelegationResult(verified=True, depth=2)
```

See [scripts/demo_multi_agent_supply_chain.py](../../scripts/demo_multi_agent_supply_chain.py) for the full runnable example.

## Running the demo

```bash
python scripts/demo_multi_agent_supply_chain.py
```

## See also

- [docs/guides/commerce.md](commerce.md) — combining delegation with AP2 mandates
- [docs/architecture.md](../architecture.md) — delegation chain model diagram
