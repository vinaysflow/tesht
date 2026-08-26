# AP2 Commerce Guide — Agent Payment Protocol

Tesht implements AP2 (Agent Payment Protocol), a two-layer mandate system that lets AI agents initiate purchases on behalf of users with cryptographic proof of authorization.

## Two-layer mandate model

```
User ─── delegates ──► Agent
                         │
                         ├── issue_intent_mandate()   ← "what" the agent wants to buy
                         │    (shopping goal, budget ceiling)
                         │
                         └── issue_cart_mandate()     ← "exactly what" it costs
                              (merchant, items, total)
                              ↑
                              references intent_mandate (budget enforcement)
```

**Intent mandate** is the human-readable authorization: "buy running shoes, max $120".
**Cart mandate** is the specific transaction: "Nike Air Max 270, $89.99 at Nike.com".

The SDK enforces that `cart.total ≤ intent.max_amount` at issuance time. Any attempt to create a cart over the intent budget raises `ValueError`.

## Amounts

All monetary amounts are **integers in the smallest currency unit** (cents for USD). So $120.00 = `12000`, $89.99 = `8999`.

## Issuing an intent mandate

```python
from tesht.identity import AgentIdentity
from tesht.commerce import issue_intent_mandate

user  = AgentIdentity.create("alice")
agent = AgentIdentity.create("alice-shopping-agent")

# User delegates purchase authority first (see delegation guide)
# ...

intent_jwt = issue_intent_mandate(
    delegator=agent,         # the agent acts as the mandate issuer
    agent_did=agent.did,
    intent={
        "description": "running shoes under $120",
        "category": "footwear",
        "max_amount": 12000,          # $120.00 in cents
        "currency": "USD",
    },
    ttl_seconds=3600,
)
```

### Intent mandate `intent` dict fields

| Field | Type | Required | Description |
|---|---|---|---|
| `description` | `str` | Yes | Human-readable shopping goal |
| `max_amount` | `int` | Yes | Budget ceiling in smallest currency unit |
| `currency` | `str` | Yes | ISO 4217 currency code |
| `category` | `str` | No | Product category |
| `merchant` | `str` | No | Restrict to specific merchant |

## Issuing a cart mandate

```python
from tesht.commerce import issue_cart_mandate

cart_jwt = issue_cart_mandate(
    delegator=agent,
    agent_did=agent.did,
    cart={
        "merchant": "Nike",
        "items": [
            {"name": "Nike Air Max 270", "qty": 1, "unit_price": 8999},
        ],
        "total": {"value": 8999, "currency": "USD"},   # $89.99 ≤ $120.00 ✅
    },
    intent_mandate_jwt=intent_jwt,   # must reference valid intent
    ttl_seconds=300,                 # short TTL — for a specific transaction
)
```

### Cart mandate `cart` dict fields

| Field | Type | Required | Description |
|---|---|---|---|
| `merchant` | `str` | No | Merchant name |
| `items` | `list[dict]` | Yes | Line items (`name`, `qty`, `unit_price`) |
| `total.value` | `int` | Yes | Total in smallest currency unit |
| `total.currency` | `str` | Yes | ISO 4217 |

## Budget enforcement

The SDK raises `ValueError` at issuance time if the cart exceeds the intent:

```python
# This raises: ValueError: cart total 15000 exceeds intent max_amount 12000
cart_jwt = issue_cart_mandate(
    delegator=agent,
    agent_did=agent.did,
    cart={"total": {"value": 15000, "currency": "USD"}, "items": []},
    intent_mandate_jwt=intent_jwt,
)
```

## Verifying a mandate

The merchant verifies that:
1. The cart JWT is a valid, unexpired signature
2. The referenced intent is valid
3. Amounts are consistent

```python
from tesht.commerce import verify_mandate

result = verify_mandate(cart_jwt)

print(result.verified)       # True
print(result.mandate_type)   # "AP2CartMandate"
print(result.mandate_id)     # UUID
print(result.delegator_did)  # agent DID
print(result.scope)          # intent scope dict
```

### `MandateVerification` fields

| Field | Type | Description |
|---|---|---|
| `verified` | `bool` | Whether the mandate is valid |
| `mandate_type` | `str` | `"AP2IntentMandate"` or `"AP2CartMandate"` |
| `mandate_id` | `str` | UUID of the mandate |
| `delegator_did` | `str` | DID of the mandate issuer |
| `agent_did` | `str` | DID of the authorized agent |
| `scope` | `dict` | Scope from the underlying intent |
| `reason` | `str \| None` | Failure reason if not verified |

## Full flow with delegation

The complete trust chain from user to merchant:

```python
from tesht.delegation import issue_delegation, verify_delegation_chain
from tesht.commerce import issue_intent_mandate, issue_cart_mandate, verify_mandate

user  = AgentIdentity.create("alice")
agent = AgentIdentity.create("agent")

# 1. User delegates authority
delegation_jwt = issue_delegation(
    delegator=user,
    delegate_did=agent.did,
    scope={"actions": ["purchase"], "max_amount": 2000000, "currency": "USD"},
)

# 2. Agent creates mandates
intent_jwt = issue_intent_mandate(agent, agent.did,
    {"description": "shoes", "max_amount": 12000, "currency": "USD"})

cart_jwt = issue_cart_mandate(agent, agent.did,
    {"total": {"value": 8999, "currency": "USD"}, "items": [...]},
    intent_mandate_jwt=intent_jwt)

# 3. Merchant verifies both
chain = verify_delegation_chain(delegation_jwt, required_action="purchase")
mandate = verify_mandate(cart_jwt)

assert chain.verified and mandate.verified
```

## Running the demo

```bash
python scripts/demo_shopping_agent.py
```

## See also

- [docs/guides/delegation.md](delegation.md) — delegation chain setup
- [docs/architecture.md](../architecture.md) — AP2 sequence diagram
