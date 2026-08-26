# Quickstart — Tesht (Pramana) SDK (Python)

Get up and running in five minutes. No server required.

## Prerequisites

- Python 3.9 or later
- Git

## 1. Clone and install the SDK

```bash
git clone https://github.com/vinaysflow/tesht.git
cd tesht
pip install -e sdk/python
```

## 2. Create an agent identity

Every Tesht agent starts with a self-sovereign identity backed by an Ed25519 keypair.

```python
from tesht.identity import AgentIdentity

alice = AgentIdentity.create("alice")
print(alice.did)   # did:key:z6Mk…
```

`did:key` identities are entirely offline — no server, no registration.

## 3. Issue and verify a credential

```python
from tesht.credentials import issue_vc, verify_vc

issuer = AgentIdentity.create("my-org")
subject = AgentIdentity.create("employee-bob")

# Issue a Verifiable Credential (returns a signed JWT)
vc_jwt = issue_vc(
    issuer=issuer,
    subject_did=subject.did,
    credential_type="EmployeeCredential",
    claims={"role": "engineer", "department": "platform"},
    ttl_seconds=86400,
)

# Verify it (no network call needed for did:key)
result = verify_vc(vc_jwt)
print(result.verified)       # True
print(result.credential_type)  # EmployeeCredential
print(result.claims)         # {'role': 'engineer', 'department': 'platform'}
```

## 4. Delegate authority to an agent

```python
from tesht.delegation import issue_delegation, verify_delegation_chain

user = AgentIdentity.create("alice")
agent = AgentIdentity.create("alice-shopping-agent")

delegation_jwt = issue_delegation(
    delegator=user,
    delegate_did=agent.did,
    scope={"actions": ["purchase"], "max_amount": 50000, "currency": "USD"},
    max_depth=1,
    ttl_seconds=3600,
)

result = verify_delegation_chain(delegation_jwt, required_action="purchase")
print(result.verified)         # True
print(result.effective_scope)  # {'actions': ['purchase'], ...}
```

## 5. Run the interactive demos

```bash
python scripts/demo_shopping_agent.py        # AP2 mandate + delegation
python scripts/demo_multi_agent_supply_chain.py  # cross-org credential + multi-hop delegation
python scripts/demo_mcp_auth.py              # MCP auth with VP
```

All three complete in under 5 seconds and exit 0 on success.

## Next steps

| Goal | Guide |
|---|---|
| Agent-to-agent payments (AP2) | [docs/guides/commerce.md](guides/commerce.md) |
| Multi-hop delegation chains | [docs/guides/delegation.md](guides/delegation.md) |
| MCP tool authentication | [docs/guides/mcp-integration.md](guides/mcp-integration.md) |
| System architecture | [docs/architecture.md](architecture.md) |
| Self-hosted backend | [docs/guides/DEPLOYMENT.md](guides/DEPLOYMENT.md) |
