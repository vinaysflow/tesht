# Tesht (Pramana) SDK — Portable AI Agent Identity

Give your AI agent a verifiable identity in 3 lines of code. W3C DIDs + Verifiable Credentials. No server needed.

Tesht (from Irish *teist*, testimony) is portable identity and scoped authorization for AI agents.

## Install

```bash
pip install tesht
```

## Quickstart

```python
from tesht import AgentIdentity, issue_vc, verify_vc

# Create an agent identity (offline — no server needed)
agent = AgentIdentity.create("my-shopping-bot")
print(agent.did)  # did:key:z6Mk...

# Issue a credential
vc = issue_vc(
    issuer=agent,
    subject_did="did:key:z6MkTarget...",
    credential_type="CapabilityCredential",
    claims={"capability": "purchase", "max_amount": 10000}
)

# Verify it (also offline for did:key)
result = verify_vc(vc)
assert result.verified == True
```

## What is this?

Tesht (Pramana) implements portable AI agent identity using W3C standards.
Every AI agent gets a DID (Decentralized Identifier) and can
issue/receive Verifiable Credentials — cryptographic proof of
identity, capabilities, and delegation authority.

Works with: LangChain, CrewAI, MCP, A2A protocol, any agent framework.

## Features

- **Offline identity**: `did:key` method — no server dependency
- **Server identity**: `did:web` method — resolvable over HTTPS
- **VC issuance and verification** (VC-JOSE/JWT, EdDSA)
- **Verifiable Presentations** for agent-to-agent auth
- **Delegation chains** with scope enforcement
- **Revocation** via W3C Bitstring Status List

## Delegation example

```python
from tesht import AgentIdentity, issue_delegation, delegate_further, verify_delegation_chain

root = AgentIdentity.create("root-agent")
worker = AgentIdentity.create("worker-agent")
subworker = AgentIdentity.create("subworker-agent")

# Root delegates to worker
d1 = issue_delegation(root, worker.did, scope={"actions": ["read", "pay"], "max_amount": 500})

# Worker narrows and delegates further
d2 = delegate_further(worker, d1, subworker.did, scope={"actions": ["pay"], "max_amount": 100})

# Verify the full chain
result = verify_delegation_chain([d1, d2])
assert result.valid
print(result.scope)  # {"actions": ["pay"], "max_amount": 100}
```

## Verifiable Presentation example

```python
from tesht import AgentIdentity, issue_vc, create_presentation, verify_presentation

issuer = AgentIdentity.create("issuer")
holder = AgentIdentity.create("holder")

vc = issue_vc(issuer, holder.did, credential_type="AccessCredential")
vp = create_presentation(holder, [vc], audience="did:key:zVerifier...")

result = verify_presentation(vp, expected_audience="did:key:zVerifier...")
assert result.valid
```

## API reference

| Function | Description |
|---|---|
| `AgentIdentity.create(name, domain=None)` | Generate a new Ed25519 keypair + DID |
| `issue_vc(issuer, subject_did, ...)` | Issue a signed VC-JWT |
| `verify_vc(jwt, ...)` | Verify a VC-JWT (offline for did:key) |
| `create_presentation(holder, vcs, ...)` | Wrap VCs into a signed VP-JWT |
| `verify_presentation(jwt, ...)` | Verify a VP-JWT |
| `issue_delegation(issuer, delegate_did, scope)` | Issue a root delegation JWT |
| `delegate_further(holder, parent_jwt, ...)` | Sub-delegate with scope narrowing |
| `verify_delegation_chain(jwts, ...)` | Verify full chain recursively |

## Links

- [GitHub](https://github.com/vinaysflow/tesht)
- [Documentation](https://github.com/vinaysflow/tesht)
- [Live demo](https://aurviaglobal-tesht-demo.hf.space/demo)
