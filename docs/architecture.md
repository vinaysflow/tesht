# Architecture — Tesht (Pramana)

## Overview

Tesht (Pramana) provides portable, cryptographically verifiable identities for AI agents. It is built on open W3C standards: Decentralized Identifiers (DIDs), Verifiable Credentials (VCs), and Verifiable Presentations (VPs).

```mermaid
flowchart TB
    subgraph sdk [Python SDK — tesht]
        identity[AgentIdentity]
        credentials[Credentials]
        delegation[Delegation]
        commerce[Commerce / AP2]
        integrations[Integrations\nMCP · LangChain · A2A]
    end

    subgraph backend [Backend API — FastAPI]
        agents_api[Agents API]
        creds_api[Credentials API]
        trust_api[Trust Score API]
        webhooks_api[Webhooks API]
        resolver[DID Resolver\nLRU Cache]
        db[(PostgreSQL)]
    end

    subgraph frontend [Frontend — Next.js]
        ui[Web UI]
    end

    identity --> credentials
    identity --> delegation
    identity --> commerce
    credentials --> integrations
    delegation --> integrations

    sdk -->|HTTP| backend
    frontend -->|HTTP| backend
    backend --> db
    backend --> resolver
```

## DID Methods

Tesht supports two DID methods with different trust models:

```mermaid
flowchart LR
    subgraph offline [Offline / Self-Sovereign]
        didkey["did:key:z6Mk…\n(Ed25519 keypair)"]
        keygen["AgentIdentity.create()\nGenerates keypair locally"]
        keygen --> didkey
    end

    subgraph online [Server-Resolvable]
        didweb["did:web:example.com\n(DID document at HTTPS URL)"]
        server["Backend API\n/.well-known/did.json"]
        server --> didweb
    end

    didkey -->|"verify_vc() resolves inline"| verifier[Verifier]
    didweb -->|"resolver fetches + caches"| verifier
```

`did:key` DIDs embed the public key in the identifier itself — no network call is ever needed for verification. `did:web` DIDs are resolved via HTTPS, with a thread-safe LRU cache (TTL 300s, max 10,000 entries) in the backend.

## Credential Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Issued: issue_vc()
    Issued --> Valid: verify_vc() → verified=True
    Issued --> Expired: TTL elapsed
    Valid --> Revoked: POST /v1/revoke
    Valid --> Expired: TTL elapsed
    Revoked --> Invalid: verify_vc() → revoked=True
    Expired --> Invalid: verify_vc() → expired=True
    Invalid --> [*]
```

Credentials are signed VC-JWTs (EdDSA / Ed25519). Revocation uses a W3C Bitstring Status List — a compact, privacy-preserving mechanism where the credential references a bit index in a published status list.

## Delegation Chain Model

```mermaid
flowchart TD
    user["User\n(delegator)"]
    agent1["Agent L1\n(delegate)"]
    agent2["Agent L2\n(sub-delegate)"]

    user -->|"issue_delegation()\nscope={actions, max_amount}\nmax_depth=2"| agent1
    agent1 -->|"delegate_further()\nnarrowed_scope\n(can only narrow)"| agent2

    agent2 -->|"verify_delegation_chain()\nrequired_action='purchase'"| result["DelegationResult\nverified=True\ndepth=2\neffective_scope={…}"]
```

Key invariants enforced by the SDK:
- **Scope narrowing only** — child scope cannot exceed parent (`ScopeEscalationError`)
- **Depth limit** — `delegate_further` raises `ValueError` if `depth >= max_depth`
- **Expiry propagation** — expired parent immediately invalidates all children

## AP2 Mandate Flow

```mermaid
sequenceDiagram
    participant User
    participant Agent
    participant Merchant

    User->>Agent: issue_delegation(scope: purchase ≤ $200)
    Agent->>Agent: issue_intent_mandate(description, max_amount)
    Agent->>Agent: issue_cart_mandate(items, total, intent_jwt)
    Agent->>Merchant: present cart_jwt + delegation_jwt
    Merchant->>Merchant: verify_delegation_chain(delegation_jwt)
    Merchant->>Merchant: verify_mandate(cart_jwt)
    Merchant-->>Agent: authorized ✅
```

The AP2 (Agent Payment Protocol) layering means:
1. **Intent mandate** — captures the shopping goal (human-readable, budget ceiling)
2. **Cart mandate** — captures the specific transaction (merchant, items, total)

`issue_cart_mandate` enforces that `cart.total ≤ intent.max_amount` at issuance time.

## Trust Score Pipeline

```mermaid
flowchart LR
    jwt[Credential JWT] --> parser[JWT Parser]
    parser --> f1["Factor: Credential Validity\n0–25 pts"]
    parser --> f2["Factor: Issuer Reputation\n0–25 pts"]
    parser --> f3["Factor: Agent History\n0–25 pts"]
    parser --> f4["Factor: Delegation Depth\n0–25 pts"]
    f1 --> total[Total Score 0–100]
    f2 --> total
    f3 --> total
    f4 --> total
    total --> risk["Risk Level\nlow / medium / high / critical"]
```

Trust scores are computed on-demand by the backend (`POST /v1/trust/score`) and optionally recorded as `TrustEvent` records for historical trending.

## MCP Authentication Flow

```mermaid
sequenceDiagram
    participant Client as Agent (MCP Client)
    participant Server as MCP Server

    Client->>Client: create_presentation(vc_jwts, audience=server.did)
    Client->>Server: HTTP request\nAuthorization: Bearer <VP-JWT>
    Server->>Server: TeshtMCPAuth.verify_request(headers)
    Server->>Server: verify_presentation(vp_jwt)
    Server->>Server: check trusted_issuers, required_credential_types
    Server-->>Client: MCPAuthResult(authenticated=True/False)
```

## Repository Layout

```
tesht/
├── sdk/
│   ├── python/tesht/        ← Python SDK (no server dependency)
│   │   ├── identity.py
│   │   ├── credentials.py
│   │   ├── delegation.py
│   │   ├── commerce.py
│   │   └── integrations/
│   └── typescript/src/        ← TypeScript SDK
├── backend/                   ← FastAPI backend
│   ├── api/routes/
│   ├── core/                  ← settings, db, resolver, trust_score, webhooks
│   └── migrations/
├── frontend/                  ← Next.js web UI
├── scripts/                   ← Standalone demos + dev utilities
├── tests/
│   ├── synthetic/             ← Data generator
│   └── e2e/                   ← Full ecosystem tests
└── docs/
```
