# Tesht (Pramana) SDK — Portable AI Agent Identity

Give your AI agent a verifiable identity in 3 lines of code. W3C DIDs + Verifiable Credentials. No server needed.

Tesht (from Irish *teist*, testimony) is portable identity and scoped authorization for AI agents.

## Install

```bash
npm install @tesht/sdk
```

## Quickstart

```typescript
import { AgentIdentity, issueVC, verifyVC } from "@tesht/sdk";

// Create an agent identity (offline — no server needed)
const agent = await AgentIdentity.create("my-shopping-bot");
console.log(agent.did); // did:key:z6Mk...

// Issue a credential
const vc = await issueVC(agent, "did:key:z6MkTarget...", {
  credentialType: "CapabilityCredential",
  claims: { capability: "purchase", max_amount: 10000 },
});

// Verify it (also offline for did:key)
const result = await verifyVC(vc);
console.log(result.valid); // true
```

## What is this?

Tesht implements portable AI agent identity using W3C standards.
Every AI agent gets a DID (Decentralized Identifier) and can
issue/receive Verifiable Credentials — cryptographic proof of
identity, capabilities, and delegation authority.

Works with: LangChain.js, any agent framework, MCP, A2A protocol.

## Features

- **Offline identity**: `did:key` method — no server dependency
- **Server identity**: `did:web` method — resolvable over HTTPS
- **VC issuance and verification** (VC-JOSE/JWT, EdDSA)
- **Verifiable Presentations** for agent-to-agent auth
- **Delegation chains** with scope enforcement
- **Revocation** via W3C Bitstring Status List

## Delegation example

```typescript
import {
  AgentIdentity,
  issueDelegation,
  delegateFurther,
  verifyDelegationChain,
} from "@tesht/sdk";

const root = await AgentIdentity.create("root-agent");
const worker = await AgentIdentity.create("worker-agent");
const subworker = await AgentIdentity.create("subworker-agent");

// Root delegates to worker
const d1 = await issueDelegation(root, worker.did, {
  actions: ["read", "pay"],
  maxAmount: 500,
});

// Worker narrows and delegates further
const d2 = await delegateFurther(worker, d1, subworker.did, {
  actions: ["pay"],
  maxAmount: 100,
});

// Verify the full chain
const result = await verifyDelegationChain([d1, d2]);
console.log(result.valid);          // true
console.log(result.scope?.maxAmount); // 100
```

## Verifiable Presentation example

```typescript
import {
  AgentIdentity,
  issueVC,
  createPresentation,
  verifyPresentation,
} from "@tesht/sdk";

const issuer = await AgentIdentity.create("issuer");
const holder = await AgentIdentity.create("holder");

const vc = await issueVC(issuer, holder.did, {
  credentialType: "AccessCredential",
});
const vp = await createPresentation(holder, [vc], {
  audience: "did:key:zVerifier...",
});

const result = await verifyPresentation(vp, {
  expectedAudience: "did:key:zVerifier...",
});
console.log(result.valid); // true
```

## API reference

| Function | Description |
|---|---|
| `AgentIdentity.create(name, domain?)` | Generate a new Ed25519 keypair + DID |
| `issueVC(issuer, subjectDid, opts?)` | Issue a signed VC-JWT |
| `verifyVC(jwt, opts?)` | Verify a VC-JWT (offline for did:key) |
| `createPresentation(holder, vcs, opts?)` | Wrap VCs into a signed VP-JWT |
| `verifyPresentation(jwt, opts?)` | Verify a VP-JWT |
| `issueDelegation(issuer, delegateDid, scope, opts?)` | Issue a root delegation JWT |
| `delegateFurther(holder, parentJwt, newDelegateDid, scope, opts?)` | Sub-delegate with scope narrowing |
| `verifyDelegationChain(jwts, opts?)` | Verify full chain recursively |
| `resolveDIDKey(did)` | Resolve a `did:key` to a DID document |

All functions are `async`. `AgentIdentity` uses static async factory methods.

## Links

- [GitHub](https://github.com/vinaysflow/tesht)
- [Documentation](https://github.com/vinaysflow/tesht)
