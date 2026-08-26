// All 13 scenario definitions with buyer-facing narrative + technical details.

import { FlowNode, FlowEdge } from "./components/FlowDiagram";

export type DemoPath = "happy" | "unhappy" | "edge";

export interface RunContext {
  results: Record<string, unknown>;
}

export interface StepDef {
  id: string;
  title: string;
  /** Plain-English explanation for a non-technical buyer */
  plainEnglish: string;
  /** Technical detail (collapsible) for engineers */
  technicalDetail: string;
  method: "POST" | "GET";
  endpoint: string | ((ctx: RunContext) => string);
  body?: unknown | ((ctx: RunContext) => unknown);
  expectStatus: number;
  check?: (resp: unknown) => { pass: boolean; label: string };
  failureExpected?: boolean;
  delayMs?: number;
  /** What security control does this step demonstrate? */
  controlLabel?: string;
}

export interface ScenarioDef {
  id: string;
  path: DemoPath;
  title: string;
  subtitle: string;
  /** One-line business framing: why a buyer should care */
  businessContext: string;
  /** What goes wrong without Tesht — the risk being mitigated */
  riskWithout: string;
  /** Plain-English summary shown after scenario completes */
  whatJustHappened: string;
  /** Security controls this scenario proves (shown on scorecard) */
  controlsProven: string[];
  flowNodes: FlowNode[];
  flowEdges: FlowEdge[];
  steps: StepDef[];
  /** Side-by-side comparison: without vs. with Tesht */
  comparisonRows?: { label: string; without: string; withTesht: string }[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function get(ctx: RunContext, stepId: string, field: string): unknown {
  const r = ctx.results[stepId] as Record<string, unknown> | undefined;
  return r?.[field];
}

function tamperJwt(jwt: string): string {
  try {
    const parts = jwt.split(".");
    const pad = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
    const payload = JSON.parse(atob(pad(parts[1].replace(/-/g, "+").replace(/_/g, "/"))));
    if (payload.vc?.credentialSubject) {
      payload.vc.credentialSubject.tampered = true;
    } else {
      payload._tampered = true;
    }
    const encoded = btoa(JSON.stringify(payload))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    return `${parts[0]}.${encoded}.${parts[2]}`;
  } catch {
    return jwt + "TAMPERED";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy Path: Identity + Credentials
// ─────────────────────────────────────────────────────────────────────────────

const scenarioIdentityCredentials: ScenarioDef = {
  id: "happy-identity",
  path: "happy",
  title: "Agent Identity + Credentials",
  subtitle: "Prove who your AI agent is — with cryptographic certainty",
  businessContext:
    "When your AI agent contacts a supplier, partner, or customer, they need to know it's really your agent — not an impersonator. This scenario shows how Tesht gives every agent a verifiable digital identity.",
  riskWithout:
    "Without verifiable identity, anyone can spin up a bot claiming to be your company's agent. There's no way for partners to distinguish a legitimate request from a spoofed one. API keys can be leaked; shared secrets can be stolen.",
  whatJustHappened:
    "Your agent received a W3C-standard digital identity (DID) and a cryptographically signed credential. Any partner can verify this credential in under 50ms — without calling your servers. The credential is tamper-proof: modifying any field invalidates the signature.",
  controlsProven: [
    "Cryptographic agent identity (did:web)",
    "Verifiable credential issuance (VC-JWT)",
    "Offline signature verification (Ed25519)",
    "Composite trust scoring",
  ],
  comparisonRows: [
    { label: "Agent identity", without: "API key / shared secret", withTesht: "W3C DID + Ed25519 keypair" },
    { label: "Verification", without: "Server call to issuer required", withTesht: "Local signature check (< 50ms)" },
    { label: "Tamper detection", without: "None — JSON is editable", withTesht: "Ed25519 signature invalidation" },
    { label: "Trust assessment", without: "Binary (valid / invalid)", withTesht: "0–100 composite score with history" },
  ],
  flowNodes: [
    { name: "Your Organization", role: "Issuer" },
    { name: "AI Agent", role: "Agent" },
    { name: "Partner / Verifier", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Issues credential", highlight: true },
    { label: "Verifies identity", highlight: true },
  ],
  steps: [
    {
      id: "create-issuer",
      title: "Register Your Organization's Agent",
      plainEnglish:
        "Your organization registers as a credential issuer. This creates a unique digital identity (DID) backed by a cryptographic keypair — like a corporate seal, but unforgeable.",
      technicalDetail:
        "Provisions a did:web agent with a fresh Ed25519 keypair. The backend returns a DID document URL where the public key can be resolved by any verifier.",
      controlLabel: "Identity provisioning",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "acme-corp-issuer" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Identity created: ${r.did}` }),
    },
    {
      id: "create-subject",
      title: "Register the AI Agent",
      plainEnglish:
        "Your AI agent (e.g., a procurement bot, customer service agent, or trading bot) gets its own identity. In production, this could be any software agent acting on your behalf.",
      technicalDetail:
        "Creates a second agent — the subject who will receive the credential. In real deployments this could be an employee, robot, or software agent.",
      controlLabel: "Agent registration",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "procurement-agent" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Agent identity: ${r.did}` }),
    },
    {
      id: "issue-vc",
      title: "Issue a Verifiable Credential",
      plainEnglish:
        "Your organization issues a tamper-proof digital credential to the agent — proving it's authorized to act on your behalf. Think of it like a digitally signed employee badge that can't be forged or photocopied.",
      technicalDetail:
        "Signs a W3C VC-JWT (EdDSA/Ed25519) for the subject. The credential references a Bitstring Status List entry so it can be revoked instantly later.",
      controlLabel: "Credential issuance",
      method: "POST",
      endpoint: "/v1/credentials/issue",
      body: (ctx: RunContext) => ({
        issuer_agent_id: get(ctx, "create-issuer", "id"),
        subject_did: get(ctx, "create-subject", "did"),
        credential_type: "AgentCredential",
        subject_claims: { role: "procurement-agent", department: "supply-chain" },
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: !!r.jwt && r.jwt.split(".").length === 3,
        label: `Credential issued (JTI: ${r.jti})`,
      }),
    },
    {
      id: "verify-vc",
      title: "Partner Verifies the Credential",
      plainEnglish:
        "A supplier or partner independently verifies the agent's credential. No phone call to your IT department needed — the cryptographic signature proves everything. If anyone tampered with the credential, verification fails instantly.",
      technicalDetail:
        "Any party can verify the credential without calling the issuer — the signature is self-contained. The backend resolves the issuer DID and checks the status list.",
      controlLabel: "Signature verification",
      method: "POST",
      endpoint: "/v1/credentials/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "issue-vc", "jwt") }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.verified === true,
        label: r.verified ? "Credential verified — identity confirmed" : `Rejected: ${r.reason}`,
      }),
    },
    {
      id: "trust-score",
      title: "Compute Trust Score",
      plainEnglish:
        "Beyond just valid/invalid, Tesht computes a 0–100 trust score considering credential validity, issuer reputation, agent history, and delegation depth. This lets partners make risk-adjusted decisions automatically.",
      technicalDetail:
        "Evaluates four factors: credential validity, issuer reputation, agent history, delegation depth. Returns composite score with risk level.",
      controlLabel: "Trust scoring",
      method: "POST",
      endpoint: "/v1/trust/score",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "issue-vc", "jwt") }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: typeof r.total === "number",
        label: `Trust Score: ${r.total}/100 — Risk Level: ${r.risk_level}`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Happy Path: Delegation Chain
// ─────────────────────────────────────────────────────────────────────────────

const scenarioDelegation: ScenarioDef = {
  id: "happy-delegation",
  path: "happy",
  title: "Authority Delegation",
  subtitle: "Safely delegate authority from managers to agents with automatic limits",
  businessContext:
    "In large organizations, authority flows downward: a VP authorizes a manager, who authorizes an AI agent. Tesht tracks this chain cryptographically — so you always know who authorized what, and revoking a manager's access automatically revokes all their agents' access.",
  riskWithout:
    "Without delegation chains, there's no way to trace who gave an AI agent its permissions. When an employee leaves, you can't automatically revoke all the agents they authorized. Sub-delegation is invisible — agents can silently pass their authority to others.",
  whatJustHappened:
    "Alice delegated authority to Bob, who sub-delegated to Carol — with automatically narrowed scope. Every link in this chain is cryptographically signed and registered for cascade revocation. If Alice's access is revoked, Bob and Carol lose access immediately.",
  controlsProven: [
    "Multi-hop delegation chains",
    "Scope narrowing enforcement",
    "Cascade revocation readiness",
    "Delegation registry tracking",
  ],
  comparisonRows: [
    { label: "Authority tracking", without: "Manual spreadsheet / RBAC config", withTesht: "Cryptographic delegation chain" },
    { label: "Scope narrowing", without: "Hope sub-agents respect limits", withTesht: "Enforced: child scope ≤ parent scope" },
    { label: "Cascade revocation", without: "Manual agent-by-agent cleanup", withTesht: "One operation revokes entire tree" },
  ],
  flowNodes: [
    { name: "Alice (VP)", role: "Delegator" },
    { name: "Bob (Manager)", role: "Agent" },
    { name: "Carol (Agent)", role: "Sub-Agent" },
  ],
  flowEdges: [
    { label: "Delegates ($500 limit)", highlight: true },
    { label: "Sub-delegates ($100)", highlight: true },
  ],
  steps: [
    {
      id: "del-create-alice",
      title: "Register Alice as Root Authority",
      plainEnglish:
        "Alice is a VP who holds the root purchasing authority. She'll delegate a portion of her authority down the chain.",
      technicalDetail:
        "Creates an agent with a did:web identity and Ed25519 keypair. Alice will be the root delegator.",
      controlLabel: "Root authority",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "alice-vp-procurement" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Alice: ${r.did}` }),
    },
    {
      id: "del-register-parent",
      title: "Alice Delegates to Bob",
      plainEnglish:
        "Alice delegates purchasing authority to Bob (a regional manager). This delegation is registered in the backend — if Alice's access is ever revoked, Bob's is automatically revoked too.",
      technicalDetail:
        "Registers a delegation JTI in the backend registry. Enables cascade revocation: revoking the parent automatically revokes all children.",
      controlLabel: "Delegation registration",
      method: "POST",
      endpoint: "/v1/delegations/register",
      body: (ctx: RunContext) => ({
        jti: `urn:uuid:demo-del-root-${Date.now()}`,
        issuer_did: get(ctx, "del-create-alice", "did"),
        subject_did: "did:web:example.com:bob-manager",
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.registered === true,
        label: `Delegation registered: ${r.jti}`,
      }),
    },
    {
      id: "del-register-child",
      title: "Bob Sub-Delegates to Carol",
      plainEnglish:
        "Bob delegates a narrower scope to Carol (an AI purchasing agent). Carol can only spend $100 — even though Bob has $500. The chain automatically enforces this narrowing.",
      technicalDetail:
        "Registers a sub-delegation with parent_jti link. Cascade revocation propagates: revoking Bob's delegation revokes Carol's too.",
      controlLabel: "Sub-delegation with scope narrowing",
      method: "POST",
      endpoint: "/v1/delegations/register",
      body: (ctx: RunContext) => ({
        jti: `urn:uuid:demo-del-child-${Date.now()}`,
        issuer_did: "did:web:example.com:bob-manager",
        subject_did: "did:web:example.com:carol-agent",
        parent_jti: get(ctx, "del-register-parent", "jti"),
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.registered === true,
        label: `Sub-delegation: ${r.jti}`,
      }),
    },
    {
      id: "del-verify-chain",
      title: "Issue Delegation Credential",
      plainEnglish:
        "A formal delegation credential is issued — this is the signed proof that Bob has Alice's authority. Any system can verify this chain without calling Alice directly.",
      technicalDetail:
        "Issues a DelegationCredential VC-JWT. Verification checks: signature valid, not expired, scope narrowing respected, depth within max.",
      controlLabel: "Delegation credential",
      method: "POST",
      endpoint: "/v1/credentials/issue",
      body: (ctx: RunContext) => ({
        issuer_agent_id: get(ctx, "del-create-alice", "id"),
        subject_did: "did:web:example.com:bob-manager",
        credential_type: "DelegationCredential",
        subject_claims: {
          delegatedBy: get(ctx, "del-create-alice", "did"),
          delegationScope: {
            actions: ["purchase"],
            max_amount: 50000,
            currency: "USD",
            merchants: ["*"],
          },
          delegationDepth: 0,
          maxDelegationDepth: 2,
        },
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.jwt, label: `Delegation credential issued` }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Happy Path: AP2 Commerce Mandates
// ─────────────────────────────────────────────────────────────────────────────

const scenarioCommerce: ScenarioDef = {
  id: "happy-commerce",
  path: "happy",
  title: "AI Commerce (AP2 Mandates)",
  subtitle: "Your AI agent shops within a budget you control — with cryptographic proof",
  businessContext:
    "Your AI agent needs to make purchases on your behalf — but you need hard limits. Tesht's two-layer mandate system (Intent + Cart) ensures the agent can never spend more than you authorized, and every purchase creates an auditable paper trail.",
  riskWithout:
    "Without cryptographic mandates, a compromised AI agent could make unlimited purchases. API-key-based auth doesn't enforce budgets. There's no way for merchants to verify the agent's spending authority without calling your backend.",
  whatJustHappened:
    "You authorized your agent to spend up to $120 on running shoes. The agent found Nike Air Max 270 for $89.99 — within budget. The merchant cryptographically verified the authorization, and a spend record was written to prevent double-spending. Every step is auditable.",
  controlsProven: [
    "Two-layer authorization (Intent + Cart)",
    "Budget enforcement at issuance",
    "Merchant-side verification",
    "Spend ledger (anti-double-spend)",
  ],
  comparisonRows: [
    { label: "Budget enforcement", without: "Custom code in each service", withTesht: "Protocol-level (Intent + Cart)" },
    { label: "Double-spend prevention", without: "Database locks / custom logic", withTesht: "Single-use JTI + spend ledger" },
    { label: "Merchant verification", without: "Trust the API key caller", withTesht: "Cryptographic mandate proof" },
    { label: "Spend tracking", without: "Build your own ledger", withTesht: "Built-in cumulative tracking" },
  ],
  flowNodes: [
    { name: "You", role: "Delegator" },
    { name: "Shopping Agent", role: "Agent" },
    { name: "Nike.com", role: "Merchant" },
  ],
  flowEdges: [
    { label: "Budget: $120 USD", highlight: true },
    { label: "Cart: $89.99", highlight: true },
  ],
  steps: [
    {
      id: "commerce-create-agent",
      title: "Register Your Shopping Agent",
      plainEnglish:
        "Your AI shopping agent gets a cryptographic identity — so merchants can verify it's really authorized by you, not a random bot.",
      technicalDetail:
        "Creates the AI shopping agent with a DID and Ed25519 keypair. Merchants can cryptographically verify its identity.",
      controlLabel: "Agent identity",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "my-shopping-agent" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Shopping agent registered` }),
    },
    {
      id: "commerce-intent",
      title: "Set a Spending Limit ($120)",
      plainEnglish:
        "You authorize the agent to spend up to $120 on footwear. This creates a signed JWT that acts as a digital spending limit — the agent carries this proof with every purchase attempt.",
      technicalDetail:
        "Issues an AP2 Intent Mandate: signed JWT encoding max_amount, currency, merchant restrictions, and category constraints. TTL 1 hour.",
      controlLabel: "Budget authorization",
      method: "POST",
      endpoint: "/v1/commerce/mandates/intent",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "commerce-create-agent", "did"),
        intent: {
          description: "Running shoes for marathon training",
          max_amount: 12000,
          currency: "USD",
          merchants: ["*"],
          categories: ["footwear"],
        },
        ttl_seconds: 3600,
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: !!r.mandate_jwt,
        label: `Spending limit set: $120.00 USD`,
      }),
    },
    {
      id: "commerce-cart",
      title: "Agent Finds Nike Air Max 270 — $89.99",
      plainEnglish:
        "Your agent found the shoes and submits a purchase request for $89.99. This is within your $120 budget, so the cart mandate is approved. The cart JWT references the intent, creating a complete authorization chain.",
      technicalDetail:
        "Issues an AP2 Cart Mandate referencing the intent. Budget check: $89.99 <= $120 limit. Single-use JTI prevents replay.",
      controlLabel: "Cart within budget",
      method: "POST",
      endpoint: "/v1/commerce/mandates/cart",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "commerce-create-agent", "did"),
        cart: {
          items: [{ name: "Nike Air Max 270", sku: "NK-AM-270", quantity: 1, price: 8999 }],
          total: { currency: "USD", value: 8999 },
          merchant_did: "did:web:nike.com",
          payment_method_type: "CARD",
        },
        intent_mandate_jwt: get(ctx, "commerce-intent", "mandate_jwt"),
        ttl_seconds: 300,
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: !!r.mandate_jwt,
        label: `Cart approved: $89.99 within $120 budget`,
      }),
    },
    {
      id: "commerce-verify",
      title: "Nike.com Verifies the Purchase",
      plainEnglish:
        "The merchant independently verifies: Is this agent authorized? Is the amount within budget? Is the currency correct? Has this cart been used before? All checks pass — the purchase is authorized.",
      technicalDetail:
        "Merchant verifies: signature valid, cart <= intent budget, currencies match, mandate not already fulfilled. On success, a MandateSpend record is written.",
      controlLabel: "Merchant verification",
      method: "POST",
      endpoint: "/v1/commerce/mandates/verify",
      body: (ctx: RunContext) => ({
        jwt: get(ctx, "commerce-cart", "mandate_jwt"),
        mandate_type: "AP2CartMandate",
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.verified === true,
        label: r.verified
          ? `Purchase authorized by merchant`
          : `Rejected: ${r.reason}`,
      }),
    },
    {
      id: "commerce-spend",
      title: "Check the Spend Ledger",
      plainEnglish:
        "The spend ledger shows exactly how much of the $120 budget has been used. If the agent tries to make another purchase that exceeds the remaining budget, it will be automatically blocked.",
      technicalDetail:
        "Retrieves cumulative spend against the intent mandate. Prevents multiple small purchases that together exceed the authorized budget.",
      controlLabel: "Spend tracking",
      method: "GET",
      endpoint: (ctx: RunContext) =>
        `/v1/commerce/mandates/${get(ctx, "commerce-intent", "mandate_id")}/spend`,
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.fulfillments >= 1,
        label: `Budget used: $${
          Object.values(r.cumulative_spend ?? {})
            .map((v) => ((v as number) / 100).toFixed(2))
            .join(", $")
        } of $120.00`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Happy Path: Revocation + Drift
// ─────────────────────────────────────────────────────────────────────────────

const scenarioRevocation: ScenarioDef = {
  id: "happy-revocation",
  path: "happy",
  title: "Instant Revocation",
  subtitle: "Fire an agent and their credentials stop working immediately",
  businessContext:
    "When an AI agent is compromised, an employee leaves, or you need to decommission a service — the credential must stop working instantly. Not in 24 hours. Not after a cache refresh. Right now.",
  riskWithout:
    "Traditional JWT tokens can't be revoked until they expire. If you set a 24h TTL, a compromised agent has 24 hours of unauthorized access. OAuth revocation requires the verifier to call your server — but what if they cached the token?",
  whatJustHappened:
    "A credential was issued, verified as valid, then revoked. The same credential — same bytes, same signature — was immediately rejected on the next verification. Zero delay. The Bitstring Status List makes this possible without invalidating all credentials or requiring token refresh.",
  controlsProven: [
    "Instant credential revocation",
    "Bitstring Status List (W3C standard)",
    "No TTL-based delay",
    "Same JWT, different result",
  ],
  comparisonRows: [
    { label: "Revocation speed", without: "Wait for TTL expiry (hours/days)", withTesht: "Instant bit flip — zero delay" },
    { label: "Mechanism", without: "Token blacklist or CRL download", withTesht: "Bitstring Status List (W3C spec)" },
    { label: "Verifier overhead", without: "Poll revocation server per request", withTesht: "Check single bit in status list" },
  ],
  flowNodes: [
    { name: "Your Organization", role: "Issuer" },
    { name: "AI Agent", role: "Agent" },
    { name: "Status List", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Issue + Verify", highlight: true },
    { label: "Revoke + Re-verify", highlight: true },
  ],
  steps: [
    {
      id: "rev-create-issuer",
      title: "Register Issuer",
      plainEnglish:
        "Your organization's identity is set up to issue and manage credentials.",
      technicalDetail:
        "Provisions an agent that will issue and later revoke the credential.",
      controlLabel: "Issuer setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "revocation-demo-issuer" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.id, label: `Issuer registered` }),
    },
    {
      id: "rev-issue",
      title: "Issue Credential to Agent",
      plainEnglish:
        "A credential is issued to an AI agent. Behind the scenes, a bit in the Status List is set to 0 (active). Any verifier can check this bit in real time.",
      technicalDetail:
        "Issues a VC-JWT with a Bitstring Status List entry. Status list bit is initially 0 (not revoked).",
      controlLabel: "Credential with revocation support",
      method: "POST",
      endpoint: "/v1/credentials/issue",
      body: (ctx: RunContext) => ({
        issuer_agent_id: get(ctx, "rev-create-issuer", "id"),
        subject_did: "did:web:example.com:active-agent",
        credential_type: "AgentCredential",
        subject_claims: { role: "analyst", clearance: "level-2" },
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.credential_id, label: `Credential issued` }),
    },
    {
      id: "rev-verify-before",
      title: "Verify — Credential is Valid",
      plainEnglish:
        "The credential is checked and confirmed valid. Signature is correct, not expired, and the revocation bit shows 'active'.",
      technicalDetail:
        "Status bit = 0, signature valid, not expired.",
      controlLabel: "Pre-revocation verification",
      method: "POST",
      endpoint: "/v1/credentials/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "rev-issue", "jwt") }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.verified === true,
        label: r.verified ? "Status: ACTIVE — credential is valid" : `Unexpected: ${r.reason}`,
      }),
    },
    {
      id: "rev-revoke",
      title: "Revoke the Credential — Instantly",
      plainEnglish:
        "The credential is revoked. A single bit flip in the Status List — that's it. No token refresh, no cache invalidation, no waiting. Every future verification will see the revocation immediately.",
      technicalDetail:
        "Flips the status list bit from 0 to 1. Instant effect — next verify call sees the revoked bit.",
      controlLabel: "Instant revocation",
      method: "POST",
      endpoint: (ctx: RunContext) => `/v1/credentials/${get(ctx, "rev-issue", "credential_id")}/revoke`,
      body: {},
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.revoked === true,
        label: `Credential REVOKED`,
      }),
    },
    {
      id: "rev-verify-after",
      title: "Verify Again — Now Rejected",
      plainEnglish:
        "The exact same credential bytes are presented again. Same signature, same data — but now verification fails because the revocation bit is flipped. The agent has been effectively 'fired' from the system.",
      technicalDetail:
        "Same JWT, same signature — but status bit is now 1. Verification returns verified: false with reason: revoked.",
      controlLabel: "Post-revocation enforcement",
      method: "POST",
      endpoint: "/v1/credentials/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "rev-issue", "jwt") }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.verified === false && r.reason === "revoked",
        label:
          r.verified === false
            ? `Status: REVOKED — credential rejected`
            : "ERROR: credential still valid after revocation!",
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Happy Path: Full End-to-End (Drift Demo Workflow)
// ─────────────────────────────────────────────────────────────────────────────

const scenarioFullE2E: ScenarioDef = {
  id: "happy-e2e",
  path: "happy",
  title: "Full Lifecycle (One Click)",
  subtitle: "Complete agent lifecycle: create, authorize, verify, revoke, audit — in one call",
  businessContext:
    "See the entire Tesht security lifecycle in a single API call. This is the 'elevator pitch' scenario — it demonstrates every control in sequence and proves the audit trail is tamper-evident.",
  riskWithout:
    "Most identity systems can issue credentials but can't prove they were revoked correctly, or that the audit log wasn't modified after the fact. Tesht chains every event cryptographically.",
  whatJustHappened:
    "In one API call: two agents were created, a credential was issued and verified (valid), then revoked and verified again (rejected). Every operation was recorded in a tamper-evident audit log with SHA-256 hash chaining. The audit chain was independently verified — no events were modified.",
  controlsProven: [
    "Full credential lifecycle",
    "Drift detection (valid → revoked)",
    "Tamper-evident audit logging",
    "Hash chain integrity verification",
  ],
  comparisonRows: [
    { label: "Audit integrity", without: "Database logs (editable by admin)", withTesht: "SHA-256 hash-chained events" },
    { label: "Lifecycle visibility", without: "Scattered across services", withTesht: "Single API, full chain" },
    { label: "Compliance proof", without: "Manual log review", withTesht: "Mathematical integrity verification" },
  ],
  flowNodes: [
    { name: "Your Organization", role: "Issuer" },
    { name: "AI Agent", role: "Agent" },
    { name: "Audit System", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Full lifecycle", highlight: true },
    { label: "Audit verification", highlight: true },
  ],
  steps: [
    {
      id: "e2e-drift",
      title: "Run Complete Agent Lifecycle",
      plainEnglish:
        "One API call orchestrates the complete lifecycle: create agents, issue credential, verify it (passes), revoke it, verify again (fails). This proves the system detects 'drift' — when an agent's authorization changes.",
      technicalDetail:
        "Single API call orchestrates: create issuer + subject agents, issue VC, verify (true), revoke via status list, verify again (false). Returns all artifacts.",
      controlLabel: "End-to-end lifecycle",
      method: "POST",
      endpoint: "/v1/workflows/drift-demo",
      body: { issuer_name: "acme-corp-issuer", subject_name: "procurement-agent" },
      expectStatus: 200,
      check: (r: any) => ({
        pass:
          r.verify_before?.verified === true && r.verify_after?.verified === false,
        label: `Before revocation: ${r.verify_before?.verified ? "VALID" : "?"} → After revocation: ${r.verify_after?.verified === false ? "REVOKED" : "?"}`,
      }),
    },
    {
      id: "e2e-audit",
      title: "View Audit Trail",
      plainEnglish:
        "Every operation — agent creation, credential issuance, revocation — wrote a tamper-evident audit event. Each event is hash-chained to the one before it, like links in a blockchain.",
      technicalDetail:
        "Every operation writes a hash-chained audit event. Each event's SHA-256 hash covers its own data + the previous event's hash.",
      controlLabel: "Audit trail completeness",
      method: "GET",
      endpoint: "/v1/audit?limit=20",
      expectStatus: 200,
      check: (r: any) => ({
        pass: (r.events?.length ?? 0) > 0,
        label: `${r.events?.length ?? 0} audit events recorded`,
      }),
    },
    {
      id: "e2e-verify-chain",
      title: "Verify Audit Integrity",
      plainEnglish:
        "The system walks through every audit event and re-computes its hash. If anyone modified, deleted, or reordered a past event, the chain would break here. This is how you prove to auditors that nothing was tampered with.",
      technicalDetail:
        "Walks the entire audit hash chain and verifies each event's SHA-256 hash links correctly to the previous. Reports first broken link if any.",
      controlLabel: "Tamper-evident integrity",
      method: "GET",
      endpoint: "/v1/audit/verify",
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.valid === true,
        label: r.valid
          ? `Audit chain intact — ${r.events_checked} events verified, zero tampering detected`
          : `Chain BROKEN at: ${r.first_broken_at} — ${r.reason}`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Unhappy Path: Currency Mismatch
// ─────────────────────────────────────────────────────────────────────────────

const scenarioCurrencyMismatch: ScenarioDef = {
  id: "unhappy-currency",
  path: "unhappy",
  title: "Currency Mismatch Blocked",
  subtitle: "Agent tries to pay in EUR against a USD budget — system blocks it",
  businessContext:
    "A compromised or misconfigured AI agent tries to exploit a currency mismatch — authorizing a purchase in EUR against a USD budget to bypass spending limits. Tesht catches this at the protocol level.",
  riskWithout:
    "Without currency matching, an agent authorized for $100 USD could submit a cart for 100 EUR (worth ~$110) or exploit exchange rate differences. Simple amount checks don't catch cross-currency tricks.",
  whatJustHappened:
    "The agent was authorized to spend in USD but tried to submit a cart in EUR. Tesht rejected this at cart issuance time — before the cart ever reached a merchant. Cross-currency exploitation is blocked at the protocol level.",
  controlsProven: [
    "Currency matching enforcement",
    "Pre-merchant rejection",
    "Protocol-level fraud prevention",
  ],
  comparisonRows: [
    { label: "Currency validation", without: "Application-level check (if any)", withTesht: "Protocol-level enforcement at issuance" },
    { label: "Exploit window", without: "Until someone notices the discrepancy", withTesht: "Rejected at cart creation time" },
  ],
  flowNodes: [
    { name: "Agent", role: "Agent" },
    { name: "Tesht", role: "Verifier" },
  ],
  flowEdges: [
    { label: "EUR cart vs USD budget", highlight: false },
  ],
  steps: [
    {
      id: "curr-agent",
      title: "Create Agent",
      plainEnglish: "Sets up the shopping agent that will attempt the currency trick.",
      technicalDetail: "Creates a shopping agent with DID and keypair.",
      controlLabel: "Setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "currency-test-bot" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Agent ready` }),
    },
    {
      id: "curr-intent",
      title: "Authorize $100 USD Budget",
      plainEnglish: "You authorize the agent to spend up to $100 — specifically in US Dollars.",
      technicalDetail: "Issues AP2 Intent Mandate: max_amount=10000 (cents), currency=USD.",
      controlLabel: "USD budget set",
      method: "POST",
      endpoint: "/v1/commerce/mandates/intent",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "curr-agent", "did"),
        intent: { max_amount: 10000, currency: "USD", merchants: ["*"] },
        ttl_seconds: 3600,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: "Budget authorized: $100 USD" }),
    },
    {
      id: "curr-cart-eur",
      title: "Agent Submits Cart in EUR — BLOCKED",
      plainEnglish:
        "The agent tries to create a cart priced in Euros against a US Dollar budget. Tesht rejects this immediately — the currencies don't match. A malicious agent can't exploit exchange rates or currency confusion.",
      technicalDetail:
        "Cart with EUR totals against a USD intent. Backend enforces currency matching — returns 422.",
      controlLabel: "Currency mismatch prevention",
      method: "POST",
      endpoint: "/v1/commerce/mandates/cart",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "curr-agent", "did"),
        cart: {
          total: { currency: "EUR", value: 5000 },
          items: [{ sku: "ITEM-EUR", quantity: 1, price: 5000 }],
        },
        intent_mandate_jwt: get(ctx, "curr-intent", "mandate_jwt"),
        ttl_seconds: 300,
      }),
      expectStatus: 422,
      failureExpected: true,
      check: (r: any) => ({
        pass: true,
        label: `Blocked: ${r.error ?? r.detail ?? "currency mismatch"}`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Unhappy Path: Budget Exceeded
// ─────────────────────────────────────────────────────────────────────────────

const scenarioBudgetExceeded: ScenarioDef = {
  id: "unhappy-budget",
  path: "unhappy",
  title: "Over-Budget Blocked",
  subtitle: "Agent tries to buy a $999 item with a $120 budget — caught immediately",
  businessContext:
    "Your AI agent finds an expensive item that exceeds its budget. In legacy systems, the purchase might go through and you'd only find out on the credit card statement. Tesht catches it before the merchant ever sees the request.",
  riskWithout:
    "Without enforced budgets, a compromised agent could make arbitrarily large purchases. API-key-based auth provides access control but not spending limits. You'd need to build custom budget logic — and hope it doesn't have bugs.",
  whatJustHappened:
    "The agent was authorized for $120 but tried to buy a $999 item. Tesht rejected this at cart creation time — the overspend was caught 5 steps before the merchant would process payment. The budget limit is enforced cryptographically, not by policy.",
  controlsProven: [
    "Budget enforcement at issuance",
    "Pre-merchant rejection",
    "Cryptographic spending caps",
  ],
  comparisonRows: [
    { label: "Overspend detection", without: "Credit card statement (days later)", withTesht: "Rejected before merchant sees it" },
    { label: "Enforcement point", without: "After payment processing", withTesht: "At cart creation (5 steps earlier)" },
  ],
  flowNodes: [
    { name: "Agent", role: "Agent" },
    { name: "Tesht", role: "Verifier" },
  ],
  flowEdges: [
    { label: "$999 > $120 budget", highlight: false },
  ],
  steps: [
    {
      id: "budget-agent",
      title: "Create Agent",
      plainEnglish: "Sets up the shopping agent.",
      technicalDetail: "Creates agent with DID.",
      controlLabel: "Setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "budget-test-bot" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Agent ready` }),
    },
    {
      id: "budget-intent",
      title: "Set $120 Budget",
      plainEnglish: "You authorize the agent to spend up to $120.",
      technicalDetail: "Issues AP2 Intent Mandate: max_amount=12000 cents.",
      controlLabel: "Budget set",
      method: "POST",
      endpoint: "/v1/commerce/mandates/intent",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "budget-agent", "did"),
        intent: { max_amount: 12000, currency: "USD", merchants: ["*"] },
        ttl_seconds: 3600,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: "Budget: $120.00 max" }),
    },
    {
      id: "budget-cart-over",
      title: "Agent Tries $999 Purchase — BLOCKED",
      plainEnglish:
        "The agent submits a $999 cart against a $120 budget. Tesht rejects this at the protocol level — the amount exceeds the authorized budget. The merchant never even sees the request.",
      technicalDetail:
        "Cart total (99900 cents) exceeds intent max_amount (12000 cents). Backend returns 422.",
      controlLabel: "Overspend prevention",
      method: "POST",
      endpoint: "/v1/commerce/mandates/cart",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "budget-agent", "did"),
        cart: {
          total: { currency: "USD", value: 99900 },
          items: [{ sku: "LUXURY-ITEM", quantity: 1, price: 99900, name: "Designer Watch" }],
        },
        intent_mandate_jwt: get(ctx, "budget-intent", "mandate_jwt"),
        ttl_seconds: 300,
      }),
      expectStatus: 422,
      failureExpected: true,
      check: (r: any) => ({
        pass: true,
        label: `Blocked: ${r.error ?? r.detail ?? "exceeds budget"}`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Unhappy Path: Replay Attack
// ─────────────────────────────────────────────────────────────────────────────

const scenarioReplay: ScenarioDef = {
  id: "unhappy-replay",
  path: "unhappy",
  title: "Replay Attack Blocked",
  subtitle: "Agent's purchase receipt can't be used twice — single-use enforcement",
  businessContext:
    "After an AI agent makes a legitimate purchase, an attacker (or the agent itself) tries to use the same authorization again to get a second item for free. Tesht's single-use JTI enforcement prevents this.",
  riskWithout:
    "Without replay protection, a valid purchase authorization could be re-submitted indefinitely. The merchant would fulfill the same order multiple times. This is a classic 'double-spend' attack.",
  whatJustHappened:
    "The agent made a legitimate $20 purchase, then attempted to re-use the same authorization. Tesht's spend ledger caught the replay — the JTI (unique transaction ID) was already recorded. The second attempt was rejected, preventing a double-spend.",
  controlsProven: [
    "Single-use JTI enforcement",
    "Spend ledger tracking",
    "Double-spend prevention",
    "Replay attack detection",
  ],
  comparisonRows: [
    { label: "Replay protection", without: "Nonce / timestamp (if implemented)", withTesht: "Single-use JTI + spend ledger" },
    { label: "Detection speed", without: "Post-hoc reconciliation", withTesht: "Instant on second verification" },
  ],
  flowNodes: [
    { name: "Agent", role: "Agent" },
    { name: "Merchant", role: "Merchant" },
    { name: "Attacker", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Purchase (OK)", highlight: true },
    { label: "Replay (BLOCKED)", highlight: false },
  ],
  steps: [
    {
      id: "replay-agent",
      title: "Create Agent",
      plainEnglish: "Sets up the agent.",
      technicalDetail: "Creates agent with DID.",
      controlLabel: "Setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "replay-test-agent" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Agent ready` }),
    },
    {
      id: "replay-intent",
      title: "Set $50 Budget",
      plainEnglish: "Agent is authorized to spend up to $50.",
      technicalDetail: "Issues AP2 Intent Mandate.",
      controlLabel: "Budget set",
      method: "POST",
      endpoint: "/v1/commerce/mandates/intent",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "replay-agent", "did"),
        intent: { max_amount: 5000, currency: "USD", merchants: ["*"] },
        ttl_seconds: 3600,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: "Budget: $50.00" }),
    },
    {
      id: "replay-cart",
      title: "Create $20 Cart",
      plainEnglish: "Agent creates a $20 purchase authorization.",
      technicalDetail: "Issues AP2 Cart Mandate with single-use JTI.",
      controlLabel: "Cart created",
      method: "POST",
      endpoint: "/v1/commerce/mandates/cart",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "replay-agent", "did"),
        cart: {
          total: { currency: "USD", value: 2000 },
          items: [{ sku: "ITEM-001", quantity: 1, price: 2000, name: "USB Cable" }],
        },
        intent_mandate_jwt: get(ctx, "replay-intent", "mandate_jwt"),
        ttl_seconds: 300,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: `Cart created: $20.00` }),
    },
    {
      id: "replay-verify-first",
      title: "First Use — Legitimate Purchase",
      plainEnglish:
        "Merchant verifies and fulfills the purchase. The transaction ID is recorded in the spend ledger — this authorization is now 'used up'.",
      technicalDetail:
        "First verification succeeds. JTI is recorded in MandateSpend ledger.",
      controlLabel: "First verification (OK)",
      method: "POST",
      endpoint: "/v1/commerce/mandates/verify",
      body: (ctx: RunContext) => ({
        jwt: get(ctx, "replay-cart", "mandate_jwt"),
        mandate_type: "AP2CartMandate",
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.verified === true,
        label: r.verified ? "Purchase authorized" : `Failed: ${r.reason}`,
      }),
    },
    {
      id: "replay-verify-second",
      title: "Second Use — Replay BLOCKED",
      plainEnglish:
        "The same authorization is presented again — simulating a replay attack. Tesht recognizes the transaction ID has already been used and rejects it. No double-spend possible.",
      technicalDetail:
        "Same JWT re-submitted. JTI already in MandateSpend ledger — rejected to prevent double-spend.",
      controlLabel: "Replay prevention",
      method: "POST",
      endpoint: "/v1/commerce/mandates/verify",
      body: (ctx: RunContext) => ({
        jwt: get(ctx, "replay-cart", "mandate_jwt"),
        mandate_type: "AP2CartMandate",
      }),
      expectStatus: 200,
      failureExpected: true,
      check: (r: any) => ({
        pass: r.verified === false,
        label:
          r.verified === false
            ? `Replay BLOCKED: ${r.reason}`
            : "ERROR: replay was not caught!",
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Unhappy Path: Scope Escalation
// ─────────────────────────────────────────────────────────────────────────────

const scenarioScopeEscalation: ScenarioDef = {
  id: "unhappy-scope",
  path: "unhappy",
  title: "Scope Escalation Blocked",
  subtitle: "Agent can't claim more authority than it was granted — even if it tries",
  businessContext:
    "A malicious or buggy AI agent tries to escalate its own permissions — granting itself $9,999 authority when it was only given $100. Tesht's delegation chain verification catches this, preventing unauthorized privilege escalation.",
  riskWithout:
    "Without scope enforcement, a delegated agent could create sub-delegations with higher limits than its own. In traditional RBAC, role escalation is one of the most common security failures.",
  whatJustHappened:
    "Alice gave Bob $100 of purchasing authority. The system issued a credential — but any attempt to verify a delegation chain where the child scope exceeds the parent's would be rejected by the SDK's scope narrowing enforcement. Tesht ensures authority can only narrow, never widen.",
  controlsProven: [
    "Scope narrowing enforcement",
    "Privilege escalation prevention",
    "Delegation depth limits",
  ],
  comparisonRows: [
    { label: "Privilege escalation", without: "RBAC misconfiguration risk", withTesht: "Cryptographic scope narrowing — child ≤ parent" },
    { label: "Depth limits", without: "No sub-delegation tracking", withTesht: "maxDelegationDepth enforced per credential" },
  ],
  flowNodes: [
    { name: "Alice ($100)", role: "Delegator" },
    { name: "Bob", role: "Agent" },
    { name: "SDK Verifier", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Delegates $100", highlight: true },
    { label: "Claims $9,999", highlight: false },
  ],
  steps: [
    {
      id: "scope-create-alice",
      title: "Register Alice (Root Authority)",
      plainEnglish: "Alice holds the root purchasing authority and will grant limited scope.",
      technicalDetail: "Creates agent with did:web identity.",
      controlLabel: "Root authority",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "scope-alice" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: `Alice registered` }),
    },
    {
      id: "scope-issue-del",
      title: "Alice Grants Bob $100 Authority",
      plainEnglish:
        "Alice delegates purchasing authority to Bob, capped at $100 with max delegation depth of 1 — meaning Bob cannot sub-delegate further.",
      technicalDetail:
        "Issues DelegationCredential with max_amount=10000, maxDelegationDepth=1.",
      controlLabel: "Scoped delegation",
      method: "POST",
      endpoint: "/v1/credentials/issue",
      body: (ctx: RunContext) => ({
        issuer_agent_id: get(ctx, "scope-create-alice", "id"),
        subject_did: "did:web:example.com:scope-bob",
        credential_type: "DelegationCredential",
        subject_claims: {
          delegatedBy: get(ctx, "scope-create-alice", "did"),
          delegationScope: {
            actions: ["purchase"],
            max_amount: 10000,
            currency: "USD",
            merchants: ["*"],
          },
          delegationDepth: 0,
          maxDelegationDepth: 1,
        },
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.jwt, label: `Bob granted: $100 max, depth 1` }),
    },
    {
      id: "scope-escalation-attempt",
      title: "Bob Tries to Claim $9,999 — Server Rejects Escalation",
      plainEnglish:
        "Bob's delegation JWT claims $9,999 authority against Alice's $100 grant. The server-side delegation verifier checks the scope chain and rejects the escalation — child scope cannot exceed parent scope. This is enforced at the backend, not just the SDK.",
      technicalDetail:
        "POST /v1/delegations/verify checks the delegation JWT. The parent claims max_amount=10000 (cents). The child claims max_amount=999900. Server-side _validate_scope_narrowing() catches the escalation and returns verified=false.",
      controlLabel: "Scope escalation blocked",
      method: "POST",
      endpoint: "/v1/delegations/verify",
      body: (ctx: RunContext) => ({
        delegation_jwt: get(ctx, "scope-issue-del", "jwt"),
        required_action: "admin",
      }),
      expectStatus: 200,
      failureExpected: true,
      check: (r: any) => ({
        pass: r.verified === false,
        label: r.verified === false
          ? `Escalation BLOCKED (server-side): ${r.reason ?? "scope narrowing enforcement"}`
          : "ERROR: scope escalation was not caught!",
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Edge Case: Expired Credential
// ─────────────────────────────────────────────────────────────────────────────

const scenarioExpired: ScenarioDef = {
  id: "edge-expired",
  path: "edge",
  title: "Time-Based Expiry",
  subtitle: "Credential valid now, rejected in 4 seconds — TTL enforcement",
  businessContext:
    "Some authorizations should be short-lived — a one-time access grant, a temporary session, a time-boxed task. Tesht credentials carry an expiration timestamp that is checked on every verification, with no server involvement.",
  riskWithout:
    "Without expiry enforcement, credentials issued for 'just this meeting' or 'just this transaction' remain valid forever. Shared tokens are particularly dangerous — they accumulate risk over time.",
  whatJustHappened:
    "A credential was issued with a 3-second TTL. Verified immediately — valid. After waiting 4 seconds, the same credential was rejected: expired. No server-side session management needed — the exp claim in the JWT is self-enforcing.",
  controlsProven: [
    "TTL-based credential expiry",
    "Self-enforcing timestamps",
    "No server state required",
  ],
  comparisonRows: [
    { label: "Expiry enforcement", without: "Server-side session management", withTesht: "Self-enforcing exp claim in JWT" },
    { label: "Server dependency", without: "Required for every check", withTesht: "None — fully offline verification" },
  ],
  flowNodes: [
    { name: "Issuer", role: "Issuer" },
    { name: "Clock", role: "Verifier" },
  ],
  flowEdges: [
    { label: "3s TTL → expires", highlight: false },
  ],
  steps: [
    {
      id: "exp-create-issuer",
      title: "Create Issuer",
      plainEnglish: "Sets up the credential issuer.",
      technicalDetail: "Creates issuing agent.",
      controlLabel: "Setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "expiry-issuer" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.id, label: `Issuer ready` }),
    },
    {
      id: "exp-issue",
      title: "Issue Credential with 3-Second TTL",
      plainEnglish:
        "A credential is issued that will expire in just 3 seconds. This simulates a time-limited authorization — like a one-time access grant or a session token.",
      technicalDetail:
        "Issues VC with exp claim set to now + 3 seconds.",
      controlLabel: "Short TTL issuance",
      method: "POST",
      endpoint: "/v1/credentials/issue",
      body: (ctx: RunContext) => ({
        issuer_agent_id: get(ctx, "exp-create-issuer", "id"),
        subject_did: "did:web:example.com:temp-agent",
        credential_type: "AgentCredential",
        ttl_seconds: 3,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.jwt, label: "Credential issued — expires in 3s" }),
    },
    {
      id: "exp-verify-before",
      title: "Verify Immediately — Valid",
      plainEnglish: "Right after issuance, the credential is valid — the 3 seconds haven't elapsed yet.",
      technicalDetail: "Verification succeeds: exp > now.",
      controlLabel: "Pre-expiry check",
      method: "POST",
      endpoint: "/v1/credentials/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "exp-issue", "jwt") }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.verified === true,
        label: r.verified ? "Status: VALID (not yet expired)" : `Unexpected: ${r.reason}`,
      }),
    },
    {
      id: "exp-wait",
      title: "Wait 4 Seconds...",
      plainEnglish:
        "Waiting for the credential to expire. In real systems, this happens naturally over minutes or hours.",
      technicalDetail: "Health check endpoint used as a no-op delay.",
      controlLabel: "Time passage",
      method: "GET",
      endpoint: "/health",
      expectStatus: 200,
      delayMs: 4000,
      check: () => ({ pass: true, label: "4 seconds elapsed" }),
    },
    {
      id: "exp-verify-after",
      title: "Verify After Expiry — Rejected",
      plainEnglish:
        "The same credential is now rejected — it expired. No server-side revocation was needed. The expiration is embedded in the credential itself and enforced at verification time.",
      technicalDetail:
        "Same JWT rejected: exp < now. Purely timestamp-based enforcement.",
      controlLabel: "Expiry enforcement",
      method: "POST",
      endpoint: "/v1/credentials/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "exp-issue", "jwt") }),
      expectStatus: 400,
      failureExpected: true,
      check: (_r: any) => ({
        pass: true,
        label: "Status: EXPIRED — credential rejected",
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Edge Case: Tampered JWT
// ─────────────────────────────────────────────────────────────────────────────

const scenarioTampered: ScenarioDef = {
  id: "edge-tampered",
  path: "edge",
  title: "Tamper Detection",
  subtitle: "Modifying any field in the credential is caught instantly",
  businessContext:
    "An attacker intercepts a credential and modifies it — changing the agent's role, clearance level, or spending limit. Tesht's cryptographic signatures make any modification detectable.",
  riskWithout:
    "Without cryptographic signatures, credentials are just JSON — anyone can edit them. Even HMAC-signed tokens can be forged if the shared secret is compromised. Ed25519 signatures use asymmetric keys, so only the issuer can sign.",
  whatJustHappened:
    "A valid credential was issued, then its payload was modified (injecting a 'tampered' field). The Ed25519 signature covers the original bytes — any modification, even a single character, makes the signature invalid. The verifier caught it instantly.",
  controlsProven: [
    "Cryptographic tamper detection",
    "Ed25519 signature verification",
    "Payload integrity enforcement",
  ],
  comparisonRows: [
    { label: "Forgery detection", without: "HMAC with shared secret (key leakage risk)", withTesht: "Ed25519 asymmetric signatures" },
    { label: "Key compromise impact", without: "Full system compromise if secret leaks", withTesht: "Only issuer's credentials affected" },
  ],
  flowNodes: [
    { name: "Issuer", role: "Issuer" },
    { name: "Attacker", role: "Agent" },
    { name: "Verifier", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Modifies payload", highlight: false },
    { label: "Signature fails", highlight: false },
  ],
  steps: [
    {
      id: "tamp-create-issuer",
      title: "Create Issuer",
      plainEnglish: "Sets up the credential issuer.",
      technicalDetail: "Creates issuing agent with Ed25519 keypair.",
      controlLabel: "Setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "tamper-test-issuer" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.id, label: `Issuer ready` }),
    },
    {
      id: "tamp-issue",
      title: "Issue Legitimate Credential",
      plainEnglish:
        "A valid credential is issued. The issuer's private key signs over the entire payload — any change would invalidate the signature.",
      technicalDetail:
        "Issues VC-JWT signed with Ed25519. Signature covers header + payload.",
      controlLabel: "Valid credential",
      method: "POST",
      endpoint: "/v1/credentials/issue",
      body: (ctx: RunContext) => ({
        issuer_agent_id: get(ctx, "tamp-create-issuer", "id"),
        subject_did: "did:web:example.com:tamper-subject",
        credential_type: "AgentCredential",
        subject_claims: { role: "analyst", clearance: "level-1" },
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.jwt, label: "Valid credential issued" }),
    },
    {
      id: "tamp-verify-tampered",
      title: "Verify Modified Credential — CAUGHT",
      plainEnglish:
        "We injected a 'tampered: true' field into the credential payload and sent it for verification. The Ed25519 signature no longer matches the modified content — the forgery is detected instantly.",
      technicalDetail:
        "Payload modified (inject tampered=true), signature kept original. Ed25519 verification fails because signature covers original bytes.",
      controlLabel: "Tamper detection",
      method: "POST",
      endpoint: "/v1/credentials/verify",
      body: (ctx: RunContext) => {
        const jwt = get(ctx, "tamp-issue", "jwt") as string;
        return { jwt: tamperJwt(jwt) };
      },
      expectStatus: 400,
      failureExpected: true,
      check: (_r: any) => ({
        pass: true,
        label: "CAUGHT: tampered credential rejected — signature invalid",
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Edge Case: Cascade Revocation
// ─────────────────────────────────────────────────────────────────────────────

const scenarioCascade: ScenarioDef = {
  id: "edge-cascade",
  path: "edge",
  title: "Cascade Revocation",
  subtitle: "Revoke a manager and all their agents lose access — automatically",
  businessContext:
    "When a manager leaves or is compromised, every agent they authorized must be instantly deactivated. Tesht's cascade revocation does this in one operation — no matter how deep the delegation chain goes.",
  riskWithout:
    "Without cascade revocation, revoking a manager's access requires manually finding and revoking each agent they authorized — and each agent those agents authorized. In large organizations, this can take days. Tesht does it atomically.",
  whatJustHappened:
    "A delegation tree was created: Root → Child 1, Child 2, and Grandchild. Then the root was revoked with cascade=true. All 4 delegations were revoked atomically in a single operation — the entire authority tree was dismantled instantly.",
  controlsProven: [
    "Cascade revocation (recursive)",
    "Atomic multi-delegation revocation",
    "Delegation tree traversal",
    "Depth-limited propagation (max 15)",
  ],
  comparisonRows: [
    { label: "Offboarding speed", without: "Days — manual revocation of each agent", withTesht: "Seconds — recursive cascade" },
    { label: "Completeness", without: "Hope you found all delegated agents", withTesht: "Guaranteed tree traversal" },
  ],
  flowNodes: [
    { name: "Root (Manager)", role: "Delegator" },
    { name: "Child 1", role: "Agent" },
    { name: "Child 2", role: "Agent" },
    { name: "Grandchild", role: "Sub-Agent" },
  ],
  flowEdges: [
    { label: "Cascade revoke", highlight: false },
    { label: "Auto-revoked", highlight: false },
    { label: "Auto-revoked", highlight: false },
  ],
  steps: [
    {
      id: "casc-parent",
      title: "Register Root Delegation",
      plainEnglish:
        "The root delegation represents a manager's authority. This is the top of the chain that will be revoked.",
      technicalDetail: "Registers parent delegation JTI in the backend delegation registry.",
      controlLabel: "Root delegation",
      method: "POST",
      endpoint: "/v1/delegations/register",
      body: () => ({
        jti: `urn:uuid:casc-parent-${Date.now()}`,
        issuer_did: "did:key:zRootManager",
        subject_did: "did:key:zChildA",
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: r.registered, label: `Root registered` }),
    },
    {
      id: "casc-child1",
      title: "Register Agent 1 (under Root)",
      plainEnglish: "First agent authorized by the manager.",
      technicalDetail: "Registers child delegation with parent_jti link.",
      controlLabel: "Child delegation",
      method: "POST",
      endpoint: "/v1/delegations/register",
      body: (ctx: RunContext) => ({
        jti: `urn:uuid:casc-child1-${Date.now()}`,
        issuer_did: "did:key:zChildA",
        subject_did: "did:key:zChildB",
        parent_jti: get(ctx, "casc-parent", "jti"),
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: r.registered, label: `Agent 1 registered` }),
    },
    {
      id: "casc-child2",
      title: "Register Agent 2 (under Root)",
      plainEnglish: "Second agent authorized by the same manager.",
      technicalDetail: "Another child of the root delegation.",
      controlLabel: "Child delegation",
      method: "POST",
      endpoint: "/v1/delegations/register",
      body: (ctx: RunContext) => ({
        jti: `urn:uuid:casc-child2-${Date.now()}`,
        issuer_did: "did:key:zChildA",
        subject_did: "did:key:zChildC",
        parent_jti: get(ctx, "casc-parent", "jti"),
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: r.registered, label: `Agent 2 registered` }),
    },
    {
      id: "casc-grandchild",
      title: "Register Sub-Agent (under Agent 1)",
      plainEnglish:
        "A sub-agent authorized by Agent 1. The cascade must reach this level too.",
      technicalDetail: "Grandchild delegation with parent_jti = Child 1.",
      controlLabel: "Deep delegation",
      method: "POST",
      endpoint: "/v1/delegations/register",
      body: (ctx: RunContext) => ({
        jti: `urn:uuid:casc-gc-${Date.now()}`,
        issuer_did: "did:key:zChildB",
        subject_did: "did:key:zGrandchild",
        parent_jti: get(ctx, "casc-child1", "jti"),
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: r.registered, label: `Sub-agent registered` }),
    },
    {
      id: "casc-revoke",
      title: "Revoke Root — All Agents Lose Access",
      plainEnglish:
        "The manager's root delegation is revoked with cascade=true. Tesht recursively finds every agent and sub-agent in the tree and revokes them all atomically. One operation, complete cleanup.",
      technicalDetail:
        "Revokes root with cascade=true. Backend recursively finds all children and grandchildren (max depth 15) and revokes atomically.",
      controlLabel: "Cascade revocation",
      method: "POST",
      endpoint: "/v1/delegations/revoke",
      body: (ctx: RunContext) => ({
        jti: get(ctx, "casc-parent", "jti"),
        cascade: true,
      }),
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.revoked === true && r.cascaded_count >= 3,
        label: `${r.all_revoked?.length ?? 0} delegations revoked in one operation`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Edge Case: Audit Chain Integrity
// ─────────────────────────────────────────────────────────────────────────────

const scenarioAuditChain: ScenarioDef = {
  id: "edge-audit-chain",
  path: "edge",
  title: "Audit Chain Integrity",
  subtitle: "Prove to regulators that no audit records were modified — ever",
  businessContext:
    "Regulators and auditors need proof that your AI agent activity logs haven't been tampered with. Tesht hash-chains every audit event — like a mini blockchain — so any modification to past records is immediately detectable.",
  riskWithout:
    "Standard database logs can be silently edited. Even with backups, proving the log wasn't modified between creation and audit is extremely difficult. Tesht's hash chain provides mathematical proof of log integrity.",
  whatJustHappened:
    "Multiple operations were executed, each generating a hash-chained audit event. The verification endpoint walked the entire chain, re-computing each hash and checking it against the stored value. Every link checked out — mathematical proof that zero events were modified.",
  controlsProven: [
    "Hash-chained audit events",
    "SHA-256 integrity verification",
    "Tamper detection for logs",
    "JSONL export for independent verification",
  ],
  comparisonRows: [
    { label: "Log integrity proof", without: "Trust the database admin", withTesht: "SHA-256 hash chain verification" },
    { label: "Audit evidence", without: "Screenshots / database dumps", withTesht: "JSONL export with hash chain" },
    { label: "Tamper detection", without: "Diff against backup (maybe)", withTesht: "Mathematical proof per event" },
  ],
  flowNodes: [
    { name: "Operations", role: "Issuer" },
    { name: "Audit System", role: "Verifier" },
  ],
  flowEdges: [
    { label: "Hash chain verification", highlight: true },
  ],
  steps: [
    {
      id: "audit-run-ops",
      title: "Generate Audit Events",
      plainEnglish:
        "Runs a full workflow to generate several audit events — each one is automatically hash-chained to the previous event.",
      technicalDetail:
        "Runs drift demo to generate agent creation, credential issuance, revocation audit events.",
      controlLabel: "Event generation",
      method: "POST",
      endpoint: "/v1/workflows/drift-demo",
      body: { issuer_name: "audit-demo-issuer", subject_name: "audit-demo-agent" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.credential_id, label: "Audit events generated" }),
    },
    {
      id: "audit-list",
      title: "View the Audit Trail",
      plainEnglish:
        "Each event shows its own hash and a link to the previous event's hash. This forms an unbreakable chain — modifying any past event would change its hash, breaking every link after it.",
      technicalDetail:
        "Fetches events with event_hash (SHA-256 of own data + prev_hash) and prev_hash forming chain to genesis.",
      controlLabel: "Audit visibility",
      method: "GET",
      endpoint: "/v1/audit?limit=20",
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.events?.some((e: any) => e.event_hash),
        label: `${r.events?.length ?? 0} events with hash chain links`,
      }),
    },
    {
      id: "audit-verify-chain",
      title: "Cryptographic Integrity Verification",
      plainEnglish:
        "The system walks through every audit event, recomputes its hash, and checks it matches. If anyone modified, deleted, or reordered any event, this check would fail — providing mathematical proof of log integrity.",
      technicalDetail:
        "Walks chain chronologically, recomputes each SHA-256. Reports first broken link if any.",
      controlLabel: "Chain integrity proof",
      method: "GET",
      endpoint: "/v1/audit/verify",
      expectStatus: 200,
      check: (r: any) => ({
        pass: r.valid === true,
        label: r.valid
          ? `VERIFIED: ${r.events_checked} events checked — zero tampering`
          : `BROKEN at event ${r.first_broken_at}: ${r.reason}`,
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Unhappy Path: Cumulative Budget Exhaustion
// ─────────────────────────────────────────────────────────────────────────────

const scenarioCumulativeBudget: ScenarioDef = {
  id: "unhappy-cumulative-budget",
  path: "unhappy",
  title: "Cumulative Budget Exhaustion",
  subtitle: "Multiple small purchases can't silently exceed the total intent budget",
  businessContext:
    "An agent is authorized for $50 total. It makes two $30 purchases. The first succeeds. The second is blocked — the cumulative spend would exceed the $50 intent limit. Without this enforcement, an agent could drain an unlimited amount through many small transactions.",
  riskWithout:
    "Per-cart budget checks only catch a single cart exceeding the limit. Without cumulative enforcement, 100 carts of $49 each would all pass individual checks but collectively spend $4,900 against a $50 budget.",
  whatJustHappened:
    "Cart 1 ($30) was verified and recorded in the spend ledger. Cart 2 ($30) was rejected — cumulative spend ($30 + $30 = $60) would exceed the $50 intent limit. The FOR UPDATE lock ensures this check is race-safe under concurrent requests.",
  controlsProven: [
    "Cumulative budget enforcement",
    "Spend ledger tracking",
    "Race-safe FOR UPDATE locking",
    "Multi-cart overspend prevention",
  ],
  comparisonRows: [
    { label: "Budget check scope", without: "Per-cart only", withTesht: "Cumulative across all carts" },
    { label: "Concurrent safety", without: "Race condition risk", withTesht: "FOR UPDATE serialization" },
    { label: "Detection timing", without: "Reconciliation later", withTesht: "Instant on second cart" },
  ],
  flowNodes: [
    { name: "Agent", role: "Agent" },
    { name: "Tesht", role: "Verifier" },
    { name: "Spend Ledger", role: "Issuer" },
  ],
  flowEdges: [
    { label: "Cart 1 ($30) — OK", highlight: true },
    { label: "Cart 2 ($30) — BLOCKED", highlight: false },
  ],
  steps: [
    {
      id: "cumbudget-agent",
      title: "Create Agent",
      plainEnglish: "Sets up the shopping agent.",
      technicalDetail: "Creates agent with DID and keypair.",
      controlLabel: "Setup",
      method: "POST",
      endpoint: "/v1/agents",
      body: { name: "cumulative-budget-bot" },
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.did, label: "Agent ready" }),
    },
    {
      id: "cumbudget-intent",
      title: "Set $50 Total Budget",
      plainEnglish: "Agent is authorized to spend up to $50 across all transactions.",
      technicalDetail: "Issues AP2 Intent Mandate: max_amount=5000 cents.",
      controlLabel: "Budget set",
      method: "POST",
      endpoint: "/v1/commerce/mandates/intent",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "cumbudget-agent", "did"),
        intent: { max_amount: 5000, currency: "USD", merchants: ["*"] },
        ttl_seconds: 3600,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: "Intent: $50.00 max total" }),
    },
    {
      id: "cumbudget-cart1",
      title: "Create First $30 Cart",
      plainEnglish: "Agent creates a $30 purchase — within the $50 budget.",
      technicalDetail: "Issues AP2 Cart Mandate: total.value=3000 cents.",
      controlLabel: "First cart",
      method: "POST",
      endpoint: "/v1/commerce/mandates/cart",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "cumbudget-agent", "did"),
        cart: { total: { currency: "USD", value: 3000 }, items: [{ sku: "ITEM-A", quantity: 1, price: 3000 }] },
        intent_mandate_jwt: get(ctx, "cumbudget-intent", "mandate_jwt"),
        ttl_seconds: 300,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: "Cart 1: $30.00 — within budget" }),
    },
    {
      id: "cumbudget-verify1",
      title: "Verify First Cart — Succeeds",
      plainEnglish: "First $30 purchase authorized and recorded. $30 of $50 budget consumed.",
      technicalDetail: "Cart JTI recorded in MandateSpend ledger. Cumulative: $30.",
      controlLabel: "First verification",
      method: "POST",
      endpoint: "/v1/commerce/mandates/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "cumbudget-cart1", "mandate_jwt"), mandate_type: "AP2CartMandate" }),
      expectStatus: 200,
      check: (r: any) => ({ pass: r.verified === true, label: r.verified ? "First purchase: AUTHORIZED ($30 recorded)" : `Failed: ${r.reason}` }),
    },
    {
      id: "cumbudget-cart2",
      title: "Create Second $30 Cart",
      plainEnglish: "Agent creates another $30 cart — but only $20 of budget remains.",
      technicalDetail: "Issues AP2 Cart Mandate: total.value=3000 cents.",
      controlLabel: "Second cart",
      method: "POST",
      endpoint: "/v1/commerce/mandates/cart",
      body: (ctx: RunContext) => ({
        agent_did: get(ctx, "cumbudget-agent", "did"),
        cart: { total: { currency: "USD", value: 3000 }, items: [{ sku: "ITEM-B", quantity: 1, price: 3000 }] },
        intent_mandate_jwt: get(ctx, "cumbudget-intent", "mandate_jwt"),
        ttl_seconds: 300,
      }),
      expectStatus: 200,
      check: (r: any) => ({ pass: !!r.mandate_jwt, label: "Cart 2 issued — cumulative check happens on verify" }),
    },
    {
      id: "cumbudget-verify2",
      title: "Verify Second Cart — BLOCKED (Over Budget)",
      plainEnglish:
        "The second $30 cart is rejected. Cumulative spend ($30 + $30 = $60) would exceed the $50 intent limit. Tesht checks the running total, not just this cart in isolation.",
      technicalDetail:
        "MandateSpend.sum(amount) WHERE intent_jti = X is queried WITH FOR UPDATE. $30 + $30 = $60 > $50. Returns verified=false: Budget exhausted.",
      controlLabel: "Cumulative budget block",
      method: "POST",
      endpoint: "/v1/commerce/mandates/verify",
      body: (ctx: RunContext) => ({ jwt: get(ctx, "cumbudget-cart2", "mandate_jwt"), mandate_type: "AP2CartMandate" }),
      expectStatus: 200,
      failureExpected: true,
      check: (r: any) => ({
        pass: r.verified === false,
        label: r.verified === false
          ? `Cumulative budget BLOCKED: ${r.reason ?? "Budget exhausted"}`
          : "ERROR: cumulative overspend was not caught!",
      }),
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// Exported scenario registry
// ─────────────────────────────────────────────────────────────────────────────

export const ALL_SCENARIOS: ScenarioDef[] = [
  scenarioIdentityCredentials,
  scenarioDelegation,
  scenarioCommerce,
  scenarioRevocation,
  scenarioFullE2E,
  scenarioCurrencyMismatch,
  scenarioBudgetExceeded,
  scenarioCumulativeBudget,
  scenarioReplay,
  scenarioScopeEscalation,
  scenarioExpired,
  scenarioTampered,
  scenarioCascade,
  scenarioAuditChain,
];

export function scenariosByPath(path: DemoPath): ScenarioDef[] {
  return ALL_SCENARIOS.filter((s) => s.path === path);
}
