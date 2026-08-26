import { describe, it, expect } from "vitest";
import { AgentIdentity } from "../src/identity.js";
import {
  issueDelegation,
  delegateFurther,
  verifyDelegationChain,
  intersectScopes,
  ScopeEscalationError,
  type Scope,
} from "../src/delegation.js";

// ── Scope intersection ────────────────────────────────────────────────────────

describe("intersectScopes", () => {
  it("intersects actions to common subset", () => {
    const parent: Scope = { actions: ["read", "write", "delete"] };
    const child: Scope = { actions: ["read", "write"] };
    const result = intersectScopes(parent, child);
    expect(result.actions).toEqual(["read", "write"]);
  });

  it("child cannot add actions not in parent", () => {
    const parent: Scope = { actions: ["read"] };
    const child: Scope = { actions: ["read", "write"] };
    // intersectScopes filters to common, so write is dropped
    const result = intersectScopes(parent, child);
    expect(result.actions).toEqual(["read"]);
  });

  it("takes minimum of maxAmount", () => {
    const parent: Scope = { maxAmount: 100, currency: "USD" };
    const child: Scope = { maxAmount: 50, currency: "USD" };
    const result = intersectScopes(parent, child);
    expect(result.maxAmount).toBe(50);
  });

  it("parent maxAmount wins when child is higher", () => {
    const parent: Scope = { maxAmount: 100, currency: "USD" };
    const child: Scope = { maxAmount: 200, currency: "USD" };
    const result = intersectScopes(parent, child);
    expect(result.maxAmount).toBe(100);
  });

  it("throws ScopeEscalationError on currency mismatch", () => {
    const parent: Scope = { currency: "USD" };
    const child: Scope = { currency: "EUR" };
    expect(() => intersectScopes(parent, child)).toThrow(ScopeEscalationError);
  });

  it("throws ScopeEscalationError on merchant escalation", () => {
    const parent: Scope = { merchants: ["amazon"] };
    const child: Scope = { merchants: ["amazon", "shopify"] };
    expect(() => intersectScopes(parent, child)).toThrow(ScopeEscalationError);
  });

  it("child merchants must be subset of parent", () => {
    const parent: Scope = { merchants: ["amazon", "shopify", "ebay"] };
    const child: Scope = { merchants: ["amazon"] };
    const result = intersectScopes(parent, child);
    expect(result.merchants).toEqual(["amazon"]);
  });

  it("inherits parent scope when child does not specify", () => {
    const parent: Scope = { actions: ["read", "write"], maxAmount: 500 };
    const child: Scope = {};
    const result = intersectScopes(parent, child);
    expect(result.actions).toEqual(["read", "write"]);
    expect(result.maxAmount).toBe(500);
  });
});

// ── issueDelegation ───────────────────────────────────────────────────────────

describe("issueDelegation", () => {
  it("returns a valid JWT", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, { actions: ["read"] });
    expect(jwt.split(".")).toHaveLength(3);
  });

  it("JWT payload has del claim with scope and depth=0", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, { actions: ["read", "write"] });
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.vc.credentialSubject.delegationDepth).toBe(0);
    expect(payload.vc.credentialSubject.delegationScope.actions).toEqual(["read", "write"]);
    expect(payload.vc.credentialSubject.parentDelegation).toBeUndefined();
  });

  it("iss and sub are set correctly", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, {});
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.iss).toBe(root.did);
    expect(payload.sub).toBe(delegate.did);
  });
});

// ── verifyDelegationChain — single link ────────────────────────────────────────

describe("verifyDelegationChain single link", () => {
  it("verifies a single root delegation", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, { actions: ["read"] });
    const result = await verifyDelegationChain([jwt]);
    expect(result.valid).toBe(true);
    expect(result.delegator).toBe(root.did);
    expect(result.delegate).toBe(delegate.did);
  });

  it("fails on expired delegation", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, {}, { ttlSeconds: -10 });
    const result = await verifyDelegationChain([jwt]);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("expir");
  });

  it("fails on empty chain", async () => {
    const result = await verifyDelegationChain([]);
    expect(result.valid).toBe(false);
  });

  it("returns effective scope in result", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const scope: Scope = { actions: ["pay"], maxAmount: 100, currency: "USD" };
    const jwt = await issueDelegation(root, delegate.did, scope);
    const result = await verifyDelegationChain([jwt]);
    expect(result.valid).toBe(true);
    expect(result.scope?.actions).toEqual(["pay"]);
    expect(result.scope?.maxAmount).toBe(100);
  });
});

// ── delegateFurther and multi-link chain ──────────────────────────────────────

describe("delegateFurther", () => {
  it("creates a valid two-level delegation chain", async () => {
    const root = await AgentIdentity.create("root");
    const middle = await AgentIdentity.create("middle");
    const leaf = await AgentIdentity.create("leaf");

    const rootJwt = await issueDelegation(root, middle.did, {
      actions: ["read", "write"],
      maxAmount: 500,
    });

    const childJwt = await delegateFurther(middle, rootJwt, leaf.did, {
      actions: ["read"],
      maxAmount: 200,
    });

    const result = await verifyDelegationChain([rootJwt, childJwt]);
    expect(result.valid).toBe(true);
    expect(result.delegator).toBe(root.did);
    expect(result.delegate).toBe(leaf.did);
    expect(result.depth).toBe(1);
  });

  it("scope is narrowed — child maxAmount is capped at parent limit", async () => {
    const root = await AgentIdentity.create("root");
    const middle = await AgentIdentity.create("middle");
    const leaf = await AgentIdentity.create("leaf");

    const rootJwt = await issueDelegation(root, middle.did, {
      actions: ["pay"],
      maxAmount: 100,
      currency: "USD",
    });

    // Child requests 200 but parent only allows 100 — intersectScopes caps it
    const childJwt = await delegateFurther(middle, rootJwt, leaf.did, {
      actions: ["pay"],
      maxAmount: 200,
      currency: "USD",
    });

    const result = await verifyDelegationChain([rootJwt, childJwt]);
    expect(result.valid).toBe(true);
    // scope is capped at parent's 100
    expect(result.scope?.maxAmount).toBe(100);
  });

  it("scope narrowing via intersectScopes caps maxAmount", async () => {
    const root = await AgentIdentity.create("root");
    const middle = await AgentIdentity.create("middle");
    const leaf = await AgentIdentity.create("leaf");

    const rootJwt = await issueDelegation(root, middle.did, {
      actions: ["pay"],
      maxAmount: 100,
      currency: "USD",
    });

    const childJwt = await delegateFurther(middle, rootJwt, leaf.did, {
      actions: ["pay"],
      maxAmount: 50,
      currency: "USD",
    });

    const result = await verifyDelegationChain([rootJwt, childJwt]);
    expect(result.valid).toBe(true);
    expect(result.scope?.maxAmount).toBe(50);
  });

  it("throws when currency mismatches between parent and child", async () => {
    const root = await AgentIdentity.create("root");
    const middle = await AgentIdentity.create("middle");
    const leaf = await AgentIdentity.create("leaf");

    const rootJwt = await issueDelegation(root, middle.did, { currency: "USD" });

    await expect(
      delegateFurther(middle, rootJwt, leaf.did, { currency: "EUR" }),
    ).rejects.toBeInstanceOf(ScopeEscalationError);
  });

  it("fails verification when holder is not subject of parent", async () => {
    const root = await AgentIdentity.create("root");
    const wrong = await AgentIdentity.create("wrong");
    const leaf = await AgentIdentity.create("leaf");

    const rootJwt = await issueDelegation(root, leaf.did, { actions: ["read"] });

    await expect(
      delegateFurther(wrong, rootJwt, leaf.did, { actions: ["read"] }),
    ).rejects.toThrow();
  });
});

// ── requiredAction check ──────────────────────────────────────────────────────

describe("verifyDelegationChain requiredAction", () => {
  it("passes when required action is in scope", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, { actions: ["read", "pay"] });
    const result = await verifyDelegationChain([jwt], { requiredAction: "pay" });
    expect(result.valid).toBe(true);
  });

  it("fails when required action is not in scope", async () => {
    const root = await AgentIdentity.create("root");
    const delegate = await AgentIdentity.create("delegate");
    const jwt = await issueDelegation(root, delegate.did, { actions: ["read"] });
    const result = await verifyDelegationChain([jwt], { requiredAction: "pay" });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("pay");
  });
});
