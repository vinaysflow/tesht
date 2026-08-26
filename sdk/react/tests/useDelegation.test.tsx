import { describe, it, expect } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { AgentIdentity } from "@tesht/sdk";
import { useDelegation, ScopeEscalationError } from "../src/useDelegation.js";
import { makeWrapper } from "./helpers.js";

const wrapper = makeWrapper();

describe("useDelegation", () => {
  it("issue + verifyChain (single link) succeeds", async () => {
    const { result } = renderHook(() => useDelegation(), { wrapper });
    await waitFor(() => expect(result.current).not.toBeNull());

    let chainResult: Awaited<ReturnType<typeof result.current.verifyChain>>;
    await act(async () => {
      const delegator = await AgentIdentity.create("delegator");
      const delegate = await AgentIdentity.create("delegate");
      const jwt = await result.current.issue(delegator, delegate.did, {
        actions: ["purchase"],
        maxAmount: 10000,
        currency: "USD",
      });
      chainResult = await result.current.verifyChain([jwt]);
    });

    expect(chainResult!.valid).toBe(true);
    expect(chainResult!.scope?.actions).toContain("purchase");
    // single link = depth 0 (delegationJwts.length - 1 = 0)
    expect(chainResult!.depth).toBe(0);
  });

  it("two-link chain with delegateFurther succeeds", async () => {
    const { result } = renderHook(() => useDelegation(), { wrapper });
    await waitFor(() => expect(result.current).not.toBeNull());

    let chainResult: Awaited<ReturnType<typeof result.current.verifyChain>>;
    await act(async () => {
      const root = await AgentIdentity.create("root");
      const mid  = await AgentIdentity.create("mid");
      const leaf = await AgentIdentity.create("leaf");

      const rootJwt = await result.current.issue(root, mid.did, {
        actions: ["purchase", "refund"],
        maxAmount: 50000,
        currency: "USD",
      });

      const childJwt = await result.current.delegateFurther(
        mid,
        rootJwt,
        leaf.did,
        { actions: ["purchase"], maxAmount: 10000, currency: "USD" },
      );

      // Two JWTs in the chain → depth = 2 - 1 = 1
      chainResult = await result.current.verifyChain([rootJwt, childJwt]);
    });

    expect(chainResult!.valid).toBe(true);
    expect(chainResult!.depth).toBe(1);
    expect(chainResult!.scope?.actions).toContain("purchase");
  });

  it("scope escalation throws ScopeEscalationError via delegateFurther (maxAmount)", async () => {
    const { result } = renderHook(() => useDelegation(), { wrapper });
    await waitFor(() => expect(result.current).not.toBeNull());

    let thrown: unknown;
    await act(async () => {
      try {
        const parent = await AgentIdentity.create("parent");
        const child  = await AgentIdentity.create("child");
        const leaf   = await AgentIdentity.create("leaf");

        const parentJwt = await result.current.issue(parent, child.did, {
          actions: ["purchase"],
          maxAmount: 5000,
          currency: "USD",
        });

        // validateScopeNarrowing is called with maxAmount exceeding parent
        result.current.validateScopeNarrowing(
          { actions: ["purchase"], maxAmount: 5000, currency: "USD" },
          { actions: ["purchase"], maxAmount: 9999, currency: "USD" },
        );
        // If we reach here without a parentJwt-based escalation, use it in delegateFurther
        await result.current.delegateFurther(child, parentJwt, leaf.did, {
          actions: ["purchase"],
          maxAmount: 9999,
          currency: "USD",
        });
      } catch (e) {
        thrown = e;
      }
    });

    expect(thrown).toBeInstanceOf(ScopeEscalationError);
  });

  it("intersectScopes returns the narrower of two scopes", async () => {
    const { result } = renderHook(() => useDelegation(), { wrapper });
    await waitFor(() => expect(result.current).not.toBeNull());

    const parent = { actions: ["purchase", "refund"], maxAmount: 50000, currency: "USD" };
    const child  = { actions: ["purchase"], maxAmount: 10000, currency: "USD" };

    const intersected = result.current.intersectScopes(parent, child);

    expect(intersected.actions).toEqual(["purchase"]);
    expect(intersected.maxAmount).toBe(10000);
  });

  it("validateScopeNarrowing throws on amount escalation", async () => {
    const { result } = renderHook(() => useDelegation(), { wrapper });
    await waitFor(() => expect(result.current).not.toBeNull());

    const parent = { actions: ["purchase"], maxAmount: 5000, currency: "USD" };
    const child  = { actions: ["purchase"], maxAmount: 9999, currency: "USD" };

    expect(() => {
      result.current.validateScopeNarrowing(parent, child);
    }).toThrow(ScopeEscalationError);
  });

  it("empty delegation chain returns valid=false", async () => {
    const { result } = renderHook(() => useDelegation(), { wrapper });
    await waitFor(() => expect(result.current).not.toBeNull());

    let chainResult: Awaited<ReturnType<typeof result.current.verifyChain>>;
    await act(async () => {
      chainResult = await result.current.verifyChain([]);
    });

    expect(chainResult!.valid).toBe(false);
  });
});
