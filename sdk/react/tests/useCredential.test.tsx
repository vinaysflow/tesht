import { describe, it, expect } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { AgentIdentity } from "@tesht/sdk";
import { useCredential } from "../src/useCredential.js";
import { makeWrapper } from "./helpers.js";

const wrapper = makeWrapper();

describe("useCredential", () => {
  it("issue + verify round-trip succeeds", async () => {
    const { result } = renderHook(() => useCredential(), { wrapper });

    let verifyResult: Awaited<ReturnType<typeof result.current.verify>>;
    await act(async () => {
      const issuer = await AgentIdentity.create("issuer");
      const subject = await AgentIdentity.create("subject");
      const jwt = await result.current.issue(issuer, subject.did, {
        credentialType: "TestCredential",
        claims: { role: "tester" },
      });
      verifyResult = await result.current.verify(jwt);
    });

    expect(verifyResult!.valid).toBe(true);
    expect(verifyResult!.credentialType).toBe("TestCredential");
    expect((verifyResult!.claims as Record<string, unknown>)?.role).toBe("tester");
  });

  it("tampered JWT returns valid=false", async () => {
    const { result } = renderHook(() => useCredential(), { wrapper });

    let verifyResult: Awaited<ReturnType<typeof result.current.verify>>;
    await act(async () => {
      const issuer = await AgentIdentity.create("issuer");
      const subject = await AgentIdentity.create("subject");
      const jwt = await result.current.issue(issuer, subject.did, {
        credentialType: "AgentCredential",
      });
      // Tamper: flip a character in the signature portion
      const parts = jwt.split(".");
      const tampered = parts.slice(0, 2).join(".") + "." + parts[2].slice(1) + "X";
      verifyResult = await result.current.verify(tampered);
    });

    expect(verifyResult!.valid).toBe(false);
  });

  it("expired VC returns valid=false with reason", async () => {
    const { result } = renderHook(() => useCredential(), { wrapper });

    let verifyResult: Awaited<ReturnType<typeof result.current.verify>>;
    await act(async () => {
      const issuer = await AgentIdentity.create("issuer");
      const subject = await AgentIdentity.create("subject");
      // Issue with ttl of -1 second in the past
      const jwt = await result.current.issue(issuer, subject.did, {
        ttlSeconds: -1,
      });
      verifyResult = await result.current.verify(jwt);
    });

    expect(verifyResult!.valid).toBe(false);
  });

  it("createPresentation + verifyPresentation round-trip", async () => {
    const { result } = renderHook(() => useCredential(), { wrapper });

    let presResult: Awaited<ReturnType<typeof result.current.verifyPresentation>>;
    await act(async () => {
      const issuer = await AgentIdentity.create("issuer");
      const holder = await AgentIdentity.create("holder");
      const audience = "did:key:z6MkAudienceExample";
      const vc = await result.current.issue(issuer, holder.did, {
        credentialType: "AgentCredential",
      });
      const vp = await result.current.createPresentation(
        holder,
        [vc],
        { audience },
      );
      presResult = await result.current.verifyPresentation(vp, {
        expectedAudience: audience,
      });
    });

    expect(presResult!.valid).toBe(true);
    expect(presResult!.holder).toBeDefined();
  });
});
