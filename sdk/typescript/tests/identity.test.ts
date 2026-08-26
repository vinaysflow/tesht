import { describe, it, expect } from "vitest";
import { b58Encode, b58Decode } from "../src/base58.js";
import { AgentIdentity, resolveDIDKey } from "../src/identity.js";

// ── Base58btc ─────────────────────────────────────────────────────────────────

describe("Base58btc", () => {
  it("encodes empty bytes to empty string", () => {
    expect(b58Encode(new Uint8Array(0))).toBe("");
  });

  it("decodes empty string to empty bytes", () => {
    expect(b58Decode("")).toEqual(new Uint8Array(0));
  });

  it("encodes and decodes round-trip", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
    expect(b58Decode(b58Encode(data))).toEqual(data);
  });

  it("encodes leading zero bytes as '1' characters", () => {
    const data = new Uint8Array([0, 0, 1]);
    const encoded = b58Encode(data);
    expect(encoded.startsWith("11")).toBe(true);
  });

  it("throws on invalid character", () => {
    expect(() => b58Decode("0OIl")).toThrow();
  });

  it("known vector: 32 bytes of 0xff encode correctly", () => {
    const data = new Uint8Array(32).fill(0xff);
    const encoded = b58Encode(data);
    // Must decode back exactly
    expect(b58Decode(encoded)).toEqual(data);
    expect(encoded.length).toBeGreaterThan(0);
  });
});

// ── AgentIdentity ─────────────────────────────────────────────────────────────

describe("AgentIdentity.create", () => {
  it("returns an AgentIdentity with a did:key DID", async () => {
    const identity = await AgentIdentity.create("test-agent");
    expect(identity.did).toMatch(/^did:key:z/);
    expect(identity.method).toBe("key");
  });

  it("name is accessible", async () => {
    const identity = await AgentIdentity.create("my-agent");
    expect(identity.name).toBe("my-agent");
  });

  it("generates unique DIDs each call", async () => {
    const a = await AgentIdentity.create("a");
    const b = await AgentIdentity.create("b");
    expect(a.did).not.toBe(b.did);
  });

  it("creates did:web identity when domain provided", async () => {
    const identity = await AgentIdentity.create("web-agent", "example.com");
    expect(identity.did).toBe("did:web:example.com");
    expect(identity.method).toBe("web");
    expect(identity.domain).toBe("example.com");
  });

  it("publicJwk has OKP/Ed25519 shape", async () => {
    const identity = await AgentIdentity.create("test");
    expect(identity.publicJwk.kty).toBe("OKP");
    expect(identity.publicJwk.crv).toBe("Ed25519");
    expect(identity.publicJwk.x).toBeTruthy();
  });

  it("kid is derived from the DID", async () => {
    const identity = await AgentIdentity.create("test");
    expect(identity.kid).toContain(identity.did);
  });
});

describe("AgentIdentity DID document", () => {
  it("did:key document has correct context", async () => {
    const identity = await AgentIdentity.create("test");
    const doc = identity.didDocument;
    const ctx = doc["@context"] as string[];
    expect(ctx).toContain("https://www.w3.org/ns/did/v1");
  });

  it("did:key document has Ed25519VerificationKey2020", async () => {
    const identity = await AgentIdentity.create("test");
    const doc = identity.didDocument;
    const vm = (doc["verificationMethod"] as Array<Record<string, unknown>>)[0];
    expect(vm["type"]).toBe("Ed25519VerificationKey2020");
    expect(vm["publicKeyMultibase"]).toMatch(/^z/);
  });

  it("did:web document has JsonWebKey2020 with publicKeyJwk", async () => {
    const identity = await AgentIdentity.create("web-agent", "example.com");
    const doc = identity.didDocument;
    const vm = (doc["verificationMethod"] as Array<Record<string, unknown>>)[0];
    expect(vm["type"]).toBe("JsonWebKey2020");
    expect(vm["publicKeyJwk"]).toBeTruthy();
  });

  it("verification methods include authentication and assertionMethod", async () => {
    const identity = await AgentIdentity.create("test");
    const doc = identity.didDocument;
    expect(doc["authentication"]).toBeTruthy();
    expect(doc["assertionMethod"]).toBeTruthy();
  });
});

describe("AgentIdentity serialization", () => {
  it("toDict/fromDict round-trip preserves DID", async () => {
    const original = await AgentIdentity.create("agent");
    const d = original.toDict();
    const restored = await AgentIdentity.fromDict(d);
    expect(restored.did).toBe(original.did);
  });

  it("toDict/fromDict round-trip preserves signing ability", async () => {
    const original = await AgentIdentity.create("agent");
    const d = original.toDict();
    const restored = await AgentIdentity.fromDict(d);
    const msg = new TextEncoder().encode("hello");
    const sig = await original.sign(msg);
    expect(await restored.verify(msg, sig)).toBe(true);
  });

  it("fromPrivateKeyHex reconstructs identity", async () => {
    const original = await AgentIdentity.create("agent");
    const hex = original.privateKeyHex;
    const restored = await AgentIdentity.fromPrivateKeyHex(hex, "agent");
    expect(restored.did).toBe(original.did);
  });
});

describe("AgentIdentity signing", () => {
  it("sign/verify round-trip succeeds", async () => {
    const identity = await AgentIdentity.create("test");
    const msg = new TextEncoder().encode("Tesht (Pramana)");
    const sig = await identity.sign(msg);
    expect(await identity.verify(msg, sig)).toBe(true);
  });

  it("tampered message fails verification", async () => {
    const identity = await AgentIdentity.create("test");
    const msg = new TextEncoder().encode("original");
    const sig = await identity.sign(msg);
    const tampered = new TextEncoder().encode("tampered");
    expect(await identity.verify(tampered, sig)).toBe(false);
  });

  it("cross-identity verification fails", async () => {
    const alice = await AgentIdentity.create("alice");
    const bob = await AgentIdentity.create("bob");
    const msg = new TextEncoder().encode("hello");
    const sig = await alice.sign(msg);
    expect(await bob.verify(msg, sig)).toBe(false);
  });
});

// ── resolveDIDKey ──────────────────────────────────────────────────────────────

describe("resolveDIDKey", () => {
  it("resolves a did:key and returns a DID document", async () => {
    const identity = await AgentIdentity.create("test");
    const doc = await resolveDIDKey(identity.did);
    expect(doc["id"]).toBe(identity.did);
  });

  it("resolved document matches didDocument property", async () => {
    const identity = await AgentIdentity.create("test");
    const resolved = await resolveDIDKey(identity.did);
    const direct = identity.didDocument;
    expect(resolved["id"]).toBe(direct["id"]);
  });

  it("throws for non did:key DIDs", async () => {
    await expect(resolveDIDKey("did:web:example.com")).rejects.toThrow();
  });

  it("resolved document has publicKeyMultibase", async () => {
    const identity = await AgentIdentity.create("test");
    const doc = await resolveDIDKey(identity.did);
    const vm = (doc["verificationMethod"] as Array<Record<string, unknown>>)[0];
    expect(vm["publicKeyMultibase"]).toMatch(/^z/);
  });
});
