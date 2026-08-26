import { useCallback } from "react";
import {
  AgentIdentity,
  resolveDIDKey,
  type AgentIdentityDict,
} from "@tesht/sdk";

export interface UseIdentityReturn {
  /** Create a new agent identity with a fresh Ed25519 keypair. */
  createAgent: (name: string, domain?: string) => Promise<AgentIdentity>;
  /** Restore an agent identity from a serialised dict (private key included). */
  fromDict: (d: AgentIdentityDict) => Promise<AgentIdentity>;
  /** Resolve a did:key DID to its DID document (fully offline). */
  resolveDIDKey: (did: string) => Promise<Record<string, unknown>>;
}

/**
 * Provides offline identity operations backed by the @tesht/sdk TypeScript SDK.
 * No server connection required — all crypto runs in the browser.
 */
export function useIdentity(): UseIdentityReturn {
  const createAgent = useCallback(
    (name: string, domain?: string) => AgentIdentity.create(name, domain),
    [],
  );

  const fromDict = useCallback(
    (d: AgentIdentityDict) => AgentIdentity.fromDict(d),
    [],
  );

  const resolveKey = useCallback(
    (did: string) => resolveDIDKey(did),
    [],
  );

  return { createAgent, fromDict, resolveDIDKey: resolveKey };
}
