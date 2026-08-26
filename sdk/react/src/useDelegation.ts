import { useCallback } from "react";
import {
  issueDelegation,
  delegateFurther,
  verifyDelegationChain,
  intersectScopes,
  validateScopeNarrowing,
  ScopeEscalationError,
  type AgentIdentity,
  type Scope,
  type DelegationResult,
  type IssueDelegationOptions,
  type DelegateFurtherOptions,
  type VerifyDelegationChainOptions,
} from "@tesht/sdk";

export type { Scope, DelegationResult };
export { ScopeEscalationError };

export interface UseDelegationReturn {
  /** Issue a root delegation credential JWT from a delegator to a delegate. */
  issue: (
    issuer: AgentIdentity,
    delegateDid: string,
    scope: Scope,
    opts?: IssueDelegationOptions,
  ) => Promise<string>;

  /**
   * Extend an existing delegation to a new sub-delegate with a narrowed scope.
   * Throws ScopeEscalationError if the requested scope exceeds the parent.
   */
  delegateFurther: (
    holder: AgentIdentity,
    parentJwt: string,
    delegateDid: string,
    scope: Scope,
    opts?: DelegateFurtherOptions,
  ) => Promise<string>;

  /**
   * Verify a delegation chain (array of JWTs from root to tip).
   * Optionally assert that a specific action is in the effective scope.
   */
  verifyChain: (
    jwts: string[],
    opts?: VerifyDelegationChainOptions,
  ) => Promise<DelegationResult>;

  /** Compute the intersection of two scopes (child must be narrower than parent). */
  intersectScopes: typeof intersectScopes;

  /** Validate that child scope does not escalate parent scope; throws ScopeEscalationError. */
  validateScopeNarrowing: typeof validateScopeNarrowing;
}

/**
 * Provides offline delegation chain operations backed by the @tesht/sdk
 * TypeScript SDK. No server connection required.
 */
export function useDelegation(): UseDelegationReturn {
  const issue = useCallback(
    (
      issuer: AgentIdentity,
      delegateDid: string,
      scope: Scope,
      opts?: IssueDelegationOptions,
    ) => issueDelegation(issuer, delegateDid, scope, opts),
    [],
  );

  const delegateFurtherFn = useCallback(
    (
      holder: AgentIdentity,
      parentJwt: string,
      delegateDid: string,
      scope: Scope,
      opts?: DelegateFurtherOptions,
    ) => delegateFurther(holder, parentJwt, delegateDid, scope, opts),
    [],
  );

  const verifyChain = useCallback(
    (jwts: string[], opts?: VerifyDelegationChainOptions) =>
      verifyDelegationChain(jwts, opts),
    [],
  );

  return {
    issue,
    delegateFurther: delegateFurtherFn,
    verifyChain,
    intersectScopes,
    validateScopeNarrowing,
  };
}
