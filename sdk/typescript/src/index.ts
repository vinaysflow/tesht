export { TeshtClient } from "./client.js";
export { b58Encode, b58Decode } from "./base58.js";
export { AgentIdentity, resolveDIDKey } from "./identity.js";
export type { AgentIdentityDict } from "./identity.js";
export {
  issueVC,
  verifyVC,
  createPresentation,
  verifyPresentation,
} from "./credentials.js";
export type {
  VerificationResult,
  PresentationResult,
  IssueVCOptions,
  VerifyVCOptions,
  CreatePresentationOptions,
  VerifyPresentationOptions,
} from "./credentials.js";
export {
  issueDelegation,
  delegateFurther,
  verifyDelegationChain,
  intersectScopes,
  validateScopeNarrowing,
  ScopeEscalationError,
} from "./delegation.js";
export type {
  Scope,
  DelegationResult,
  IssueDelegationOptions,
  DelegateFurtherOptions,
  VerifyDelegationChainOptions,
} from "./delegation.js";
