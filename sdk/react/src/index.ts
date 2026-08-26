// ---------------------------------------------------------------------------
// @tesht/react — React SDK Wrapper
//
// Offline hooks (no server needed):
//   useIdentity   — create/restore AgentIdentity, resolve did:key
//   useCredential — issue/verify VCs and Verifiable Presentations
//   useDelegation — issue/verify delegation chains, scope narrowing
//
// Server-connected hooks (require <TeshtProvider apiUrl="...">):
//   useTrustScore — POST /v1/trust/score
//   useAuditLog   — GET  /v1/audit
//   useMandate    — POST /v1/commerce/mandates/{intent,cart,verify}
//   useSession    — Session runtime: create / decide / step_up / revoke
//
// Provider:
//   TeshtProvider  — context root; accepts apiUrl + authToken props
//   useTesht       — access raw context
// ---------------------------------------------------------------------------

// Context / Provider
export {
  TeshtProvider,
  useTesht,
  useRequireApiUrl,
  type TeshtContextValue,
  type TeshtProviderProps,
} from "./context.js";

// Offline hooks
export { useIdentity, type UseIdentityReturn } from "./useIdentity.js";
export { useCredential, type UseCredentialReturn } from "./useCredential.js";
export {
  useDelegation,
  ScopeEscalationError,
  type UseDelegationReturn,
  type Scope,
  type DelegationResult,
} from "./useDelegation.js";

// Server-connected hooks
export {
  useTrustScore,
  type UseTrustScoreReturn,
  type TrustScoreResult,
} from "./useTrustScore.js";
export {
  useAuditLog,
  type UseAuditLogReturn,
  type AuditEvent,
  type AuditLogOptions,
} from "./useAuditLog.js";
export {
  useMandate,
  type UseMandateReturn,
  type IntentPayload,
  type CartPayload,
  type CartItem,
  type MandateResponse,
  type MandateVerifyRequest,
  type MandateVerifyResponse,
} from "./useMandate.js";
export {
  useSession,
  type SessionRecord,
  type DecisionRecord,
} from "./useSession.js";

// Re-export core SDK types that consumers will need
export type {
  AgentIdentity,
  AgentIdentityDict,
  VerificationResult,
  PresentationResult,
  IssueVCOptions,
  VerifyVCOptions,
  CreatePresentationOptions,
  VerifyPresentationOptions,
  IssueDelegationOptions,
  DelegateFurtherOptions,
  VerifyDelegationChainOptions,
} from "@tesht/sdk";
