import { useCallback } from "react";
import {
  issueVC,
  verifyVC,
  createPresentation,
  verifyPresentation,
  type AgentIdentity,
  type IssueVCOptions,
  type VerifyVCOptions,
  type VerificationResult,
  type CreatePresentationOptions,
  type VerifyPresentationOptions,
  type PresentationResult,
} from "@tesht/sdk";

export interface UseCredentialReturn {
  /** Issue a Verifiable Credential JWT. Fully offline (did:key). */
  issue: (
    issuer: AgentIdentity,
    subjectDid: string,
    opts?: IssueVCOptions,
  ) => Promise<string>;

  /** Verify a VC JWT. Fully offline for did:key issuers. */
  verify: (jwt: string, opts?: VerifyVCOptions) => Promise<VerificationResult>;

  /** Create a Verifiable Presentation JWT wrapping one or more VCs. */
  createPresentation: (
    holder: AgentIdentity,
    vcJwts: string[],
    opts?: CreatePresentationOptions,
  ) => Promise<string>;

  /** Verify a VP JWT and (optionally) the embedded VCs. */
  verifyPresentation: (
    vpJwt: string,
    opts?: VerifyPresentationOptions,
  ) => Promise<PresentationResult>;
}

/**
 * Provides offline VC issuance and verification backed by the @tesht/sdk
 * TypeScript SDK. No server connection required.
 */
export function useCredential(): UseCredentialReturn {
  const issue = useCallback(
    (issuer: AgentIdentity, subjectDid: string, opts?: IssueVCOptions) =>
      issueVC(issuer, subjectDid, opts),
    [],
  );

  const verify = useCallback(
    (jwt: string, opts?: VerifyVCOptions) => verifyVC(jwt, opts),
    [],
  );

  const createPres = useCallback(
    (
      holder: AgentIdentity,
      vcJwts: string[],
      opts?: CreatePresentationOptions,
    ) => createPresentation(holder, vcJwts, opts),
    [],
  );

  const verifyPres = useCallback(
    (vpJwt: string, opts?: VerifyPresentationOptions) =>
      verifyPresentation(vpJwt, opts),
    [],
  );

  return {
    issue,
    verify,
    createPresentation: createPres,
    verifyPresentation: verifyPres,
  };
}
