import { useCallback } from "react";
import { useTesht, useRequireApiUrl } from "./context.js";
import { apiPost } from "./api.js";

// ---------------------------------------------------------------------------
// Request/response types matching backend /v1/commerce/mandates/*
// ---------------------------------------------------------------------------

export interface IntentPayload {
  /** AP2 intent description. */
  description: string;
  /** Maximum transaction amount (integer, smallest currency unit e.g. cents). */
  max_amount: number;
  /** ISO 4217 currency code. */
  currency: string;
  /** Optional product category. */
  category?: string;
  /** Optional merchant restriction. */
  merchant?: string;
  /** Custom key-value constraints. */
  constraints?: Record<string, unknown>;
}

export interface CartItem {
  name: string;
  qty: number;
  unit_price: number;
}

export interface CartPayload {
  /** Reference to the intent mandate JWT that constrains this cart. */
  intent_mandate_jwt: string;
  /** Merchant name. */
  merchant?: string;
  items: CartItem[];
  total: {
    value: number;
    currency: string;
  };
}

export interface MandateResponse {
  mandate_id: string;
  mandate_type: string;
  jwt: string;
  issued_at: string;
  expires_at?: string;
}

export interface MandateVerifyRequest {
  jwt: string;
  mandate_type?: string;
}

export interface MandateVerifyResponse {
  verified: boolean;
  mandate_type: string;
  mandate_id: string;
  delegator_did: string;
  agent_did: string;
  scope: Record<string, unknown>;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseMandateReturn {
  /**
   * Create an AP2 intent mandate (shopping goal, budget ceiling).
   * Calls POST /v1/commerce/mandates/intent.
   */
  createIntent: (body: IntentPayload) => Promise<MandateResponse>;

  /**
   * Create an AP2 cart mandate (specific transaction, items + total).
   * Calls POST /v1/commerce/mandates/cart.
   * The backend enforces cart.total ≤ intent.max_amount.
   */
  createCart: (body: CartPayload) => Promise<MandateResponse>;

  /**
   * Verify a mandate JWT (intent or cart).
   * Calls POST /v1/commerce/mandates/verify.
   */
  verify: (body: MandateVerifyRequest) => Promise<MandateVerifyResponse>;
}

/**
 * Provides AP2 mandate operations via the Tesht backend.
 * Requires apiUrl set on <TeshtProvider>.
 */
export function useMandate(): UseMandateReturn {
  const apiUrl = useRequireApiUrl();
  const { authToken } = useTesht();

  const createIntent = useCallback(
    (body: IntentPayload) =>
      apiPost<MandateResponse>(
        apiUrl,
        "/v1/commerce/mandates/intent",
        body,
        authToken,
      ),
    [apiUrl, authToken],
  );

  const createCart = useCallback(
    (body: CartPayload) =>
      apiPost<MandateResponse>(
        apiUrl,
        "/v1/commerce/mandates/cart",
        body,
        authToken,
      ),
    [apiUrl, authToken],
  );

  const verify = useCallback(
    (body: MandateVerifyRequest) =>
      apiPost<MandateVerifyResponse>(
        apiUrl,
        "/v1/commerce/mandates/verify",
        body,
        authToken,
      ),
    [apiUrl, authToken],
  );

  return { createIntent, createCart, verify };
}
