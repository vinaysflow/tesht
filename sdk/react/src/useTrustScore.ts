import { useCallback, useState } from "react";
import { useTesht, useRequireApiUrl } from "./context.js";
import { apiPost } from "./api.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TrustScoreResult {
  total: number;
  factors: Record<string, number>;
  risk_level: string;
  explanation: string;
  computed_at: string;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseTrustScoreReturn {
  /**
   * Compute a composite trust score (0–100) for a VC-JWT.
   * Calls POST /v1/trust/score on the backend.
   * Requires apiUrl set on <TeshtProvider>.
   */
  score: (jwt: string) => Promise<TrustScoreResult>;
  loading: boolean;
  error: string | null;
}

export function useTrustScore(): UseTrustScoreReturn {
  const apiUrl = useRequireApiUrl();
  const { authToken } = useTesht();

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const score = useCallback(
    async (jwt: string): Promise<TrustScoreResult> => {
      setLoading(true);
      setError(null);
      try {
        const result = await apiPost<TrustScoreResult>(
          apiUrl,
          "/v1/trust/score",
          { jwt },
          authToken,
        );
        return result;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [apiUrl, authToken],
  );

  return { score, loading, error };
}
