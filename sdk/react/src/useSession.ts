/**
 * React hook for the Session authorization runtime.
 * Handoff → decide → step_up → revoke.
 */
import { useCallback, useState } from "react";
import { apiGet, apiPost } from "./api.js";
import { useTesht } from "./context.js";

export type SessionRecord = {
  id: string;
  status: string;
  agent_did: string;
  human_did?: string | null;
  scope: Record<string, unknown>;
  packs: string[];
  trust_score?: number | null;
  last_decision: Record<string, unknown>;
  proof_bundle: Record<string, unknown>;
};

export type DecisionRecord = {
  session_id: string;
  decision: "allow" | "step_up" | "block" | string;
  error_code?: string | null;
  reason: string;
  trust_score?: number | null;
  session_status: string;
};

export function useSession() {
  const { apiUrl, authToken } = useTesht();
  const [session, setSession] = useState<SessionRecord | null>(null);
  const [lastDecision, setLastDecision] = useState<DecisionRecord | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const createSession = useCallback(
    async (body: {
      agent_did: string;
      human_did?: string;
      scope?: Record<string, unknown>;
      packs?: string[];
      ttl_seconds?: number;
      agent_vc_jwt?: string;
      delegation_jwt?: string;
      human_proof_jwt?: string;
    }) => {
      setLoading(true);
      setError(null);
      try {
        const s = await apiPost<SessionRecord>(
          apiUrl,
          "/v1/sessions",
          { packs: ["core"], ttl_seconds: 3600, scope: {}, ...body },
          authToken,
        );
        setSession(s);
        return s;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [apiUrl, authToken],
  );

  const decide = useCallback(
    async (
      sessionId: string,
      body: {
        action: string;
        amount?: number;
        currency?: string;
        tool_name?: string;
        resource?: string;
      },
    ) => {
      setLoading(true);
      setError(null);
      try {
        const d = await apiPost<DecisionRecord>(
          apiUrl,
          `/v1/sessions/${sessionId}/actions`,
          body,
          authToken,
        );
        setLastDecision(d);
        return d;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [apiUrl, authToken],
  );

  const stepUp = useCallback(
    async (sessionId: string, body: Record<string, unknown> = {}) => {
      setLoading(true);
      setError(null);
      try {
        const s = await apiPost<SessionRecord>(
          apiUrl,
          `/v1/sessions/${sessionId}/step_up`,
          body,
          authToken,
        );
        setSession(s);
        return s;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [apiUrl, authToken],
  );

  const revoke = useCallback(
    async (sessionId: string, cascade = true, reason?: string) => {
      setLoading(true);
      setError(null);
      try {
        const s = await apiPost<SessionRecord>(
          apiUrl,
          `/v1/sessions/${sessionId}/revoke`,
          { cascade, reason },
          authToken,
        );
        setSession(s);
        return s;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [apiUrl, authToken],
  );

  const refresh = useCallback(
    async (sessionId: string) => {
      const s = await apiGet<SessionRecord>(
        apiUrl,
        `/v1/sessions/${sessionId}`,
        authToken,
      );
      setSession(s);
      return s;
    },
    [apiUrl, authToken],
  );

  return {
    session,
    lastDecision,
    loading,
    error,
    createSession,
    decide,
    stepUp,
    revoke,
    refresh,
  };
}
