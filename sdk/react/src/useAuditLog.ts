import { useCallback, useEffect, useState } from "react";
import { useTesht, useRequireApiUrl } from "./context.js";
import { apiGet } from "./api.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditEvent {
  id: string;
  event_type: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  payload: Record<string, unknown>;
  created_at: string;
}

interface AuditListResp {
  events: AuditEvent[];
}

export interface AuditLogOptions {
  /** Max events to return (default 50, max 500). */
  limit?: number;
  /** Filter by actor DID or name. */
  actor?: string;
  /** Filter by event_type. */
  eventType?: string;
  /** Filter by resource_type. */
  resourceType?: string;
  /** Filter by resource_id. */
  resourceId?: string;
  /** Include public (cross-tenant) events. */
  includePublic?: boolean;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseAuditLogReturn {
  events: AuditEvent[];
  loading: boolean;
  error: string | null;
  /** Re-fetch the audit log. */
  refresh: () => void;
}

/**
 * Fetches the audit event log from POST /v1/audit.
 * Automatically fetches on mount; call refresh() to re-fetch.
 * Requires apiUrl set on <TeshtProvider>.
 */
export function useAuditLog(opts: AuditLogOptions = {}): UseAuditLogReturn {
  const apiUrl = useRequireApiUrl();
  const { authToken } = useTesht();

  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const {
    limit = 50,
    actor,
    eventType,
    resourceType,
    resourceId,
    includePublic,
  } = opts;

  useEffect(() => {
    let cancelled = false;

    async function fetch() {
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams({ limit: String(limit) });
        if (actor) params.set("actor", actor);
        if (eventType) params.set("event_type", eventType);
        if (resourceType) params.set("resource_type", resourceType);
        if (resourceId) params.set("resource_id", resourceId);
        if (includePublic) params.set("include_public", "true");

        const data = await apiGet<AuditListResp>(
          apiUrl,
          `/v1/audit?${params.toString()}`,
          authToken,
        );
        if (!cancelled) setEvents(data.events);
      } catch (e: unknown) {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : String(e);
          setError(msg);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void fetch();
    return () => {
      cancelled = true;
    };
  }, [apiUrl, authToken, tick, limit, actor, eventType, resourceType, resourceId, includePublic]);

  const refresh = useCallback(() => setTick((n) => n + 1), []);

  return { events, loading, error, refresh };
}
