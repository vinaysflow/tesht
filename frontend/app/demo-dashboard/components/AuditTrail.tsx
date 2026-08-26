"use client";

import { useState, useCallback } from "react";
import { apiGet, apiBase, getAccessToken } from "../../../lib/api";

interface AuditEvent {
  id: string;
  event_type: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  created_at: string;
  event_hash: string | null;
  prev_hash: string | null;
}

interface ChainResult {
  valid: boolean;
  events_checked: number;
  first_broken_at: string | null;
  reason: string | null;
}

interface AuditTrailProps {
  initialEvents?: AuditEvent[];
  initialChain?: ChainResult | null;
  compact?: boolean;
}

const EVENT_DESCRIPTIONS: Record<string, string> = {
  "credential.issued": "A new credential was issued to an agent",
  "credential.revoked": "An agent's credential was revoked",
  "credential.verified": "A credential was verified",
  "agent.created": "A new agent identity was registered",
  "delegation.registered": "Authority was delegated to an agent",
  "delegation.revoked": "A delegation was revoked",
  "workflow.drift_demo.issued": "Drift demo: credential issued",
  "workflow.drift_demo.revoked": "Drift demo: credential revoked",
  "mandate.intent.issued": "A spending budget was authorized",
  "mandate.cart.issued": "A purchase cart was created",
  "mandate.cart.verified": "A purchase was verified by merchant",
};

function describeEvent(type: string): string {
  return EVENT_DESCRIPTIONS[type] ?? type.replace(/[._]/g, " ");
}

export function AuditTrail({
  initialEvents = [],
  initialChain = null,
}: AuditTrailProps) {
  const [events, setEvents] = useState<AuditEvent[]>(initialEvents);
  const [chain, setChain] = useState<ChainResult | null>(initialChain);
  const [verifying, setVerifying] = useState(false);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiGet<{ events: AuditEvent[] }>("/v1/audit?limit=30");
      setEvents(data.events ?? []);
    } catch { /* requires admin scope */ }
    setLoading(false);
  }, []);

  const verifyChain = useCallback(async () => {
    setVerifying(true);
    try {
      const result = await apiGet<ChainResult>("/v1/audit/verify");
      setChain(result);
    } catch { /* ignore */ }
    setVerifying(false);
  }, []);

  async function exportJsonl() {
    const base = apiBase();
    const token = getAccessToken();
    const headers: Record<string, string> = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    try {
      const res = await fetch(`${base}/v1/audit/export`, { headers });
      if (!res.ok) return;
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "tesht-audit.jsonl";
      a.click();
      URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  }

  return (
    <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
      {/* Header */}
      <div className="px-6 py-5 border-b border-gray-100">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h4 className="font-bold text-gray-900">Audit Trail</h4>
            <p className="text-sm text-gray-500 mt-1 leading-relaxed max-w-lg">
              Every operation is recorded in a tamper-evident log. Each entry is cryptographically linked to the one before it —
              if anyone modifies a past record, the chain breaks and the tampering is detected.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {chain && (
              <div
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold ${
                  chain.valid
                    ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                    : "bg-red-50 text-red-700 border border-red-200"
                }`}
              >
                <span>{chain.valid ? "\u2713" : "\u2717"}</span>
                <span>
                  {chain.valid
                    ? `Chain Verified (${chain.events_checked} events)`
                    : "Chain Broken"}
                </span>
              </div>
            )}
            <button
              onClick={verifyChain}
              disabled={verifying}
              className="text-xs px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white font-semibold transition-colors"
            >
              {verifying ? "Verifying..." : "Verify Integrity"}
            </button>
            <button
              onClick={refresh}
              disabled={loading}
              className="text-xs px-3.5 py-2 rounded-xl border border-gray-200 hover:bg-gray-50 text-gray-600 font-medium"
            >
              {loading ? "..." : "Refresh"}
            </button>
            <button
              onClick={exportJsonl}
              className="text-xs px-3.5 py-2 rounded-xl border border-gray-200 hover:bg-gray-50 text-gray-600 font-medium"
            >
              Export
            </button>
          </div>
        </div>
      </div>

      {/* Chain broken alert */}
      {chain && !chain.valid && (
        <div className="mx-5 mt-4 px-4 py-3.5 bg-red-50 border border-red-200 rounded-xl text-sm text-red-700">
          <p className="font-semibold">Tampering Detected</p>
          <p className="mt-1 text-xs">
            The audit chain is broken at event <code className="font-mono">{chain.first_broken_at}</code>.
            This means a record was modified, deleted, or reordered after it was created.
          </p>
          {chain.reason && <p className="mt-1 text-xs font-mono opacity-75">{chain.reason}</p>}
        </div>
      )}

      {/* Events */}
      {events.length > 0 ? (
        <div className="divide-y divide-gray-100">
          {events.map((evt, i) => {
            const isGenesis = !evt.prev_hash || evt.prev_hash === "0".repeat(64);
            return (
              <div key={evt.id} className="px-6 py-3.5 flex items-start gap-4 hover:bg-gray-50/50 transition-colors">
                <div className="flex-shrink-0 pt-0.5">
                  <span className="w-6 h-6 rounded-full bg-gray-100 text-gray-500 text-xs font-mono flex items-center justify-center">
                    {events.length - i}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-sm font-semibold text-violet-700">{evt.event_type}</code>
                    <span className="text-xs text-gray-400">
                      {new Date(evt.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">{describeEvent(evt.event_type)}</p>
                </div>
                <div className="flex-shrink-0 text-right">
                  <div className="flex items-center gap-1.5 text-xs">
                    <span className="text-gray-400">Hash:</span>
                    <code className="text-emerald-600 font-mono">
                      {evt.event_hash ? evt.event_hash.slice(0, 10) + "..." : "\u2014"}
                    </code>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs mt-0.5">
                    <span className="text-gray-400">Prev:</span>
                    {isGenesis ? (
                      <span className="text-amber-600 font-mono text-xs">genesis</span>
                    ) : (
                      <code className="text-blue-600 font-mono">
                        {evt.prev_hash ? evt.prev_hash.slice(0, 10) + "..." : "\u2014"}
                      </code>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="px-6 py-8 text-center text-sm text-gray-400">
          <p>No audit events loaded yet.</p>
          <p className="text-xs mt-1">
            Run a scenario to generate events, then click Refresh.
          </p>
        </div>
      )}

      {/* Hash chain visualization */}
      {events.length >= 2 && (
        <div className="px-6 py-4 bg-gray-50 border-t border-gray-100">
          <p className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-3">Hash Chain (latest events)</p>
          <div className="flex items-center gap-1.5 overflow-x-auto py-1">
            {events.slice(0, 6).reverse().map((evt, i) => (
              <div key={evt.id} className="flex items-center gap-1.5 flex-shrink-0">
                <div className="bg-white border border-gray-200 rounded-xl px-3 py-2 text-center min-w-24 shadow-sm">
                  <p className="text-xs text-violet-600 font-medium truncate max-w-24">
                    {evt.event_type.split(".").pop()}
                  </p>
                  <p className="text-xs font-mono text-emerald-600 mt-0.5">
                    {evt.event_hash ? evt.event_hash.slice(0, 8) : "\u2014"}
                  </p>
                </div>
                {i < 5 && events.length > i + 1 && (
                  <span className="text-gray-300 text-sm font-bold">{"\u2192"}</span>
                )}
              </div>
            ))}
            {events.length > 6 && (
              <span className="text-gray-400 text-xs ml-1">
                + {events.length - 6} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
