"use client";

import { useState, useEffect } from "react";
import { apiGet } from "../../../lib/api";

interface RiskTierSummary {
  tier: string;
  count: number;
  description: string;
  color: string;
}

interface AgentRiskRow {
  name: string;
  did: string;
  spiffe_id: string | null;
  trust_score: number;
  risk_tier: string;
  event_count: number;
  recent_delta: number;
  failure_rate: number;
}

interface RiskDashboard {
  fleet_size: number;
  tiers: RiskTierSummary[];
  agents: AgentRiskRow[];
  mock_insurance_premium_usd: number;
  generated_at: string;
}

const TIER_STYLES: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  insurable:   { bg: "bg-emerald-50",  text: "text-emerald-700",  border: "border-emerald-200",  dot: "bg-emerald-500" },
  elevated:    { bg: "bg-amber-50",    text: "text-amber-700",    border: "border-amber-200",    dot: "bg-amber-500" },
  review:      { bg: "bg-orange-50",   text: "text-orange-700",   border: "border-orange-200",   dot: "bg-orange-500" },
  uninsurable: { bg: "bg-red-50",      text: "text-red-700",      border: "border-red-200",      dot: "bg-red-500" },
};

function ScoreBar({ score, tier }: { score: number; tier: string }) {
  const style = TIER_STYLES[tier] || TIER_STYLES.elevated;
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-100 rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-full rounded-full ${style.dot}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={`text-xs font-bold font-mono ${style.text}`}>{score}</span>
    </div>
  );
}

export function RiskDashboardTab() {
  const [data, setData] = useState<RiskDashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterTier, setFilterTier] = useState<string>("all");

  useEffect(() => {
    apiGet<RiskDashboard>("/v1/trust/risk-dashboard")
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  const filtered = data?.agents.filter((a) => filterTier === "all" || a.risk_tier === filterTier) ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-amber-500 to-orange-500 rounded-2xl p-6 text-white">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center text-2xl flex-shrink-0">🛡️</div>
          <div>
            <h2 className="text-lg font-bold">Insurance Risk Dashboard</h2>
            <p className="text-amber-100 text-sm mt-1">
              Fleet-level risk assessment for AI agent insurance pricing.
              Trust scores map agents to risk tiers affecting premium calculations.
            </p>
          </div>
        </div>
      </div>

      {loading && (
        <div className="py-12 text-center text-gray-400">
          <div className="w-6 h-6 border-2 border-amber-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm">Loading risk data...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          <p className="font-semibold">Failed to load risk dashboard</p>
          <p className="font-mono text-xs mt-1">{error}</p>
        </div>
      )}

      {data && !loading && data.fleet_size === 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-2xl p-6 text-center">
          <p className="text-2xl mb-2">🌱</p>
          <p className="text-sm font-semibold text-blue-800">No agents yet</p>
          <p className="text-xs text-blue-600 mt-1">
            Click <strong>"Load Demo Data"</strong> in the System State bar above to seed 30 agents with realistic trust histories.
          </p>
        </div>
      )}

      {data && !loading && data.fleet_size > 0 && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {data.tiers.map((tier) => {
              const style = TIER_STYLES[tier.tier] || TIER_STYLES.elevated;
              return (
                <button
                  key={tier.tier}
                  onClick={() => setFilterTier(filterTier === tier.tier ? "all" : tier.tier)}
                  className={`${style.bg} border-2 ${filterTier === tier.tier ? style.border : "border-transparent"} rounded-2xl p-4 text-left transition-all`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-3 h-3 rounded-full ${style.dot}`} />
                    <span className={`text-xs font-bold uppercase tracking-wide ${style.text}`}>{tier.tier}</span>
                  </div>
                  <p className={`text-3xl font-black ${style.text}`}>{tier.count}</p>
                  <p className="text-xs text-gray-600 mt-1 leading-snug">{tier.description}</p>
                </button>
              );
            })}
          </div>

          {/* Insurance premium */}
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Indicative Annual Premium</p>
                <p className="text-3xl font-black text-gray-900 mt-1">
                  ${data.mock_insurance_premium_usd.toLocaleString("en-US", { minimumFractionDigits: 0 })}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  Based on {data.fleet_size} agents × risk-adjusted pricing
                </p>
              </div>
              <div className="text-right">
                <p className="text-xs text-gray-500">Fleet size</p>
                <p className="text-2xl font-bold text-gray-800">{data.fleet_size}</p>
              </div>
            </div>
            <div className="mt-4 bg-blue-50 border border-blue-100 rounded-xl p-3 text-xs text-blue-700">
              <strong>How Tesht reduces premiums:</strong> Every verifiable agent identity with a trust score
              above 80 qualifies for the insurable tier. Deploying Tesht shifts agents from uninsurable ($0.5×
              multiplier) to insurable rates by providing cryptographic proof of identity and behavior.
            </div>
          </div>

          {/* Agent table */}
          <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <h3 className="text-sm font-bold text-gray-800">
                Agent Risk Ledger {filterTier !== "all" && `— ${filterTier}`}
              </h3>
              <span className="text-xs text-gray-500">{filtered.length} agents</span>
            </div>
            <div className="divide-y divide-gray-100 max-h-[400px] overflow-y-auto">
              {filtered.map((agent) => {
                const style = TIER_STYLES[agent.risk_tier] || TIER_STYLES.elevated;
                return (
                  <div key={agent.did} className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-gray-800">{agent.name}</span>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${style.bg} ${style.text} font-medium`}>
                            {agent.risk_tier}
                          </span>
                          {agent.spiffe_id && (
                            <span className="text-xs bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-full">SPIFFE</span>
                          )}
                        </div>
                        <p className="text-xs font-mono text-gray-400 mt-0.5 truncate">{agent.did}</p>
                        {agent.spiffe_id && (
                          <p className="text-xs font-mono text-indigo-400 mt-0.5 truncate">{agent.spiffe_id}</p>
                        )}
                        <ScoreBar score={agent.trust_score} tier={agent.risk_tier} />
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className="text-xs text-gray-500">{agent.event_count} events</p>
                        <p className={`text-xs font-semibold mt-0.5 ${agent.recent_delta >= 0 ? "text-emerald-600" : "text-red-600"}`}>
                          {agent.recent_delta >= 0 ? "+" : ""}{agent.recent_delta} recent
                        </p>
                        <p className="text-xs text-gray-400 mt-0.5">{(agent.failure_rate * 100).toFixed(0)}% failure</p>
                      </div>
                    </div>
                  </div>
                );
              })}
              {filtered.length === 0 && (
                <div className="p-8 text-center text-gray-400 text-sm">No agents in this tier.</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
