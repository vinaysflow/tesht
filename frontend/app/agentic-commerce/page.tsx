"use client";

/**
 * Agentic Commerce — end-to-end dogfood surface.
 *
 * A human authorizes a shopping agent with a budget + merchant allowlist
 * (creates a Pramana authorization Session), then the agent "shops" a mock
 * storefront. Every purchase runs through the Session decide path composed
 * with AP2 mandates: scope + trust + cumulative budget + merchant allowlist.
 * Trust drops trigger a step-up modal; the human can revoke at any time.
 *
 * No real money moves — purchases are authorization decisions, not settlement.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  apiBase,
  apiGet,
  apiPost,
  clearAccessToken,
  getAccessToken,
  setAccessToken,
} from "../../lib/api";

type Product = {
  id: string;
  name: string;
  merchant: string;
  merchant_name: string;
  price: number; // cents
  currency: string;
  category: string;
  image: string;
};

type Merchant = { id: string; name: string };
type Catalog = { products: Product[]; merchants: Merchant[] };

type Budget = {
  budget: number | null;
  spent: number;
  remaining: number | null;
  currency: string;
};

type Decision = {
  session_id: string;
  decision: "allow" | "step_up" | "block";
  error_code?: string | null;
  reason?: string | null;
  trust_score?: number | null;
  factors?: { budget?: Budget } & Record<string, unknown>;
  session_status?: string;
};

type SessionResp = {
  id: string;
  status: string;
  agent_did: string;
  human_did?: string | null;
  scope: Record<string, unknown>;
  packs: string[];
};

type ActivityItem = {
  ts: string;
  kind: "allow" | "step_up" | "block" | "info";
  title: string;
  detail: string;
};

const RISK_LEVELS = [
  { id: "high", label: "High trust (allow)", score: 90 },
  { id: "medium", label: "Medium (step-up)", score: 60 },
  { id: "low", label: "Low (block)", score: 30 },
] as const;

function money(cents: number | null | undefined, currency = "USD"): string {
  if (cents == null) return "—";
  const sym = currency === "USD" ? "$" : "";
  return `${sym}${(cents / 100).toFixed(2)}`;
}

function decColor(kind: ActivityItem["kind"]): string {
  return kind === "allow"
    ? "text-green-700 bg-green-50 border-green-200"
    : kind === "step_up"
    ? "text-amber-700 bg-amber-50 border-amber-200"
    : kind === "block"
    ? "text-red-700 bg-red-50 border-red-200"
    : "text-gray-700 bg-gray-50 border-gray-200";
}

export default function AgenticCommercePage() {
  const base = apiBase();
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string>("");

  const [catalog, setCatalog] = useState<Catalog | null>(null);

  // Authorize form
  const [humanName, setHumanName] = useState("did:example:alice");
  const [budgetDollars, setBudgetDollars] = useState(300);
  const [allMerchants, setAllMerchants] = useState(true);
  const [selectedMerchants, setSelectedMerchants] = useState<Set<string>>(new Set());
  const [risk, setRisk] = useState<(typeof RISK_LEVELS)[number]["id"]>("high");

  const [session, setSession] = useState<SessionResp | null>(null);
  const [budget, setBudget] = useState<Budget | null>(null);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [busy, setBusy] = useState(false);

  // Step-up modal state
  const [stepUpFor, setStepUpFor] = useState<Product | null>(null);

  const riskScore = useMemo(
    () => RISK_LEVELS.find((r) => r.id === risk)?.score ?? 90,
    [risk]
  );

  const log = useCallback((item: Omit<ActivityItem, "ts">) => {
    setActivity((prev) => [{ ts: new Date().toLocaleTimeString(), ...item }, ...prev].slice(0, 40));
  }, []);

  const ensureSession = useCallback(async () => {
    if (getAccessToken()) {
      setReady(true);
      return;
    }
    const res = await fetch(`${base}/v1/demo/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    const data = await res.json();
    setAccessToken(data.token);
    setReady(true);
  }, [base]);

  useEffect(() => {
    (async () => {
      try {
        await ensureSession();
        const cat = await apiGet<Catalog>("/v1/storefront/products");
        setCatalog(cat);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [ensureSession]);

  function toggleMerchant(id: string) {
    setSelectedMerchants((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function authorize() {
    setError("");
    setBusy(true);
    try {
      const agent = await apiPost<{ did: string }>("/v1/agents", {
        name: `shopping-agent-${Date.now()}`,
      });
      const scope: Record<string, unknown> = {
        actions: ["purchase"],
        max_amount: Math.round(budgetDollars * 100),
        currency: "USD",
      };
      if (!allMerchants) {
        scope.merchants = Array.from(selectedMerchants);
      }
      const s = await apiPost<SessionResp>("/v1/sessions", {
        agent_did: agent.did,
        human_did: humanName,
        scope,
        packs: ["core", "commerce"],
        ttl_seconds: 3600,
      });
      setSession(s);
      setBudget({
        budget: Math.round(budgetDollars * 100),
        spent: 0,
        remaining: Math.round(budgetDollars * 100),
        currency: "USD",
      });
      setActivity([]);
      log({
        kind: "info",
        title: "Agent authorized",
        detail: `${humanName} → ${agent.did.slice(0, 28)}… · budget ${money(
          Math.round(budgetDollars * 100)
        )} · merchants ${allMerchants ? "any" : Array.from(selectedMerchants).join(", ") || "none"}`,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function decide(product: Product, scoreOverride?: number): Promise<Decision | null> {
    if (!session) return null;
    const body: Record<string, unknown> = {
      action: "purchase",
      amount: product.price,
      currency: product.currency,
      merchant: product.merchant,
    };
    if (scoreOverride != null) body.simulate_score = scoreOverride;
    else body.simulate_score = riskScore;
    return apiPost<Decision>(`/v1/sessions/${session.id}/actions`, body);
  }

  function applyDecision(product: Product, d: Decision) {
    if (d.factors?.budget) setBudget(d.factors.budget);
    if (d.decision === "allow") {
      log({
        kind: "allow",
        title: `✓ Bought ${product.name}`,
        detail: `${money(product.price)} at ${product.merchant_name} · trust ${d.trust_score}/100 · remaining ${money(
          d.factors?.budget?.remaining
        )}`,
      });
    } else if (d.decision === "step_up") {
      setStepUpFor(product);
      log({
        kind: "step_up",
        title: `↑ Step-up required for ${product.name}`,
        detail: d.reason || "Trust below allow threshold — human approval needed",
      });
    } else {
      log({
        kind: "block",
        title: `✗ Blocked: ${product.name}`,
        detail: `${d.error_code || "blocked"} — ${d.reason || ""}`,
      });
    }
  }

  async function buy(product: Product) {
    if (!session) return;
    setBusy(true);
    setError("");
    try {
      const d = await decide(product);
      if (d) applyDecision(product, d);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function completeStepUp() {
    if (!session || !stepUpFor) return;
    setBusy(true);
    setError("");
    const product = stepUpFor;
    try {
      await apiPost<SessionResp>(`/v1/sessions/${session.id}/step_up`, {
        metadata: { challenge: "human_present" },
      });
      log({ kind: "info", title: "Step-up completed", detail: "Fresh human proof accepted; retrying purchase" });
      setStepUpFor(null);
      // Retry the purchase now that the human re-authenticated (trust restored).
      const d = await decide(product, 90);
      if (d) applyDecision(product, d);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (!session) return;
    setBusy(true);
    setError("");
    try {
      const s = await apiPost<{ status: string }>(`/v1/sessions/${session.id}/revoke`, {
        cascade: true,
        reason: "human kill-switch",
      });
      setSession({ ...session, status: s.status });
      log({ kind: "block", title: "Session revoked", detail: "Kill-switch pulled — all further actions denied" });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setSession(null);
    setBudget(null);
    setActivity([]);
    setStepUpFor(null);
  }

  const revoked = session?.status === "revoked";
  const pct =
    budget && budget.budget
      ? Math.min(100, Math.round((budget.spent / budget.budget) * 100))
      : 0;

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 sticky top-0 z-20">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Agentic Commerce</h1>
            <p className="text-xs text-gray-500">
              Human → agent handoff · trust-gated purchases · AP2 budget · instant revoke
            </p>
          </div>
          <Link href="/" className="text-sm text-blue-600 hover:underline">
            ← Home
          </Link>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-6 py-6">
        {error && (
          <div className="mb-4 p-3 rounded border border-red-200 bg-red-50 text-red-700 text-sm">
            {error}
          </div>
        )}
        {!ready && <p className="text-gray-500">Initializing demo session…</p>}

        {/* Step 1: Authorize the agent */}
        {ready && !session && (
          <div className="bg-white rounded-lg border border-gray-200 p-6 max-w-2xl">
            <h2 className="font-semibold mb-1">1 · Authorize a shopping agent</h2>
            <p className="text-sm text-gray-500 mb-4">
              You (the human) delegate a budget to an agent. This creates a Pramana authorization
              session with the <code className="text-xs">core + commerce</code> packs.
            </p>

            <label className="block text-sm font-medium mb-1">Your identity (human DID)</label>
            <input
              value={humanName}
              onChange={(e) => setHumanName(e.target.value)}
              className="w-full border border-gray-300 rounded px-3 py-2 mb-4 text-sm"
            />

            <label className="block text-sm font-medium mb-1">Budget (USD)</label>
            <input
              type="number"
              min={1}
              value={budgetDollars}
              onChange={(e) => setBudgetDollars(Number(e.target.value))}
              className="w-40 border border-gray-300 rounded px-3 py-2 mb-4 text-sm"
            />

            <div className="mb-4">
              <label className="flex items-center gap-2 text-sm font-medium mb-2">
                <input
                  type="checkbox"
                  checked={allMerchants}
                  onChange={(e) => setAllMerchants(e.target.checked)}
                />
                Allow any merchant
              </label>
              {!allMerchants && (
                <div className="flex flex-wrap gap-2 pl-6">
                  {catalog?.merchants.map((m) => (
                    <label
                      key={m.id}
                      className="flex items-center gap-1 text-sm border border-gray-200 rounded px-2 py-1"
                    >
                      <input
                        type="checkbox"
                        checked={selectedMerchants.has(m.id)}
                        onChange={() => toggleMerchant(m.id)}
                      />
                      {m.name}
                    </label>
                  ))}
                </div>
              )}
            </div>

            <button
              onClick={authorize}
              disabled={busy}
              className="bg-blue-600 text-white rounded px-4 py-2 text-sm font-medium disabled:opacity-50"
            >
              {busy ? "Authorizing…" : "Authorize agent →"}
            </button>
          </div>
        )}

        {/* Active session: storefront + budget + activity */}
        {session && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left: session panel + storefront */}
            <div className="lg:col-span-2 space-y-6">
              {/* Session / budget */}
              <div className="bg-white rounded-lg border border-gray-200 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <span
                      className={`text-xs font-semibold px-2 py-0.5 rounded ${
                        revoked ? "bg-red-100 text-red-700" : "bg-green-100 text-green-700"
                      }`}
                    >
                      {revoked ? "REVOKED" : "ACTIVE"}
                    </span>
                    <span className="ml-2 text-xs text-gray-500 font-mono">
                      {session.agent_did.slice(0, 34)}…
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={revoke}
                      disabled={busy || revoked}
                      className="text-xs bg-red-600 text-white rounded px-3 py-1.5 disabled:opacity-40"
                    >
                      ⏻ Revoke (kill-switch)
                    </button>
                    <button
                      onClick={reset}
                      className="text-xs border border-gray-300 rounded px-3 py-1.5"
                    >
                      New session
                    </button>
                  </div>
                </div>

                {/* Budget meter */}
                <div className="mb-1 flex justify-between text-xs text-gray-500">
                  <span>Budget used</span>
                  <span>
                    {money(budget?.spent)} / {money(budget?.budget)} · remaining{" "}
                    <b>{money(budget?.remaining)}</b>
                  </span>
                </div>
                <div className="w-full h-3 bg-gray-100 rounded overflow-hidden">
                  <div
                    className={`h-3 ${pct > 85 ? "bg-red-500" : "bg-blue-500"}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>

                {/* Risk selector */}
                <div className="mt-4">
                  <span className="text-xs text-gray-500 mr-2">Simulated agent trust (dev):</span>
                  <div className="inline-flex gap-1">
                    {RISK_LEVELS.map((r) => (
                      <button
                        key={r.id}
                        onClick={() => setRisk(r.id)}
                        className={`text-xs px-2 py-1 rounded border ${
                          risk === r.id
                            ? "bg-gray-900 text-white border-gray-900"
                            : "border-gray-300 text-gray-600"
                        }`}
                      >
                        {r.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Storefront */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                {catalog?.products.map((p) => (
                  <div key={p.id} className="bg-white rounded-lg border border-gray-200 p-4 flex flex-col">
                    <div className="text-4xl mb-2">{p.image}</div>
                    <div className="font-medium text-sm">{p.name}</div>
                    <div className="text-xs text-gray-500 mb-2">{p.merchant_name}</div>
                    <div className="font-semibold mb-3">{money(p.price)}</div>
                    <button
                      onClick={() => buy(p)}
                      disabled={busy || revoked}
                      className="mt-auto text-xs bg-blue-600 text-white rounded px-3 py-2 disabled:opacity-40"
                    >
                      🤖 Agent: Buy
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: activity feed */}
            <div className="bg-white rounded-lg border border-gray-200 p-5 h-fit lg:sticky lg:top-24">
              <h3 className="font-semibold text-sm mb-3">Decision activity</h3>
              {activity.length === 0 && (
                <p className="text-xs text-gray-400">No actions yet. Have the agent buy something.</p>
              )}
              <ul className="space-y-2">
                {activity.map((a, i) => (
                  <li key={i} className={`text-xs border rounded p-2 ${decColor(a.kind)}`}>
                    <div className="flex justify-between">
                      <span className="font-medium">{a.title}</span>
                      <span className="opacity-60">{a.ts}</span>
                    </div>
                    <div className="opacity-80">{a.detail}</div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Step-up modal */}
      {stepUpFor && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-30">
          <div className="bg-white rounded-lg p-6 max-w-sm w-full">
            <h3 className="font-semibold mb-2">Step-up authentication required</h3>
            <p className="text-sm text-gray-600 mb-4">
              Trust for the agent dropped below the allow threshold before buying{" "}
              <b>{stepUpFor.name}</b> ({money(stepUpFor.price)}). Approve as the human to continue.
            </p>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setStepUpFor(null)}
                className="text-sm border border-gray-300 rounded px-3 py-2"
              >
                Cancel
              </button>
              <button
                onClick={completeStepUp}
                disabled={busy}
                className="text-sm bg-blue-600 text-white rounded px-4 py-2 disabled:opacity-50"
              >
                ✓ Approve & retry
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
