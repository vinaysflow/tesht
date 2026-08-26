"use client";

import { useEffect, useReducer, useCallback } from "react";
import {
  ALL_SCENARIOS,
  DemoPath,
  ScenarioDef,
  scenariosByPath,
} from "./scenarios";
import { ScenarioRunner } from "./components/ScenarioRunner";
import { SystemPulse } from "./components/SystemPulse";
import { IdentityBridgeTab } from "./components/IdentityBridgeTab";
import { ComplianceTab } from "./components/ComplianceTab";
import { RiskDashboardTab } from "./components/RiskDashboardTab";
import { AnomalyTab } from "./components/AnomalyTab";
import { MarketplaceTab } from "./components/MarketplaceTab";
import {
  apiBase,
  getAccessToken,
  setAccessToken,
  clearAccessToken,
} from "../../lib/api";

type MainTab = "scenarios" | "identity-bridge" | "compliance" | "marketplace" | "risk" | "anomaly";

// ─── State ────────────────────────────────────────────────────────────────────

interface DashboardState {
  sessionStatus: "init" | "ready" | "error";
  tenantId: string;
  sessionError: string;
  activePath: DemoPath;
  activeScenarioId: string | null;
  activeTab: MainTab;
}

type Action =
  | { type: "SESSION_READY"; tenantId: string }
  | { type: "SESSION_ERROR"; error: string }
  | { type: "SET_PATH"; path: DemoPath }
  | { type: "SET_SCENARIO"; id: string }
  | { type: "SET_TAB"; tab: MainTab };

function reducer(state: DashboardState, action: Action): DashboardState {
  switch (action.type) {
    case "SESSION_READY":
      return { ...state, sessionStatus: "ready", tenantId: action.tenantId, sessionError: "" };
    case "SESSION_ERROR":
      return { ...state, sessionStatus: "error", sessionError: action.error };
    case "SET_PATH": {
      const first = scenariosByPath(action.path)[0]?.id ?? null;
      return { ...state, activePath: action.path, activeScenarioId: first };
    }
    case "SET_SCENARIO":
      return { ...state, activeScenarioId: action.id };
    case "SET_TAB":
      return { ...state, activeTab: action.tab };
    default:
      return state;
  }
}

const INITIAL_STATE: DashboardState = {
  sessionStatus: "init",
  tenantId: "",
  sessionError: "",
  activePath: "happy",
  activeScenarioId: ALL_SCENARIOS.find((s) => s.path === "happy")?.id ?? null,
  activeTab: "scenarios",
};

// ─── Path metadata ─────────────────────────────────────────────────────────

const PATHS: { id: DemoPath; label: string; tagline: string; description: string; color: string; activeBg: string; dot: string }[] = [
  {
    id: "happy",
    label: "Happy Path",
    tagline: "Everything works as expected",
    description: "Credentials issued, verified, commerce authorized, chains intact. See Tesht protect your agents through the normal workflow.",
    color: "border-emerald-400",
    activeBg: "bg-emerald-50 border-emerald-400",
    dot: "bg-emerald-500",
  },
  {
    id: "unhappy",
    label: "Unhappy Path",
    tagline: "Attacks and misuse are blocked",
    description: "Currency mismatch, over-budget, replay attacks, scope escalation — watch Tesht reject every one at the protocol level.",
    color: "border-red-300",
    activeBg: "bg-red-50 border-red-400",
    dot: "bg-red-500",
  },
  {
    id: "edge",
    label: "Edge Cases",
    tagline: "Boundary conditions handled",
    description: "Expired credentials, tampered JWTs, cascade revocation, audit chain integrity — the hard cases that break other systems.",
    color: "border-amber-300",
    activeBg: "bg-amber-50 border-amber-400",
    dot: "bg-amber-500",
  },
];

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function DemoDashboardPage() {
  const [state, dispatch] = useReducer(reducer, INITIAL_STATE);

  const ensureSession = useCallback(async () => {
    // Minimum scopes required for all dashboard tabs to function
    const REQUIRED_SCOPES = [
      "credentials:verify", "credentials:issue", "tenant:admin",
      "trust:read", "compliance:read", "marketplace:read",
    ];

    // Check if stored token is still valid (not expired) AND has all required scopes
    const existing = getAccessToken();
    if (existing) {
      try {
        const parts = existing.split(".");
        if (parts.length === 3) {
          const pad = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
          const payload = JSON.parse(atob(pad(parts[1].replace(/-/g, "+").replace(/_/g, "/"))));
          const nowSec = Math.floor(Date.now() / 1000);
          const notExpired = payload.exp && payload.exp - nowSec > 60;
          // Parse scopes from token (can be array or space-separated string)
          const tokenScopes: string[] = Array.isArray(payload.scope)
            ? payload.scope
            : typeof payload.scope === "string"
            ? payload.scope.split(" ")
            : [];
          const hasAllScopes = REQUIRED_SCOPES.every((s) => tokenScopes.includes(s));
          if (notExpired && hasAllScopes) {
            dispatch({ type: "SESSION_READY", tenantId: payload.tenant ?? "(existing session)" });
            return;
          }
        }
      } catch {
        // Malformed token — fall through to refresh
      }
      // Token is expired, malformed, or missing required scopes — discard and re-issue
      clearAccessToken();
    }
    const base = apiBase();
    try {
      const res = await fetch(`${base}/v1/demo/session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
      const data = await res.json();
      setAccessToken(data.token);
      dispatch({ type: "SESSION_READY", tenantId: data.tenant_id });
    } catch (e: unknown) {
      dispatch({
        type: "SESSION_ERROR",
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }, []);

  useEffect(() => {
    ensureSession();
  }, [ensureSession]);

  async function handleReset() {
    clearAccessToken();
    dispatch({ type: "SESSION_ERROR", error: "" });
    await ensureSession();
  }

  const scenariosForPath = scenariosByPath(state.activePath);
  const activeScenario: ScenarioDef | undefined =
    ALL_SCENARIOS.find((s) => s.id === state.activeScenarioId) ??
    scenariosForPath[0];

  const activePath = PATHS.find((p) => p.id === state.activePath)!;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="w-9 h-9 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center text-white text-sm font-bold shadow-sm">
              P
            </div>
            <div>
              <h1 className="text-base font-bold text-gray-900">Tesht (Pramana)</h1>
              <p className="text-xs text-gray-500">Interactive Security Demo — see every control in action</p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-50 border border-gray-200">
              <span
                className={`w-2 h-2 rounded-full ${
                  state.sessionStatus === "ready"
                    ? "bg-emerald-500"
                    : state.sessionStatus === "error"
                    ? "bg-red-500"
                    : "bg-amber-400 animate-pulse"
                }`}
              />
              <span className="text-gray-600 font-mono">
                {state.sessionStatus === "init"
                  ? "Connecting..."
                  : state.sessionStatus === "error"
                  ? "Connection error"
                  : "Connected"}
              </span>
            </div>
            <button
              onClick={handleReset}
              className="px-3 py-1.5 rounded-lg border border-gray-200 text-gray-500 hover:bg-gray-50 hover:text-gray-700 transition-colors"
            >
              Reset
            </button>
            <a
              href="/"
              className="px-3 py-1.5 rounded-lg border border-gray-200 text-gray-500 hover:bg-gray-50 hover:text-gray-700 transition-colors"
            >
              Home
            </a>
          </div>
        </div>
      </div>

      {/* Session error */}
      {state.sessionStatus === "error" && state.sessionError && (
        <div className="max-w-7xl mx-auto px-6 mt-4">
          <div className="bg-red-50 border border-red-200 rounded-xl px-5 py-4 text-sm text-red-700">
            <p className="font-semibold">Unable to connect to Tesht backend</p>
            <p className="mt-1 font-mono text-xs">{state.sessionError}</p>
            <p className="mt-2 text-xs text-red-600">Make sure the backend is running on port 5051. Check the terminal for errors.</p>
          </div>
        </div>
      )}

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">

        {/* Hero */}
        <div className="text-center max-w-2xl mx-auto">
          <h2 className="text-2xl font-bold text-gray-900">
            See How Tesht Protects Your AI Agents
          </h2>
          <p className="text-gray-500 mt-2 text-sm leading-relaxed">
            Run real scenarios against a live backend. Each scenario demonstrates a specific security control —
            from identity verification to budget enforcement to tamper detection.
            Every step shows you exactly what happens and why it matters.
          </p>
        </div>

        {/* System Pulse — always visible when session ready */}
        {state.sessionStatus === "ready" && <SystemPulse />}

        {/* Main Tab Navigation */}
        {state.sessionStatus === "ready" && (
          <div className="flex gap-1 p-1 bg-gray-100 rounded-xl flex-wrap">
            {([
              { id: "scenarios",       label: "Scenarios",    icon: "🔒" },
              { id: "identity-bridge", label: "SPIFFE Bridge", icon: "🔗" },
              { id: "compliance",      label: "Compliance",   icon: "📋" },
              { id: "marketplace",     label: "Marketplace",  icon: "🏪" },
              { id: "risk",            label: "Risk",         icon: "🛡️" },
              { id: "anomaly",         label: "Anomalies",    icon: "⚠️" },
            ] as { id: MainTab; label: string; icon: string }[]).map((tab) => (
              <button
                key={tab.id}
                onClick={() => dispatch({ type: "SET_TAB", tab: tab.id })}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  state.activeTab === tab.id
                    ? "bg-white shadow-sm text-gray-900"
                    : "text-gray-500 hover:text-gray-700"
                }`}
              >
                <span>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        )}

        {/* Identity Bridge Tab */}
        {state.sessionStatus === "ready" && state.activeTab === "identity-bridge" && <IdentityBridgeTab />}

        {/* Compliance Tab */}
        {state.sessionStatus === "ready" && state.activeTab === "compliance" && <ComplianceTab />}

        {/* Marketplace Tab */}
        {state.sessionStatus === "ready" && state.activeTab === "marketplace" && <MarketplaceTab />}

        {/* Risk Dashboard Tab */}
        {state.sessionStatus === "ready" && state.activeTab === "risk" && <RiskDashboardTab />}

        {/* Anomaly Detection Tab */}
        {state.sessionStatus === "ready" && state.activeTab === "anomaly" && <AnomalyTab />}

        {/* Scenarios Tab */}
        {state.activeTab === "scenarios" && (
          <>
            {/* Path selector */}
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Choose a test category
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {PATHS.map((p) => {
                  const isActive = state.activePath === p.id;
                  return (
                    <button
                      key={p.id}
                      onClick={() => dispatch({ type: "SET_PATH", path: p.id })}
                      className={`text-left p-5 rounded-2xl border-2 transition-all ${
                        isActive
                          ? p.activeBg + " shadow-md"
                          : "border-gray-200 bg-white text-gray-700 hover:border-gray-300 hover:shadow-sm"
                      }`}
                    >
                      <div className="flex items-center gap-2.5 mb-2">
                        <div className={`w-3 h-3 rounded-full ${p.dot}`} />
                        <span className="font-bold text-sm">{p.label}</span>
                        <span className="ml-auto text-xs opacity-50 font-medium">
                          {scenariosByPath(p.id).length} scenarios
                        </span>
                      </div>
                      <p className="text-xs font-semibold opacity-70 mb-1">{p.tagline}</p>
                      <p className="text-xs leading-relaxed opacity-60">{p.description}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Scenario picker */}
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
                {activePath.label} Scenarios
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {scenariosForPath.map((scenario) => {
                  const isActive = state.activeScenarioId === scenario.id;
                  return (
                    <button
                      key={scenario.id}
                      onClick={() => dispatch({ type: "SET_SCENARIO", id: scenario.id })}
                      className={`text-left p-4 rounded-xl border-2 transition-all ${
                        isActive
                          ? "border-blue-400 bg-blue-50 shadow-sm"
                          : "border-gray-200 bg-white hover:border-gray-300 hover:shadow-sm"
                      }`}
                    >
                      <p className={`text-sm font-semibold ${isActive ? "text-blue-900" : "text-gray-800"}`}>
                        {scenario.title}
                      </p>
                      <p className="text-xs text-gray-500 mt-1 leading-snug">{scenario.subtitle}</p>
                      <div className="flex items-center gap-2 mt-2.5">
                        <span className="text-xs text-gray-400">{scenario.steps.length} steps</span>
                        <span className="text-xs text-gray-300">|</span>
                        <span className="text-xs text-gray-400">{scenario.controlsProven.length} controls</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Active scenario runner */}
            {activeScenario && state.sessionStatus === "ready" && (
              <ScenarioRunner key={activeScenario.id} scenario={activeScenario} />
            )}
          </>
        )}

        {/* Loading state */}
        {state.sessionStatus === "init" && (
          <div className="py-24 text-center text-gray-400">
            <div className="w-8 h-8 border-2 border-blue-400 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-sm">Connecting to Tesht backend...</p>
          </div>
        )}

        {/* Footer */}
        <div className="pt-6 border-t border-gray-200 text-xs text-gray-400 flex flex-wrap items-center justify-between gap-3">
          <span>Tesht (Pramana) — W3C DIDs + Verifiable Credentials + AP2 Commerce for AI Agents</span>
          <div className="flex items-center gap-4">
            <a href="/demo" className="hover:text-gray-600 transition-colors">Legacy Demo</a>
            <a href="/audit" className="hover:text-gray-600 transition-colors">Audit Log</a>
          </div>
        </div>
      </div>
    </div>
  );
}
