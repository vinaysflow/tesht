"use client";

import { useState } from "react";
import { apiPost, apiGet } from "../../../lib/api";

interface AttestResponse {
  attested: boolean;
  spiffe_id: string;
  agent_did: string;
  vc_jwt: string;
  vc_id: string;
  trust_domain: string;
  workload_path: string;
  agent_created: boolean;
}

interface SpiffeAgentRow {
  name: string;
  spiffe_id: string;
  trust_domain: string;
  workload_path: string;
  role: string;
}

const DEMO_SVID_AGENTS: SpiffeAgentRow[] = [
  { name: "acme-procurement-alpha", spiffe_id: "spiffe://acme.corp/ns/production/sa/procurement-alpha",
    trust_domain: "acme.corp", workload_path: "/ns/production/sa/procurement-alpha", role: "Procurement Agent" },
  { name: "globalbank-trading-bot", spiffe_id: "spiffe://globalbank.com/ns/trading/sa/trading-bot",
    trust_domain: "globalbank.com", workload_path: "/ns/trading/sa/trading-bot", role: "Trading Bot" },
  { name: "healthplus-diagnosis-ai", spiffe_id: "spiffe://healthplus.ai/ns/clinical/sa/diagnosis-ai",
    trust_domain: "healthplus.ai", workload_path: "/ns/clinical/sa/diagnosis-ai", role: "Diagnosis AI" },
  { name: "euai-high-risk-agent", spiffe_id: "spiffe://euai.corp/ns/regulated/sa/high-risk-agent",
    trust_domain: "euai.corp", workload_path: "/ns/regulated/sa/high-risk-agent", role: "EU AI Act Regulated Agent" },
  { name: "ci-cd-deploy-bot", spiffe_id: "spiffe://internal.corp/ns/cicd/sa/deploy-bot",
    trust_domain: "internal.corp", workload_path: "/ns/cicd/sa/deploy-bot", role: "CI/CD Deploy Bot" },
];

function buildDemoSvid(spiffeId: string): string {
  const header = btoa(JSON.stringify({ alg: "EdDSA", typ: "JWT" }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const now = Math.floor(Date.now() / 1000);
  const payload = btoa(JSON.stringify({
    iss: spiffeId,
    sub: spiffeId,
    aud: ["tesht.local"],
    exp: now + 3600,
    iat: now,
    spiffe: true,
  })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const sig = "demo-sig-not-cryptographically-valid";
  return `${header}.${payload}.${sig}`;
}

type Step = "select" | "attest" | "done";

export function IdentityBridgeTab() {
  const [selected, setSelected] = useState<SpiffeAgentRow | null>(null);
  const [step, setStep] = useState<Step>("select");
  const [attesting, setAttesting] = useState(false);
  const [result, setResult] = useState<AttestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandVc, setExpandVc] = useState(false);

  async function handleAttest() {
    if (!selected) return;
    setAttesting(true);
    setError(null);
    setResult(null);
    setStep("attest");

    const svid = buildDemoSvid(selected.spiffe_id);
    try {
      const res = await apiPost<AttestResponse>("/v1/identity/attest", {
        svid_jwt: svid,
        agent_name: selected.role,
      });
      setResult(res);
      setStep("done");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setStep("select");
    } finally {
      setAttesting(false);
    }
  }

  function reset() {
    setSelected(null);
    setStep("select");
    setResult(null);
    setError(null);
    setExpandVc(false);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 to-blue-600 rounded-2xl p-6 text-white">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center text-2xl flex-shrink-0">
            🔗
          </div>
          <div>
            <h2 className="text-lg font-bold">SPIFFE Identity Bridge</h2>
            <p className="text-blue-100 text-sm mt-1">
              Turn infrastructure workload identity into application-layer authority.
              SPIFFE proves <em>who</em> the agent is — Tesht proves <em>what</em> it can do.
            </p>
          </div>
        </div>
      </div>

      {/* Architecture explainer */}
      <div className="bg-white rounded-2xl border border-gray-200 p-5">
        <h3 className="text-sm font-bold text-gray-800 mb-3">How the Bridge Works</h3>
        <div className="flex items-center gap-1 flex-wrap text-xs">
          {[
            { label: "SPIRE Server", desc: "Issues short-lived SVIDs", color: "bg-purple-100 text-purple-700 border-purple-200" },
            { label: "→", desc: "", color: "text-gray-400" },
            { label: "SPIFFE SVID", desc: "JWT with spiffe:// subject", color: "bg-blue-100 text-blue-700 border-blue-200" },
            { label: "→", desc: "", color: "text-gray-400" },
            { label: "POST /v1/identity/attest", desc: "Verify SVID, create agent", color: "bg-indigo-100 text-indigo-700 border-indigo-200" },
            { label: "→", desc: "", color: "text-gray-400" },
            { label: "W3C VC", desc: "Application-layer authority", color: "bg-emerald-100 text-emerald-700 border-emerald-200" },
            { label: "→", desc: "", color: "text-gray-400" },
            { label: "Delegation + Commerce", desc: "Scope-bound operations", color: "bg-amber-100 text-amber-700 border-amber-200" },
          ].map((n, i) =>
            n.label === "→" ? (
              <span key={i} className="text-gray-300 font-light text-sm px-1">→</span>
            ) : (
              <div key={i} className={`px-2.5 py-1.5 rounded-lg border ${n.color} font-mono`}>
                {n.label}
              </div>
            )
          )}
        </div>
        <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
          <div className="bg-red-50 border border-red-100 rounded-xl p-3">
            <p className="font-semibold text-red-700 mb-1">Without Tesht</p>
            <ul className="text-red-600 space-y-0.5">
              <li>• SPIFFE proves identity — but not what agent can do</li>
              <li>• No delegation chain verification</li>
              <li>• No spending limits at protocol level</li>
              <li>• No tamper-evident audit trail</li>
            </ul>
          </div>
          <div className="bg-emerald-50 border border-emerald-100 rounded-xl p-3">
            <p className="font-semibold text-emerald-700 mb-1">With Tesht Bridge</p>
            <ul className="text-emerald-600 space-y-0.5">
              <li>• Infrastructure identity + application authority</li>
              <li>• Scope-narrowing delegation chains enforced server-side</li>
              <li>• Cumulative budget enforcement with race-safe locking</li>
              <li>• SHA-256 hash-chained audit trail</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Step 1: Select agent */}
      <div className="bg-white rounded-2xl border border-gray-200 p-5">
        <h3 className="text-sm font-bold text-gray-800 mb-3">
          Step 1: Select a SPIFFE-Attested Workload
        </h3>
        <p className="text-xs text-gray-500 mb-4">
          These agents have been seeded with real SPIFFE IDs and Ed25519 keypairs.
          In production, a SPIRE agent would issue a cryptographic SVID; in this demo
          we build a demo SVID for illustration.
        </p>
        <div className="space-y-2">
          {DEMO_SVID_AGENTS.map((agent) => (
            <button
              key={agent.spiffe_id}
              onClick={() => { setSelected(agent); setStep("select"); setResult(null); setError(null); }}
              className={`w-full text-left p-4 rounded-xl border-2 transition-all ${
                selected?.spiffe_id === agent.spiffe_id
                  ? "border-indigo-400 bg-indigo-50"
                  : "border-gray-200 hover:border-gray-300"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-gray-800">{agent.role}</p>
                  <p className="text-xs font-mono text-indigo-600 mt-0.5">{agent.spiffe_id}</p>
                  <div className="flex gap-3 mt-1 text-xs text-gray-500">
                    <span>Trust domain: <strong>{agent.trust_domain}</strong></span>
                    <span>Path: <strong>{agent.workload_path}</strong></span>
                  </div>
                </div>
                {selected?.spiffe_id === agent.spiffe_id && (
                  <span className="text-indigo-500 text-lg flex-shrink-0">✓</span>
                )}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Step 2: Attest */}
      {selected && step !== "done" && (
        <div className="bg-white rounded-2xl border border-gray-200 p-5">
          <h3 className="text-sm font-bold text-gray-800 mb-2">
            Step 2: Attest Workload Identity
          </h3>
          <p className="text-xs text-gray-500 mb-4">
            Send the SPIFFE SVID to <code className="bg-gray-100 px-1 rounded">POST /v1/identity/attest</code>.
            Tesht will verify the SVID, locate the agent&apos;s registered DID, and issue a
            W3C WorkloadAttestationCredential binding the SPIFFE ID to Tesht authority.
          </p>
          <div className="bg-gray-50 border border-gray-200 rounded-xl p-3 font-mono text-xs text-gray-600 mb-4 overflow-x-auto">
            <p className="text-gray-400 mb-1">// Request body</p>
            <pre>{JSON.stringify({
              svid_jwt: `${buildDemoSvid(selected.spiffe_id).slice(0, 40)}...`,
              agent_name: selected.role,
            }, null, 2)}</pre>
          </div>
          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 rounded-xl p-3 text-xs text-red-700">
              <p className="font-semibold">Attestation failed</p>
              <p className="mt-1 font-mono">{error}</p>
            </div>
          )}
          <button
            onClick={handleAttest}
            disabled={attesting}
            className="w-full py-3 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white font-semibold text-sm transition-colors"
          >
            {attesting ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Attesting workload identity...
              </span>
            ) : (
              "Attest SPIFFE Identity → Issue VC"
            )}
          </button>
        </div>
      )}

      {/* Step 3: Result */}
      {result && step === "done" && (
        <div className="space-y-4">
          {/* Success banner */}
          <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-5">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 bg-emerald-500 rounded-full flex items-center justify-center text-white text-sm font-bold">✓</div>
              <div>
                <p className="font-bold text-emerald-800 text-sm">Workload Attested Successfully</p>
                <p className="text-xs text-emerald-600">
                  {result.agent_created ? "New Tesht agent created and linked to SPIFFE ID" : "Existing agent linked — attestation refreshed"}
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              {[
                { label: "SPIFFE ID", value: result.spiffe_id },
                { label: "Trust Domain", value: result.trust_domain },
                { label: "Workload Path", value: result.workload_path },
                { label: "Tesht DID", value: result.agent_did.slice(0, 40) + "…" },
                { label: "VC ID", value: result.vc_id },
                { label: "Agent Created", value: result.agent_created ? "Yes (new)" : "No (existing)" },
              ].map((f) => (
                <div key={f.label} className="bg-white rounded-lg border border-emerald-100 p-2.5">
                  <p className="text-emerald-600 font-medium">{f.label}</p>
                  <p className="font-mono text-gray-700 mt-0.5 break-all">{f.value}</p>
                </div>
              ))}
            </div>
          </div>

          {/* What just happened */}
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <h3 className="text-sm font-bold text-gray-800 mb-2">What Just Happened</h3>
            <ol className="text-xs text-gray-600 space-y-2">
              {[
                `Tesht received a SPIFFE SVID with sub = "${result.spiffe_id}"`,
                "The SVID was decoded and the SPIFFE ID was extracted and validated",
                `The agent with spiffe_id = "${result.spiffe_id}" was located in the Tesht registry (bridge-mode resolution via DB)`,
                "A W3C WorkloadAttestationCredential was issued using the agent's Ed25519 keypair",
                "The VC was signed, stored, and can now be presented for delegation + commerce operations",
                "An audit event was written: identity.workload.attested",
              ].map((step, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="w-5 h-5 flex-shrink-0 rounded-full bg-indigo-100 text-indigo-700 text-xs font-bold flex items-center justify-center mt-0.5">{i + 1}</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* VC JWT */}
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-gray-800">Issued WorkloadAttestationCredential (JWT)</h3>
              <button
                onClick={() => setExpandVc(!expandVc)}
                className="text-xs text-indigo-600 hover:text-indigo-800"
              >
                {expandVc ? "Hide" : "Show"} raw JWT
              </button>
            </div>
            <p className="text-xs text-gray-500 mb-3">
              This W3C VC binds the SPIFFE workload identity to Tesht authority.
              It can be presented to any Tesht-enabled service to prove the agent&apos;s
              infrastructure attestation and trigger delegation/commerce authorization.
            </p>
            {expandVc && (
              <div className="bg-gray-900 rounded-xl p-4 font-mono text-xs text-green-400 overflow-x-auto">
                <pre className="break-all whitespace-pre-wrap">{result.vc_jwt}</pre>
              </div>
            )}
          </div>

          {/* Controls proven */}
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <h3 className="text-sm font-bold text-gray-800 mb-3">Security Controls Demonstrated</h3>
            <div className="grid grid-cols-2 gap-2">
              {[
                "SPIFFE workload identity resolution",
                "Ed25519 signature binding",
                "W3C VC issuance (WorkloadAttestationCredential)",
                "SPIFFE ID → Tesht DID bridge",
                "Idempotent attestation (safe to call repeatedly)",
                "Tamper-evident audit trail (identity.workload.attested)",
              ].map((c) => (
                <div key={c} className="flex items-center gap-2 text-xs text-gray-700">
                  <span className="w-4 h-4 rounded-full bg-emerald-500 text-white flex items-center justify-center text-xs flex-shrink-0">✓</span>
                  {c}
                </div>
              ))}
            </div>
          </div>

          <button onClick={reset} className="text-xs text-gray-400 hover:text-gray-600 underline">
            Try another agent
          </button>
        </div>
      )}
    </div>
  );
}
