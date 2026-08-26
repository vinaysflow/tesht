"use client";

import { useState, useEffect } from "react";
import { apiGet } from "../../../lib/api";

type Framework = "SOC2" | "HIPAA" | "EU AI Act" | "ISO 42001";

interface ControlEvidence {
  control_id: string;
  control_name: string;
  description: string;
  tesht_mechanism: string;
  evidence_value: string;
  status: string;
  passing: boolean;
}

interface ComplianceReport {
  framework: string;
  tenant_id: string;
  controls_total: number;
  controls_passing: number;
  controls_automated: number;
  chain_valid: boolean;
  audit_events_count: number;
  controls: ControlEvidence[];
  generated_at: string;
}

const FRAMEWORKS: { id: Framework; description: string; color: string }[] = [
  { id: "SOC2", description: "Trust service criteria for security, availability, and confidentiality", color: "blue" },
  { id: "HIPAA", description: "Health data privacy and security safeguards", color: "purple" },
  { id: "EU AI Act", description: "EU regulation for AI systems — risk-based requirements", color: "indigo" },
  { id: "ISO 42001", description: "AI management system certification standard", color: "teal" },
];

function ScoreRing({ passing, total }: { passing: number; total: number }) {
  const pct = total > 0 ? Math.round((passing / total) * 100) : 0;
  const color = pct >= 80 ? "text-emerald-600" : pct >= 60 ? "text-amber-600" : "text-red-600";
  const bg = pct >= 80 ? "bg-emerald-50" : pct >= 60 ? "bg-amber-50" : "bg-red-50";
  return (
    <div className={`${bg} rounded-2xl p-5 text-center`}>
      <p className={`text-4xl font-black ${color}`}>{pct}%</p>
      <p className="text-sm text-gray-600 mt-1">{passing}/{total} controls passing</p>
      <p className="text-xs text-gray-400 mt-0.5">100% automated evidence</p>
    </div>
  );
}

export function ComplianceTab() {
  const [activeFramework, setActiveFramework] = useState<Framework>("SOC2");
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setReport(null);
    apiGet<ComplianceReport>(`/v1/compliance/report?framework=${encodeURIComponent(activeFramework)}`)
      .then(setReport)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [activeFramework]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl p-6 text-white">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center text-2xl flex-shrink-0">📋</div>
          <div>
            <h2 className="text-lg font-bold">Compliance Scorecard</h2>
            <p className="text-blue-100 text-sm mt-1">
              Every Tesht control maps to a compliance framework requirement.
              All evidence is generated automatically from live system data.
            </p>
          </div>
        </div>
      </div>

      {/* Framework selector */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {FRAMEWORKS.map((fw) => (
          <button
            key={fw.id}
            onClick={() => setActiveFramework(fw.id)}
            className={`text-left p-4 rounded-xl border-2 transition-all ${
              activeFramework === fw.id
                ? "border-blue-400 bg-blue-50 shadow-sm"
                : "border-gray-200 bg-white hover:border-gray-300"
            }`}
          >
            <p className={`text-sm font-bold ${activeFramework === fw.id ? "text-blue-900" : "text-gray-800"}`}>
              {fw.id}
            </p>
            <p className="text-xs text-gray-500 mt-1 leading-snug">{fw.description}</p>
          </button>
        ))}
      </div>

      {loading && (
        <div className="py-12 text-center text-gray-400">
          <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm">Loading compliance data...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          <p className="font-semibold">Failed to load compliance report</p>
          <p className="font-mono text-xs mt-1">{error}</p>
        </div>
      )}

      {report && !loading && (
        <div className="space-y-4">
          {/* Summary cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <ScoreRing passing={report.controls_passing} total={report.controls_total} />
            <div className="bg-white border border-gray-200 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-gray-800">{report.audit_events_count}</p>
              <p className="text-sm text-gray-600 mt-1">Audit events</p>
              <p className="text-xs mt-0.5">
                Chain: {" "}
                <span className={report.chain_valid ? "text-emerald-600 font-semibold" : "text-red-600 font-semibold"}>
                  {report.chain_valid ? "VERIFIED ✓" : "BROKEN ✗"}
                </span>
              </p>
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-indigo-600">100%</p>
              <p className="text-sm text-gray-600 mt-1">Automated evidence</p>
              <p className="text-xs text-gray-400 mt-0.5">Zero manual screenshots</p>
            </div>
          </div>

          {/* Control table */}
          <div className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-100">
              <h3 className="text-sm font-bold text-gray-800">{report.framework} Controls — Live Evidence</h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Evidence is pulled directly from the live system — not screenshots or manual entries.
              </p>
            </div>
            <div className="divide-y divide-gray-100">
              {report.controls.map((ctrl) => (
                <div key={ctrl.control_id} className="p-4 flex items-start gap-4">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 text-sm font-bold ${
                    ctrl.passing ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-700"
                  }`}>
                    {ctrl.passing ? "✓" : "✗"}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono bg-gray-100 px-2 py-0.5 rounded text-gray-600">{ctrl.control_id}</span>
                      <span className="text-sm font-semibold text-gray-800">{ctrl.control_name}</span>
                      <span className="text-xs bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full">{ctrl.status}</span>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{ctrl.description}</p>
                    <div className="mt-2 flex flex-col gap-1">
                      <div className="flex items-start gap-1.5">
                        <span className="text-xs text-indigo-600 font-medium flex-shrink-0">Tesht:</span>
                        <span className="text-xs text-gray-600">{ctrl.tesht_mechanism}</span>
                      </div>
                      <div className="flex items-start gap-1.5">
                        <span className="text-xs text-emerald-600 font-medium flex-shrink-0">Evidence:</span>
                        <span className="text-xs text-gray-700 font-medium">{ctrl.evidence_value}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <p className="text-xs text-gray-400 text-center">
            Report generated: {report.generated_at} · Tenant: {report.tenant_id}
          </p>
        </div>
      )}
    </div>
  );
}
