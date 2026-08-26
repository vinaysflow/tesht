"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ScenarioDef } from "../scenarios";
import { runScenario, StepResult } from "../runner";
import { StepCard, StepState } from "./StepCard";
import { FlowDiagram } from "./FlowDiagram";
import { AuditTrail } from "./AuditTrail";
import { BadgeStatus } from "./StatusBadge";
import { apiGet } from "../../../lib/api";
import { SummarySnapshot } from "./SystemPulse";
import { BeforeAfterDiff } from "./BeforeAfterDiff";
import { ComparisonPanel } from "./ComparisonPanel";

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

interface ScenarioRunnerProps {
  scenario: ScenarioDef;
}

export function ScenarioRunner({ scenario }: ScenarioRunnerProps) {
  const [stepStates, setStepStates] = useState<Record<string, StepState>>(() =>
    Object.fromEntries(
      scenario.steps.map((s) => [s.id, { id: s.id, status: "pending" as BadgeStatus }])
    )
  );
  const [isRunning, setIsRunning] = useState(false);
  const [isDone, setIsDone] = useState(false);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [chainResult, setChainResult] = useState<ChainResult | null>(null);
  const [currentStepIndex, setCurrentStepIndex] = useState<number | undefined>(undefined);
  const [beforeSnapshot, setBeforeSnapshot] = useState<SummarySnapshot | null>(null);
  const [afterSnapshot, setAfterSnapshot] = useState<SummarySnapshot | null>(null);
  const abortRef = useRef(false);

  useEffect(() => {
    abortRef.current = true;
    setStepStates(
      Object.fromEntries(
        scenario.steps.map((s) => [s.id, { id: s.id, status: "pending" as BadgeStatus }])
      )
    );
    setIsRunning(false);
    setIsDone(false);
    setAuditEvents([]);
    setChainResult(null);
    setCurrentStepIndex(undefined);
    setBeforeSnapshot(null);
    setAfterSnapshot(null);
    abortRef.current = false;
  }, [scenario.id]);

  const loadAudit = useCallback(async () => {
    try {
      const data = await apiGet<{ events: AuditEvent[] }>("/v1/audit?limit=20");
      setAuditEvents(data.events ?? []);
    } catch { /* requires admin scope */ }
    try {
      const chain = await apiGet<ChainResult>("/v1/audit/verify");
      setChainResult(chain);
    } catch { /* ignore */ }
  }, []);

  async function handleRun() {
    if (isRunning) return;
    abortRef.current = false;
    setIsRunning(true);
    setIsDone(false);
    setAuditEvents([]);
    setChainResult(null);
    setBeforeSnapshot(null);
    setAfterSnapshot(null);
    setStepStates(
      Object.fromEntries(
        scenario.steps.map((s) => [s.id, { id: s.id, status: "pending" as BadgeStatus }])
      )
    );

    // Capture system state before the scenario runs
    try {
      const snap = await apiGet<SummarySnapshot>("/v1/demo/summary");
      setBeforeSnapshot(snap);
    } catch { /* ignore — endpoint may not be available */ }

    await runScenario(scenario, {
      onStepStart: (stepId) => {
        const idx = scenario.steps.findIndex((s) => s.id === stepId);
        setCurrentStepIndex(idx >= 0 ? idx : undefined);
        setStepStates((prev) => ({
          ...prev,
          [stepId]: { ...prev[stepId], id: stepId, status: "running" },
        }));
      },
      onStepComplete: (result: StepResult) => {
        setStepStates((prev) => ({
          ...prev,
          [result.stepId]: {
            id: result.stepId,
            status: result.status,
            request: result.request,
            response: result.response,
            error: result.error,
            durationMs: result.durationMs,
          },
        }));
      },
      onComplete: async () => {
        setCurrentStepIndex(undefined);
        setIsRunning(false);
        setIsDone(true);
        await loadAudit();
        // Capture system state after the scenario completes
        try {
          const snap = await apiGet<SummarySnapshot>("/v1/demo/summary");
          setAfterSnapshot(snap);
        } catch { /* ignore */ }
      },
    });
  }

  const passedControls = isDone
    ? scenario.steps.filter((s) => {
        const st = stepStates[s.id]?.status;
        return st === "success" || st === "expected-failure";
      })
    : [];
  const failedControls = isDone
    ? scenario.steps.filter((s) => stepStates[s.id]?.status === "failure")
    : [];
  const allPassed = isDone && failedControls.length === 0;

  return (
    <div className="space-y-5">
      {/* Scenario context card */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-6 py-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <h3 className="font-bold text-gray-900 text-lg">{scenario.title}</h3>
              <p className="text-gray-500 text-sm mt-1">{scenario.subtitle}</p>
            </div>
            <button
              onClick={handleRun}
              disabled={isRunning}
              className="flex-shrink-0 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white text-sm font-semibold rounded-xl transition-colors shadow-sm"
            >
              {isRunning ? "Running..." : isDone ? "Run Again" : "Run Scenario"}
            </button>
          </div>

          {/* Business context + risk */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
            <div className="px-4 py-3.5 bg-blue-50 border border-blue-100 rounded-xl">
              <p className="text-xs font-semibold text-blue-800 uppercase tracking-wide mb-1.5">Why this matters</p>
              <p className="text-sm text-blue-900 leading-relaxed">{scenario.businessContext}</p>
            </div>
            <div className="px-4 py-3.5 bg-amber-50 border border-amber-100 rounded-xl">
              <p className="text-xs font-semibold text-amber-800 uppercase tracking-wide mb-1.5">Risk without Tesht</p>
              <p className="text-sm text-amber-900 leading-relaxed">{scenario.riskWithout}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Flow diagram */}
      {(() => {
        const stepStatuses = scenario.steps.map((s) => {
          const st = stepStates[s.id]?.status;
          return (st === "running" ? "pending" : st ?? "pending") as "pending" | "success" | "failure" | "expected-failure";
        });
        return (
          <FlowDiagram
            nodes={scenario.flowNodes}
            edges={scenario.flowEdges}
            activeNodeIndex={currentStepIndex}
            stepStatuses={stepStatuses}
          />
        );
      })()}

      {/* Steps */}
      <div className="space-y-3">
        {scenario.steps.map((step, i) => (
          <StepCard
            key={step.id}
            step={step}
            state={stepStates[step.id] ?? { id: step.id, status: "pending" }}
            index={i}
          />
        ))}
      </div>

      {/* Executive Summary (after completion) */}
      {isDone && (
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          {/* Summary header */}
          <div className={`px-6 py-5 ${allPassed ? "bg-emerald-50 border-b border-emerald-100" : "bg-red-50 border-b border-red-100"}`}>
            <div className="flex items-center gap-3">
              <span className={`w-10 h-10 rounded-full flex items-center justify-center text-lg font-bold ${allPassed ? "bg-emerald-500 text-white" : "bg-red-500 text-white"}`}>
                {allPassed ? "\u2713" : "!"}
              </span>
              <div>
                <h4 className={`font-bold text-base ${allPassed ? "text-emerald-900" : "text-red-900"}`}>
                  {allPassed ? "All Controls Passed" : "Some Controls Failed"}
                </h4>
                <p className={`text-sm ${allPassed ? "text-emerald-700" : "text-red-700"}`}>
                  {passedControls.length} of {scenario.steps.length} steps completed successfully
                </p>
              </div>
            </div>
          </div>

          {/* What Just Happened — plain English */}
          <div className="px-6 py-5 border-b border-gray-100">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">What Just Happened</p>
            <p className="text-sm text-gray-700 leading-relaxed">{scenario.whatJustHappened}</p>
          </div>

          {/* Security Controls Scorecard */}
          <div className="px-6 py-5">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Security Controls Proven</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {scenario.controlsProven.map((control, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2.5 px-3.5 py-2.5 rounded-lg bg-gray-50 border border-gray-100"
                >
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-emerald-500 flex items-center justify-center">
                    <span className="text-white text-xs font-bold">{"\u2713"}</span>
                  </span>
                  <span className="text-sm text-gray-700">{control}</span>
                </div>
              ))}
            </div>
            <BeforeAfterDiff before={beforeSnapshot} after={afterSnapshot} />
          </div>
          {/* Comparison Panel */}
          {scenario.comparisonRows && scenario.comparisonRows.length > 0 && (
            <div className="px-6 pb-5">
              <ComparisonPanel rows={scenario.comparisonRows} />
            </div>
          )}
        </div>
      )}

      {/* Audit Trail (after completion) */}
      {isDone && (
        <AuditTrail
          initialEvents={auditEvents}
          initialChain={chainResult}
        />
      )}
    </div>
  );
}
