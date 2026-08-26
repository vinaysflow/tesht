import { useState } from 'react'
import { ProgressBar, StepCard } from './StepCard.jsx'
import { VPViewer }       from './VPViewer.jsx'
import { TrustTimeline }  from './TrustTimeline.jsx'
import { DelegationTree } from './DelegationTree.jsx'
import { IsolationView }  from './IsolationView.jsx'
import { DetectionPanel } from './DetectionPanel.jsx'
import { AuditTrail }     from './AuditTrail.jsx'
import { MultiHopView }   from './MultiHopView.jsx'
import { RevocationView } from './RevocationView.jsx'

const TABS = [
  { id: 'delegation',  label: '🔗 Delegation Chain',    act: 1 },
  { id: 'vp',          label: '🪪 Blended VP',           act: 2 },
  { id: 'isolation',   label: '🔐 Credential Isolation', act: 2 },
  { id: 'trust',       label: '📈 Trust Timeline',       act: 4 },
  { id: 'detection',   label: '🚨 Shadow Detection',     act: 5 },
  { id: 'multihop',    label: '🔀 Multi-Hop Delegation', act: 6 },
  { id: 'revocation',  label: '🚫 Revocation',           act: 7 },
  { id: 'audit',       label: '📋 CISO Audit',           act: 8 },
  { id: 'fleet',       label: '🌐 Fleet Dashboard',      act: 9 },
]

export function DemoRunner({ state, currentStep, stepLogs, results, errorMsg, onRun, onReset, activeTab, onTabChange }) {
  const [localTab, setLocalTab] = useState('delegation')
  const currentTab   = activeTab  ?? localTab
  const setActiveTab = onTabChange ?? setLocalTab

  const isComplete = state === 'complete'
  const isRunning  = state === 'running'

  const act1 = results.act1 || {}
  const act2 = results.act2 || {}
  const act4 = results.act4 || {}
  const act5 = results.act5 || {}
  const act6 = results.act6 || {}
  const act7 = results.act7 || {}
  const act8 = results.act8 || {}
  const act9 = results.act9 || {}

  const serverEntry = (act2.credentialsReceived?.requests || []).slice(-1)[0]

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex items-center gap-4 flex-wrap">
        {state === 'idle' && (
          <button
            onClick={onRun}
            className="shimmer-border p-px rounded-xl"
          >
            <div className="bg-tesht-dark hover:bg-tesht-card rounded-[11px] px-6 py-3 font-bold text-sm transition-colors">
              ▶ Run One-Click Demo
            </div>
          </button>
        )}
        {isRunning && (
          <div className="flex items-center gap-2 text-tesht-teal text-sm">
            <span className="animate-spin">⟳</span>
            <span>Running demo… Act {currentStep} of 9</span>
          </div>
        )}
        {(isComplete || state === 'error') && (
          <button
            onClick={onReset}
            className="border border-tesht-border px-4 py-2 rounded-xl text-sm hover:bg-tesht-card transition-colors"
          >
            ↺ Reset
          </button>
        )}
      </div>

      {/* Error panel */}
      {state === 'error' && errorMsg && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-4 text-sm text-red-300">
          <div className="font-bold mb-1">Demo Error</div>
          <pre className="whitespace-pre-wrap text-xs">{errorMsg}</pre>
          <div className="mt-3 text-xs text-red-400">
            Make sure all services are running. Run: <code className="font-mono">./scripts/demo_web.sh</code>
          </div>
        </div>
      )}

      {/* Progress */}
      {(isRunning || isComplete) && (
        <ProgressBar currentStep={isComplete ? 10 : currentStep} totalSteps={9} />
      )}

      {/* Step logs */}
      {(isRunning || isComplete) && stepLogs.length > 0 && (
        <div className="bg-tesht-card border border-tesht-border rounded-xl p-4 max-h-64 overflow-y-auto">
          <div className="text-xs font-bold text-tesht-muted mb-2">Demo Log</div>
          {stepLogs.map((log, i) => (
            <StepCard key={i} step={log} index={i} />
          ))}
        </div>
      )}

      {/* Results tabs — show after completion */}
      {isComplete && (
        <div>
          {/* Tab bar */}
          <div className="flex gap-1 flex-wrap mb-4 border-b border-tesht-border pb-2">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-t text-xs font-mono transition-colors
                  ${currentTab === tab.id
                    ? 'bg-tesht-teal text-white'
                    : 'text-tesht-muted hover:text-slate-200 hover:bg-tesht-card'}`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div>
            {currentTab === 'delegation' && (
              <DelegationTree
                delegationChain={act1.delegationChain}
                delegatorClaims={act1.claims}
                agentDid={act1.agentDid}
              />
            )}
            {currentTab === 'vp' && <VPViewer vpToken={act2.blendedVP} />}
            {currentTab === 'isolation' && (
              <IsolationView vpToken={act2.blendedVP} serverEntry={serverEntry} />
            )}
            {currentTab === 'trust' && <TrustTimeline trustHistory={act4.trustHistory} />}
            {currentTab === 'detection' && (
              <DetectionPanel
                alerts={act9.alerts || act5.detections?.alerts || []}
                fleet={act9.fleet   || act5.detections?.fleet  || {}}
                inventory={act9.inventory || {}}
                shadowResults={act5.shadowResults || []}
              />
            )}
            {currentTab === 'multihop' && (
              <MultiHopView
                chain={act6.chain || []}
                inScopeResult={act6.inScopeResult}
                outOfScopeResult={act6.outOfScopeResult}
              />
            )}
            {currentTab === 'revocation' && (
              <RevocationView
                preRevocation={act7.preRevocation || []}
                credentialId={act7.credentialId}
                postRevocation={act7.postRevocation || []}
                revokedAt={act7.revokedAt}
              />
            )}
            {currentTab === 'audit' && (
              <AuditTrail
                events={act8.events || act9.auditEvents || []}
                chainVerify={act8.chainVerify || act9.chainVerify}
                exportCsvUrl={act8.exportCsvUrl}
                exportJsonUrl={act8.exportJsonUrl}
                initialAgentDid={act8.agentDid || ''}
                initialFromTs={act8.fromTs || ''}
                initialToTs={act8.toTs || ''}
              />
            )}
            {currentTab === 'fleet' && (
              <DetectionPanel
                alerts={act9.alerts || []}
                fleet={act9.fleet   || {}}
                inventory={act9.inventory || {}}
                shadowResults={act5.shadowResults || []}
              />
            )}
          </div>
        </div>
      )}
    </div>
  )
}
