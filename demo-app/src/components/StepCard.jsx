import { StatusBadge } from './StatusBadge.jsx'
import { fmtMs } from '../utils/format.js'

const ACT_LABELS = [
  '', 'Enterprise Identity', 'Blended Gateway', 'Scope Enforcement',
  'Continuous Trust', 'Shadow Attack', 'Multi-Hop Delegation',
  'Revocation', 'CISO Audit', 'Fleet Dashboard',
]

export function ProgressBar({ currentStep, totalSteps = 9 }) {
  return (
    <div className="flex items-center gap-1 flex-wrap mb-6">
      {Array.from({ length: totalSteps }, (_, i) => {
        const n = i + 1
        const done    = n < currentStep
        const active  = n === currentStep
        const pending = n > currentStep
        return (
          <div key={n} className="flex items-center">
            <div className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-mono
              ${done   ? 'bg-emerald-900 text-emerald-300' : ''}
              ${active ? 'bg-pramana-teal text-white animate-pulse' : ''}
              ${pending ? 'bg-pramana-card text-pramana-muted' : ''}`}>
              <span className="font-bold">{n}</span>
              <span className="hidden sm:inline">{ACT_LABELS[n]}</span>
              {done && <span>✓</span>}
            </div>
            {n < totalSteps && <div className="w-3 h-px bg-pramana-border mx-0.5" />}
          </div>
        )
      })}
    </div>
  )
}

export function StepCard({ step, index }) {
  const { text, ok } = step
  return (
    <div className={`flex items-start gap-2 py-1 text-sm font-mono
      ${ok === false ? 'text-red-400' : 'text-slate-300'}`}>
      <span className={`mt-0.5 ${ok === false ? 'text-red-400' : 'text-emerald-400'}`}>
        {ok === false ? '✗' : '›'}
      </span>
      <span>{text}</span>
    </div>
  )
}
