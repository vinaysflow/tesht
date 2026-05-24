export function StatusBadge({ decision, size = 'sm' }) {
  const d = (decision || '').toLowerCase()
  const base = size === 'sm' ? 'px-2 py-0.5 text-xs font-bold rounded' : 'px-3 py-1 text-sm font-bold rounded-md'

  if (d === 'allowed' || d === 'allow')
    return <span className={`${base} bg-emerald-900 text-emerald-300 border border-emerald-700`}>ALLOW</span>
  if (d === 'step_up')
    return <span className={`${base} bg-yellow-900 text-yellow-300 border border-yellow-700`}>STEP-UP</span>
  if (d === 'blocked_scope')
    return <span className={`${base} bg-red-900 text-red-300 border border-red-700`}>SCOPE BLOCKED</span>
  if (d === 'blocked_trust')
    return <span className={`${base} bg-red-900 text-red-300 border border-red-700`}>TRUST BLOCKED</span>
  if (d === 'blocked_auth')
    return <span className={`${base} bg-red-900 text-red-300 border border-red-700`}>AUTH BLOCKED</span>
  if (d.startsWith('block'))
    return <span className={`${base} bg-red-900 text-red-300 border border-red-700`}>BLOCKED</span>
  return <span className={`${base} bg-slate-800 text-slate-300 border border-slate-600`}>{decision || '—'}</span>
}
