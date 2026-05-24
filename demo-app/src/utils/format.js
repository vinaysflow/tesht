/** Truncate a DID for display: did:key:zAbc...xyz */
export function shortDid(did, chars = 16) {
  if (!did || did.length <= chars + 12) return did || '—'
  return did.slice(0, chars) + '…' + did.slice(-6)
}

/** Format epoch seconds as human-readable relative time */
export function relTime(isoStr) {
  if (!isoStr || isoStr === '—') return '—'
  try {
    const ms = new Date(isoStr).getTime() - Date.now()
    const abs = Math.abs(ms)
    if (abs < 60000) return `${Math.round(abs / 1000)}s ${ms > 0 ? 'remaining' : 'ago'}`
    if (abs < 3600000) return `${Math.round(abs / 60000)}m ${ms > 0 ? 'remaining' : 'ago'}`
    return new Date(isoStr).toLocaleTimeString()
  } catch {
    return isoStr
  }
}

/** Format scope actions list for display */
export function formatScope(scope) {
  if (!scope) return '—'
  const actions = scope.actions || []
  const amount  = scope.max_amount
  const cur     = scope.currency || 'USD'
  let str = actions.slice(0, 4).join(', ')
  if (actions.length > 4) str += '…'
  if (amount) str += ` ≤ $${amount.toLocaleString()} ${cur}`
  return str || '—'
}

/** ms → human readable latency */
export function fmtMs(ms) {
  if (ms === undefined || ms === null) return '—'
  return `${Math.round(ms)}ms`
}

/** Decision string → color class */
export function decisionColor(decision) {
  if (!decision) return 'text-slate-400'
  const d = decision.toLowerCase()
  if (d === 'allowed' || d === 'allow') return 'text-emerald-400'
  if (d === 'step_up') return 'text-yellow-400'
  return 'text-red-400'
}

/** Credential type → Tailwind color class */
export function credTypeColor(type) {
  if (!type) return 'border-slate-600 text-slate-300'
  const t = type.toLowerCase()
  if (t.includes('delegation')) return 'border-blue-500 text-blue-300'
  if (t.includes('organizational') || t.includes('role') || t.includes('identity'))
    return 'border-emerald-500 text-emerald-300'
  if (t.includes('agent')) return 'border-purple-500 text-purple-300'
  return 'border-slate-500 text-slate-300'
}
