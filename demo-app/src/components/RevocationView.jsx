import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer,
} from 'recharts'
import { StatusBadge } from './StatusBadge.jsx'

function RequestRow({ req, idx, phase }) {
  const isBlocked = req.decision && req.decision.startsWith('blocked')
  return (
    <tr className="border-b border-tesht-border/50">
      <td className="py-2 pr-3 text-tesht-muted text-xs font-mono">{idx}</td>
      <td className="py-2 pr-3 text-slate-200 text-xs font-mono">{req.tool}</td>
      <td className="py-2 pr-3"><StatusBadge decision={req.decision} /></td>
      <td className="py-2 pr-3 text-xs font-mono">
        {typeof req.trustScore !== 'undefined' ? (
          <span className={req.trustScore >= 75 ? 'text-emerald-400' : req.trustScore >= 50 ? 'text-yellow-400' : 'text-red-400'}>
            {req.trustScore}
          </span>
        ) : '—'}
      </td>
      {isBlocked && req.reason && (
        <td className="py-2 text-xs text-red-400 max-w-[200px] truncate">{req.reason}</td>
      )}
    </tr>
  )
}

export function RevocationView({ preRevocation = [], credentialId, postRevocation = [], revokedAt }) {
  const hasData = preRevocation.length > 0 || postRevocation.length > 0

  if (!hasData) {
    return <div className="text-tesht-muted text-sm">No revocation data yet.</div>
  }

  // Build chart data — pre + revocation marker + post
  const chartData = [
    ...preRevocation.map((r, i) => ({
      idx: i + 1,
      label: `pre-${i + 1}`,
      score: typeof r.trustScore === 'number' ? r.trustScore : parseInt(r.trustScore) || 80,
      decision: r.decision,
      phase: 'pre',
    })),
    ...postRevocation.map((r, i) => ({
      idx: preRevocation.length + i + 2,
      label: `post-${i + 1}`,
      score: 0,
      decision: r.decision || 'blocked_auth',
      phase: 'post',
    })),
  ]

  const revocationIdx = preRevocation.length + 1
  const revokedTime   = revokedAt ? new Date(revokedAt).toLocaleTimeString() : null

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null
    const d = payload[0].payload
    return (
      <div className="bg-tesht-card border border-tesht-border rounded p-2 text-xs font-mono">
        <div className="font-bold mb-1">{d.label}</div>
        <div>Phase: <span className={d.phase === 'pre' ? 'text-emerald-400' : 'text-red-400'}>{d.phase}</span></div>
        <div>Score: <span className="text-tesht-teal">{d.score}</span></div>
        <div>Decision: <StatusBadge decision={d.decision} /></div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Trust chart with revocation reference line */}
      <div className="bg-tesht-card border border-tesht-border rounded-xl p-4">
        <h3 className="text-sm font-bold text-tesht-teal mb-4">Trust Score — Revocation Boundary</h3>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={chartData} margin={{ top: 10, right: 20, bottom: 5, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#64748B' }} />
            <YAxis domain={[0, 105]} tick={{ fontSize: 10, fill: '#64748B' }} />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={75} stroke="#10B981" strokeDasharray="4 4"
              label={{ value: 'Allow ≥75', fill: '#10B981', fontSize: 9 }} />
            <ReferenceLine
              x={`post-1`}
              stroke="#EF4444"
              strokeDasharray="6 3"
              strokeWidth={2}
              label={{ value: 'REVOKED', fill: '#EF4444', fontSize: 10, position: 'top' }}
            />
            <Line
              type="monotone"
              dataKey="score"
              stroke="#0D9488"
              strokeWidth={2}
              dot={(props) => {
                const { cx, cy, payload } = props
                const color = payload.phase === 'pre' ? '#10B981' : '#EF4444'
                return <circle key={props.key} cx={cx} cy={cy} r={5} fill={color} stroke="none" />
              }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Pre-revocation table */}
      <div className="bg-emerald-900/10 border border-emerald-700/40 rounded-xl p-4">
        <h3 className="text-sm font-bold text-emerald-400 mb-3">
          ✅ Before Revocation — {preRevocation.length} request{preRevocation.length !== 1 ? 's' : ''} ALLOWED
        </h3>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-tesht-muted border-b border-tesht-border font-mono">
              <th className="text-left pb-2 pr-3">#</th>
              <th className="text-left pb-2 pr-3">Tool</th>
              <th className="text-left pb-2 pr-3">Decision</th>
              <th className="text-left pb-2">Trust</th>
            </tr>
          </thead>
          <tbody>
            {preRevocation.map((req, i) => (
              <RequestRow key={i} req={req} idx={i + 1} phase="pre" />
            ))}
          </tbody>
        </table>
      </div>

      {/* Revocation event banner */}
      <div className="bg-red-900/30 border-2 border-red-600 rounded-xl p-5 text-center">
        <div className="text-2xl mb-2">⚠</div>
        <div className="text-lg font-bold text-red-300 mb-1">CREDENTIAL REVOKED</div>
        <div className="text-xs text-red-400 mb-3">Security team revoked the delegation credential — one API call</div>
        {credentialId && (
          <div className="text-xs font-mono text-tesht-muted bg-tesht-dark rounded px-3 py-1 inline-block">
            jti: {credentialId.slice(0, 36)}…
          </div>
        )}
        {revokedTime && (
          <div className="text-xs text-tesht-muted mt-2">Revoked at {revokedTime}</div>
        )}
        <div className="mt-3 text-xs text-red-300">
          Enforcement: <strong>instant</strong> — gateway checks BitstringStatusList on next request
        </div>
      </div>

      {/* Post-revocation table */}
      <div className="bg-red-900/10 border border-red-700/40 rounded-xl p-4">
        <h3 className="text-sm font-bold text-red-400 mb-3">
          🚫 After Revocation — {postRevocation.length} request{postRevocation.length !== 1 ? 's' : ''} BLOCKED
        </h3>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-tesht-muted border-b border-tesht-border font-mono">
              <th className="text-left pb-2 pr-3">#</th>
              <th className="text-left pb-2 pr-3">Tool</th>
              <th className="text-left pb-2 pr-3">Decision</th>
              <th className="text-left pb-2 pr-3">Trust</th>
              <th className="text-left pb-2">Reason</th>
            </tr>
          </thead>
          <tbody>
            {postRevocation.map((req, i) => (
              <RequestRow key={i} req={req} idx={i + 1} phase="post" />
            ))}
          </tbody>
        </table>
      </div>

      {/* Summary */}
      <div className="bg-tesht-card border border-tesht-border rounded-xl p-4">
        <h3 className="text-sm font-bold text-slate-400 mb-2">How it works</h3>
        <div className="text-xs text-tesht-muted space-y-1">
          <p>1. The delegation VC was issued with a <strong className="text-slate-200">BitstringStatusListEntry</strong> pointing to the bridge's status list.</p>
          <p>2. On revocation, <strong className="text-red-300">one bit was flipped</strong> in the bridge's in-memory bitstring — no TTL expiry required.</p>
          <p>3. On the next request, the gateway fetched the status list and found the bit set → <strong className="text-red-300">VP verification failed: revoked</strong>.</p>
          <p>4. No re-auth, no token invalidation, no cache flush needed. <strong className="text-slate-200">Instant.</strong></p>
        </div>
      </div>
    </div>
  )
}
