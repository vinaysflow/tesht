import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ReferenceDot, ResponsiveContainer, Legend,
} from 'recharts'
import { StatusBadge } from './StatusBadge.jsx'

function FactorRow({ label, val, max = 25, note }) {
  const pct = max > 0 ? Math.min(100, Math.round((val / max) * 100)) : 0
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-36 text-pramana-muted shrink-0">{label}</span>
      <div className="flex-1 bg-pramana-dark rounded-full h-1.5 max-w-[120px]">
        <div className="bg-pramana-teal h-1.5 rounded-full" style={{ width: `${pct}%` }} />
      </div>
      <span className="w-10 text-right font-mono text-slate-300">{val}/{max}</span>
      {note && <span className="text-pramana-muted">{note}</span>}
    </div>
  )
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="bg-pramana-card border border-pramana-border rounded p-2 text-xs font-mono">
      <div className="font-bold mb-1">{d.label}</div>
      <div>Score: <span className="text-pramana-teal">{d.score}</span></div>
      <div>Decision: <StatusBadge decision={d.decision} /></div>
      {d.penalty > 0 && <div className="text-red-400">Penalty: -{d.penalty}</div>}
    </div>
  )
}

export function TrustTimeline({ trustHistory }) {
  if (!trustHistory?.length) return <div className="text-pramana-muted text-sm">No trust history yet.</div>

  const data = trustHistory.map((e, i) => ({
    idx:      i + 1,
    label:    e.tool || `req-${i + 1}`,
    score:    typeof e.trustScore === 'number' ? e.trustScore : parseInt(e.trustScore) || 0,
    decision: e.decision,
    penalty:  e.factors?.behavioral_penalty || 0,
    reAuth:   e.reAuth,
  }))

  return (
    <div className="space-y-6">
      {/* Chart */}
      <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
        <h3 className="text-sm font-bold text-pramana-teal mb-4">Trust Score Over Session</h3>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data} margin={{ top: 10, right: 20, bottom: 5, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#64748B' }} interval={0} angle={-20} dy={8} />
            <YAxis domain={[0, 105]} tick={{ fontSize: 10, fill: '#64748B' }} />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={75} stroke="#10B981" strokeDasharray="4 4" label={{ value: 'Allow ≥75', fill: '#10B981', fontSize: 10 }} />
            <ReferenceLine y={50} stroke="#F59E0B" strokeDasharray="4 4" label={{ value: 'Step-up ≥50', fill: '#F59E0B', fontSize: 10 }} />
            <Line
              type="monotone" dataKey="score"
              stroke="#0D9488" strokeWidth={2}
              dot={(props) => {
                const { cx, cy, payload } = props
                const d = payload.decision?.toLowerCase()
                const color = d === 'allowed' || d === 'allow' ? '#10B981' :
                              d === 'step_up' ? '#F59E0B' : '#EF4444'
                return <circle key={props.key} cx={cx} cy={cy} r={5} fill={color} stroke="none" />
              }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Per-request factor table */}
      <div className="bg-pramana-card border border-pramana-border rounded-xl p-4 overflow-x-auto">
        <h3 className="text-sm font-bold text-slate-400 mb-3">Per-Request Breakdown</h3>
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-pramana-muted border-b border-pramana-border">
              <th className="text-left pb-2">#</th>
              <th className="text-left pb-2">Tool</th>
              <th className="text-left pb-2">Score</th>
              <th className="text-left pb-2">Decision</th>
              <th className="text-left pb-2">Penalty</th>
            </tr>
          </thead>
          <tbody>
            {trustHistory.map((e, i) => (
              <tr key={i} className="border-b border-pramana-border/50">
                <td className="py-1 text-pramana-muted">{i + 1}</td>
                <td className="py-1 text-slate-300">{e.tool || '—'}</td>
                <td className="py-1 text-pramana-teal font-bold">{e.trustScore}</td>
                <td className="py-1"><StatusBadge decision={e.decision} /></td>
                <td className="py-1 text-red-400">{e.factors?.behavioral_penalty ? `-${e.factors.behavioral_penalty}` : '0'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Factor breakdown for last event with data */}
      {(() => {
        const lastWithFactors = [...trustHistory].reverse().find(e => e.factors && Object.keys(e.factors).length > 0)
        if (!lastWithFactors?.factors) return null
        const f = lastWithFactors.factors
        return (
          <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
            <h3 className="text-sm font-bold text-slate-400 mb-3">Latest Factor Breakdown</h3>
            <div className="space-y-2">
              <FactorRow label="Credential Validity" val={f.credential_validity ?? 25} note="(VCs valid)" />
              <FactorRow label="Delegation Depth"    val={f.delegation_depth    ?? 20} note="(shallow chain)" />
              <FactorRow label="Issuer Reputation"   val={f.issuer_reputation   ?? 20} note="(blended VP)" />
              <FactorRow label="Agent History"        val={f.agent_history       ?? 15} />
              <div className="border-t border-pramana-border my-2" />
              {(f.behavioral_penalty > 0) && (
                <>
                  <FactorRow label="Tool Pattern Penalty" val={-(f.tool_pattern_penalty ?? 0)} max={15} />
                  <FactorRow label="Velocity Penalty"     val={-(f.velocity_penalty     ?? 0)} max={20} />
                  <FactorRow label="Scope Probe Penalty"  val={-(f.scope_probe_penalty  ?? 0)} max={25} />
                </>
              )}
            </div>
          </div>
        )
      })()}
    </div>
  )
}
