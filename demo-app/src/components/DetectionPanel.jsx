import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis } from 'recharts'

const SEV_COLORS = {
  critical: '#EF4444',
  high:     '#F97316',
  warning:  '#F59E0B',
  low:      '#64748B',
}

function SeverityBadge({ severity }) {
  const sev = (severity || 'warning').toLowerCase()
  const color = SEV_COLORS[sev] || SEV_COLORS.warning
  return (
    <span
      className="text-xs font-bold px-2 py-0.5 rounded border"
      style={{ borderColor: color + '66', color }}
    >
      {sev.toUpperCase()}
    </span>
  )
}

function AlertCard({ alert }) {
  const sev = alert.severity || 'warning'
  const color = SEV_COLORS[sev] || SEV_COLORS.warning
  return (
    <div className="border rounded-xl p-4 mb-3" style={{ borderColor: color + '66' }}>
      <div className="flex items-start gap-2 mb-1">
        <span className="text-lg">{sev === 'critical' ? '🚨' : '⚠️'}</span>
        <div>
          <div className="font-bold text-slate-100 text-sm">{alert.title || alert.type}</div>
          <div className="text-xs mt-0.5" style={{ color }}>{sev.toUpperCase()}</div>
        </div>
      </div>
      {alert.description && (
        <p className="text-xs text-pramana-muted mt-2">{alert.description}</p>
      )}
      {alert.evidence && (
        <div className="mt-2 space-y-0.5 text-xs font-mono text-pramana-muted">
          {Object.entries(alert.evidence).slice(0, 4).map(([k, v]) => (
            <div key={k}><span className="text-slate-400">{k}:</span> {String(v).slice(0, 60)}</div>
          ))}
        </div>
      )}
      {alert.action && (
        <div className="mt-2 text-xs text-pramana-teal">→ Recommended: {alert.action}</div>
      )}
    </div>
  )
}

/** Derive per-category counts from detection alerts or shadow results. */
function parseShadowCategories(alerts, shadowResults) {
  // Try to extract from API alerts first (most accurate)
  const cats = { no_creds: 0, expired_vp: 0, no_delegation: 0 }
  let catSeverity = { no_creds: 'warning', expired_vp: 'warning', no_delegation: 'warning' }

  if (alerts && alerts.length > 0) {
    for (const a of alerts) {
      if (a.type !== 'shadow_agent') continue
      const title = (a.title || '').toLowerCase()
      const count = a.evidence?.attempt_count || 1
      const sev   = a.severity || 'warning'
      if (title.includes('no credentials') || title.includes('missing')) {
        cats.no_creds += count
        catSeverity.no_creds = sev
      } else if (title.includes('expired')) {
        cats.expired_vp += count
        catSeverity.expired_vp = sev
      } else if (title.includes('delegation') || title.includes('invalid')) {
        cats.no_delegation += count
        catSeverity.no_delegation = sev
      }
    }
  }

  // Fall back to shadow results from the hook if no categorised alerts yet
  if (shadowResults && shadowResults.length > 0 && cats.no_creds + cats.expired_vp + cats.no_delegation === 0) {
    for (const sr of shadowResults) {
      if (sr.phase === 'no_creds')     cats.no_creds++
      if (sr.phase === 'expired_vp')   cats.expired_vp++
      if (sr.phase === 'no_delegation') cats.no_delegation++
    }
  }

  return { cats, catSeverity }
}

/** Extract fleet correlation detail from fleet_threat alerts. */
function parseFleetCorrelation(alerts) {
  const fleetAlerts = (alerts || []).filter(a => a.type === 'fleet_threat')
  if (!fleetAlerts.length) return null

  const swarm = fleetAlerts.find(a =>
    (a.title || '').toLowerCase().includes('swarm') ||
    (a.description || '').toLowerCase().includes('attempt')
  )
  const coordination = fleetAlerts.find(a =>
    (a.title || '').toLowerCase().includes('coordinated') ||
    (a.description || '').toLowerCase().includes('scope')
  )

  const details = []
  if (swarm) {
    const servers = swarm.evidence?.servers_targeted || swarm.evidence?.server || null
    details.push({
      label: swarm.title || 'Shadow agent swarm',
      detail: servers ? `Targeted: ${String(servers)}` : swarm.description || '',
      severity: swarm.severity,
    })
  }
  if (coordination) {
    details.push({
      label: coordination.title || 'Coordinated scope probing',
      detail: coordination.description || '',
      severity: coordination.severity,
    })
  }
  // Any remaining fleet alerts
  for (const a of fleetAlerts) {
    if (a !== swarm && a !== coordination) {
      details.push({ label: a.title || a.type, detail: a.description || '', severity: a.severity })
    }
  }
  return details.length > 0 ? details : null
}

export function DetectionPanel({ alerts = [], fleet = {}, inventory = {}, shadowResults = [] }) {
  const shadowCount  = fleet.shadow_attempts ?? (inventory.shadow_attempts?.length ?? 0)
  const knownCount   = fleet.total_agents ?? (inventory.known_agents?.length ?? 0)
  const riskDist     = fleet.risk_distribution || {}

  const donutData = [
    { name: 'Verified', value: Math.max(0, knownCount)  },
    { name: 'Shadow',   value: Math.max(0, shadowCount) },
  ]
  const donutColors = ['#0D9488', '#EF4444']

  const barData = ['low', 'medium', 'high', 'critical'].map(k => ({
    name:  k.charAt(0).toUpperCase() + k.slice(1),
    value: riskDist[k] || 0,
  }))

  const { cats, catSeverity } = parseShadowCategories(alerts, shadowResults)
  const fleetCorrelation      = parseFleetCorrelation(alerts)
  const hasCategories         = cats.no_creds + cats.expired_vp + cats.no_delegation > 0

  const categoryDefs = [
    { key: 'no_creds',     label: 'No Credentials',     icon: '🚫', desc: 'Request with no Authorization header — complete unknown entity' },
    { key: 'expired_vp',   label: 'Expired VP',          icon: '⏱',  desc: 'Presented a VP-JWT that has passed its expiry time' },
    { key: 'no_delegation',label: 'Missing Delegation',  icon: '🔗', desc: 'VP has no DelegationCredential — no human authorized this agent' },
  ]

  return (
    <div className="space-y-4">
      {/* Metrics row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Known Agents',    val: knownCount,              color: 'text-pramana-teal' },
          { label: 'Shadow Attempts', val: shadowCount,             color: 'text-red-400' },
          { label: 'Alerts',          val: alerts.length,           color: 'text-yellow-400' },
          { label: 'Avg Trust',       val: `${Math.round(fleet.avg_trust || 0)}/100`, color: 'text-blue-400' },
        ].map(({ label, val, color }) => (
          <div key={label} className="bg-pramana-card border border-pramana-border rounded-xl p-3 text-center">
            <div className={`text-2xl font-bold font-mono ${color}`}>{val}</div>
            <div className="text-xs text-pramana-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Shadow attack category breakdown */}
      {hasCategories && (
        <div className="bg-pramana-card border border-red-800/40 rounded-xl p-4">
          <h3 className="text-sm font-bold text-red-400 mb-3">🚨 Shadow Attack Categories</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {categoryDefs.map(({ key, label, icon, desc }) => {
              const count = cats[key]
              const sev   = catSeverity[key]
              const color = SEV_COLORS[sev] || SEV_COLORS.warning
              return (
                <div
                  key={key}
                  className="rounded-lg p-3 border"
                  style={{ borderColor: color + '55', background: color + '11' }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-bold text-slate-100">{icon} {label}</span>
                    <SeverityBadge severity={sev} />
                  </div>
                  <div className="text-2xl font-mono font-bold mb-1" style={{ color }}>
                    {count} attempt{count !== 1 ? 's' : ''}
                  </div>
                  <div className="text-xs text-pramana-muted">{desc}</div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Fleet correlation highlight */}
      {fleetCorrelation && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-4">
          <h3 className="text-sm font-bold text-red-400 mb-2">⚡ Fleet Correlation Detected</h3>
          <div className="space-y-2">
            {fleetCorrelation.map((item, i) => (
              <div key={i} className="flex items-start gap-2">
                <SeverityBadge severity={item.severity} />
                <div>
                  <div className="text-sm font-bold text-slate-100">{item.label}</div>
                  {item.detail && <div className="text-xs text-pramana-muted mt-0.5">{item.detail}</div>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {(knownCount + shadowCount) > 0 && (
          <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
            <h3 className="text-sm font-bold text-slate-400 mb-3">Verified vs Shadow</h3>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={donutData} cx="50%" cy="50%" innerRadius={40} outerRadius={60} dataKey="value">
                  {donutData.map((_, i) => <Cell key={i} fill={donutColors[i]} />)}
                </Pie>
                <Tooltip formatter={(v, n) => [v, n]} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 text-xs">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-pramana-teal" />Verified</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-400" />Shadow</span>
            </div>
          </div>
        )}

        {barData.some(d => d.value > 0) && (
          <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
            <h3 className="text-sm font-bold text-slate-400 mb-3">Risk Distribution</h3>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={barData} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 10, fill: '#64748B' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#64748B' }} width={60} />
                <Bar dataKey="value" fill="#0D9488" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Alert list */}
      {alerts.length > 0 && (
        <div>
          <h3 className="text-sm font-bold text-slate-400 mb-3">Active Alerts ({alerts.length})</h3>
          {alerts.slice(0, 8).map((alert, i) => (
            <AlertCard key={i} alert={alert} />
          ))}
        </div>
      )}

      {alerts.length === 0 && !hasCategories && (
        <div className="bg-pramana-card border border-pramana-border rounded-xl p-4 text-center text-pramana-muted text-sm">
          No active alerts
        </div>
      )}
    </div>
  )
}
