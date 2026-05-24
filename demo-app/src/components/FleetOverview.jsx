/**
 * FleetOverview
 * ─────────────
 * Always-visible live dashboard panel rendered above the demo runner.
 * Auto-refreshes every 5 seconds via useFleetOverview.
 *
 * Sections:
 *  1. Fleet stats bar — Total Agents, Verified, Shadow Attempts, Avg Trust
 *  2. Hash chain badge — N events, chain status
 *  3. Active alerts    — CRITICAL (red) / WARNING (amber), top 6
 *  4. Recent events    — compact 20-row table with decision badges
 */
import { useState } from 'react'
import { StatusBadge } from './StatusBadge.jsx'

// ── Helpers ────────────────────────────────────────────────────────────────────

function shortDid(did) {
  if (!did || typeof did !== 'string') return '—'
  if (did.length <= 24) return did
  return did.slice(0, 14) + '…' + did.slice(-8)
}

function fmtTime(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(typeof ts === 'number' && ts < 1e12 ? ts * 1000 : ts)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return String(ts).slice(0, 8) }
}

function trustColor(score) {
  if (score === null || score === undefined) return 'text-slate-500'
  if (score >= 75) return 'text-emerald-400'
  if (score >= 50) return 'text-yellow-400'
  return 'text-red-400'
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent = false }) {
  return (
    <div className={`flex flex-col gap-1 px-4 py-3 rounded-xl border
      ${accent
        ? 'bg-pramana-teal/10 border-pramana-teal/40'
        : 'bg-pramana-card border-pramana-border'}`}>
      <div className="text-xs text-pramana-muted">{label}</div>
      <div className={`text-xl font-bold ${accent ? 'text-pramana-teal' : 'text-slate-100'}`}>
        {value ?? '—'}
      </div>
      {sub && <div className="text-xs text-pramana-muted">{sub}</div>}
    </div>
  )
}

function ChainBadge({ chainVerify }) {
  if (!chainVerify) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-pramana-border text-xs text-pramana-muted">
        <span>🔒</span>
        <span>Hash chain — waiting for events…</span>
      </div>
    )
  }

  const storage = chainVerify.storage || 'in-memory'
  const count   = chainVerify.in_memory_count ?? chainVerify.events_checked ?? 0

  if (storage === 'postgresql') {
    const valid = chainVerify.valid
    return (
      <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono
        ${valid
          ? 'bg-emerald-900/20 border-emerald-700 text-emerald-300'
          : 'bg-red-900/20 border-red-700 text-red-300'}`}>
        <span>{valid ? '🔒' : '⚠'}</span>
        <span>SHA-256 chain</span>
        <span className="opacity-40">|</span>
        <span>{count} events</span>
        <span className="opacity-40">|</span>
        <span>PostgreSQL</span>
        <span className="opacity-40">|</span>
        <strong>{valid ? 'VALID ✓' : 'BROKEN ✗'}</strong>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-pramana-border text-xs font-mono text-pramana-muted">
      <span>🔒</span>
      <span>Hash chain (in-memory)</span>
      <span className="opacity-40">|</span>
      <span>{count} events tracked</span>
    </div>
  )
}

function AlertRow({ alert }) {
  const sev = (alert.severity || 'warning').toLowerCase()
  const isCritical = sev === 'critical'
  return (
    <div className={`flex items-start gap-2 px-3 py-2 rounded-lg text-xs
      ${isCritical
        ? 'bg-red-900/20 border border-red-800/50'
        : 'bg-yellow-900/15 border border-yellow-800/40'}`}>
      <span className="mt-0.5 shrink-0">{isCritical ? '🔴' : '🟡'}</span>
      <div className="flex-1 min-w-0">
        <div className={`font-semibold ${isCritical ? 'text-red-300' : 'text-yellow-300'}`}>
          {alert.title || 'Alert'}
        </div>
        {alert.description && (
          <div className="text-slate-400 truncate">{alert.description.slice(0, 80)}</div>
        )}
      </div>
      <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase
        ${isCritical ? 'bg-red-900 text-red-300' : 'bg-yellow-900 text-yellow-300'}`}>
        {sev}
      </span>
    </div>
  )
}

function EventRow({ event, idx }) {
  const agentLabel = event.agent_name
    || event.agent_label
    || shortDid(event.agent_did)

  const tool = event.tool_name
    || event.tool_called
    || event.tool
    || event.resource_path
    || '—'

  const trust = event.trust_score ?? event.score ?? null

  return (
    <tr className={`border-b border-pramana-border/40 ${idx % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
      <td className="px-2 py-1.5 text-[10px] text-pramana-muted font-mono whitespace-nowrap">
        {fmtTime(event.timestamp || event.created_at)}
      </td>
      <td className="px-2 py-1.5 text-xs text-slate-300 max-w-[140px] truncate" title={event.agent_did}>
        {agentLabel}
      </td>
      <td className="px-2 py-1.5 text-xs font-mono text-pramana-teal/80 max-w-[120px] truncate">
        {tool}
      </td>
      <td className={`px-2 py-1.5 text-xs font-mono text-right ${trustColor(trust)}`}>
        {trust !== null ? Math.round(trust) : '—'}
      </td>
      <td className="px-2 py-1.5">
        <StatusBadge decision={event.decision} />
      </td>
    </tr>
  )
}

// ── Main component ──────────────────────────────────────────────────────────────

export function FleetOverview({ events = [], detections = {}, chainVerify, inventory = {}, loading, lastUpdated }) {
  const [collapsed, setCollapsed] = useState(false)

  const alerts    = detections.alerts  || []
  const fleet     = detections.fleet   || {}

  // known_agents is a list from the gateway; shadow_attempts is also a list
  const knownAgentsList   = Array.isArray(inventory.known_agents) ? inventory.known_agents : []
  const shadowAttemptList = Array.isArray(inventory.shadow_attempts) ? inventory.shadow_attempts : []

  const totalAgents   = typeof inventory.total_agents === 'number'
    ? inventory.total_agents
    : knownAgentsList.length || fleet.total_agents || 0

  const verifiedCount = typeof inventory.verified_agents === 'number'
    ? inventory.verified_agents
    : typeof inventory.healthy_agents === 'number'
      ? inventory.healthy_agents
      : fleet.verified_agents ?? 0

  const shadowCount   = typeof inventory.shadow_attempts === 'number'
    ? inventory.shadow_attempts
    : shadowAttemptList.length || fleet.shadow_attempts || 0

  const avgTrust      = inventory.avg_trust_score ?? inventory.avg_trust ?? fleet.avg_trust ?? null

  const critCount = alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length
  const warnCount = alerts.filter(a => (a.severity || '').toLowerCase() !== 'critical').length

  const noData = events.length === 0 && alerts.length === 0 && totalAgents === 0

  const lastUpdStr = lastUpdated
    ? lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : null

  return (
    <div className="mb-6 rounded-xl border border-pramana-border bg-pramana-card/60">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-pramana-border">
        <div className="flex items-center gap-3">
          <span className="text-sm font-bold text-slate-200">Fleet Overview</span>
          {loading && (
            <span className="text-xs text-pramana-muted animate-pulse">Fetching…</span>
          )}
          {!loading && lastUpdStr && (
            <span className="text-[10px] text-pramana-muted">Updated {lastUpdStr}</span>
          )}
          {critCount > 0 && (
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-900 text-red-300 border border-red-700">
              {critCount} CRITICAL
            </span>
          )}
        </div>
        <button
          onClick={() => setCollapsed(c => !c)}
          className="text-xs text-pramana-muted hover:text-slate-300 transition-colors px-2 py-1"
        >
          {collapsed ? 'Expand ▾' : 'Collapse ▴'}
        </button>
      </div>

      {!collapsed && (
        <div className="p-4 space-y-4">
          {/* No data state */}
          {noData && !loading && (
            <div className="text-center py-6 text-pramana-muted text-sm">
              <div className="text-2xl mb-2">📊</div>
              <div>No events yet.</div>
              <div className="text-xs mt-1">
                Run the preload script or click "Run Demo" to populate the fleet.
              </div>
              <code className="text-xs bg-pramana-dark px-2 py-0.5 rounded mt-2 inline-block font-mono">
                PYTHONPATH=".:sdk/python" python3 scripts/demo_preload.py
              </code>
            </div>
          )}

          {/* Stats bar */}
          {!noData && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <StatCard
                label="Total Agents Seen"
                value={totalAgents || events.length > 0 ? (totalAgents || '…') : '0'}
                accent
              />
              <StatCard
                label="Verified Agents"
                value={verifiedCount}
                sub={totalAgents > 0 ? `${Math.round(verifiedCount / totalAgents * 100)}% of fleet` : undefined}
              />
              <StatCard
                label="Shadow Attempts"
                value={shadowCount}
                sub={shadowCount > 0 ? 'unauthorized probes' : 'none detected'}
              />
              <StatCard
                label="Avg Trust Score"
                value={avgTrust !== null ? Math.round(avgTrust) : (events.length > 0 ? '…' : '—')}
                sub="0–100 dynamic"
                accent={avgTrust !== null && avgTrust >= 70}
              />
            </div>
          )}

          {/* Hash chain */}
          {!noData && <ChainBadge chainVerify={chainVerify} />}

          {/* Alerts panel */}
          {alerts.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-400 mb-2">
                Active Alerts — {alerts.length} total
                {critCount > 0 && <span className="ml-2 text-red-400">({critCount} critical)</span>}
                {warnCount > 0 && <span className="ml-2 text-yellow-400">({warnCount} warning)</span>}
              </div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {/* Critical first */}
                {[...alerts]
                  .sort((a, b) => {
                    const order = { critical: 0, warning: 1 }
                    return (order[(a.severity || '').toLowerCase()] ?? 2) -
                           (order[(b.severity || '').toLowerCase()] ?? 2)
                  })
                  .slice(0, 8)
                  .map((a, i) => <AlertRow key={i} alert={a} />)
                }
              </div>
            </div>
          )}

          {/* Recent events table */}
          {events.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-400 mb-2">
                Recent Events — {events.length} loaded (most recent 20 shown)
              </div>
              <div className="overflow-x-auto rounded-lg border border-pramana-border">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-pramana-border bg-pramana-dark/60">
                      <th className="px-2 py-1.5 text-left text-[10px] text-pramana-muted font-semibold">Time</th>
                      <th className="px-2 py-1.5 text-left text-[10px] text-pramana-muted font-semibold">Agent</th>
                      <th className="px-2 py-1.5 text-left text-[10px] text-pramana-muted font-semibold">Tool</th>
                      <th className="px-2 py-1.5 text-right text-[10px] text-pramana-muted font-semibold">Trust</th>
                      <th className="px-2 py-1.5 text-left text-[10px] text-pramana-muted font-semibold">Decision</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(0, 20).map((e, i) => (
                      <EventRow key={e.event_id || e.id || i} event={e} idx={i} />
                    ))}
                  </tbody>
                </table>
              </div>
              {events.length > 20 && (
                <div className="text-[10px] text-pramana-muted mt-1 text-right">
                  Showing 20 of {events.length} — see Audit Trail tab for full history
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
