import { useState } from 'react'
import { StatusBadge } from './StatusBadge.jsx'
import { shortDid, fmtMs, formatScope } from '../utils/format.js'

// ── Hash chain verification badge ─────────────────────────────────────────────

function ChainBadge({ chainVerify }) {
  if (!chainVerify) return null

  const storage = chainVerify.storage || 'unknown'
  const count   = chainVerify.in_memory_count ?? chainVerify.events_checked ?? 0

  if (storage === 'postgresql') {
    const valid = chainVerify.valid
    return (
      <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-mono
        ${valid
          ? 'bg-emerald-900/20 border-emerald-700 text-emerald-300'
          : 'bg-red-900/20 border-red-700 text-red-300'}`}>
        <span>{valid ? '🔒' : '⚠'}</span>
        <span>SHA-256 hash chain</span>
        <span className="text-pramana-muted">|</span>
        <span>{count} events</span>
        <span className="text-pramana-muted">|</span>
        <span>PostgreSQL</span>
        <span className="text-pramana-muted">|</span>
        <strong>{valid ? 'VALID' : 'BROKEN'}</strong>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-pramana-border text-xs font-mono text-pramana-muted">
      <span>🔒</span>
      <span>Hash chain</span>
      <span className="text-pramana-muted">|</span>
      <span>{count} events (in-memory)</span>
      <span className="text-pramana-muted">|</span>
      <span>Start PostgreSQL for persistent SHA-256 chain</span>
    </div>
  )
}

// ── Expanded detail row ────────────────────────────────────────────────────────

function ExpandedDetail({ event }) {
  const dc = event.delegator_claims || {}
  const scope = event.effective_scope
  const chainDids = event.delegation_chain_dids
  const depth = event.delegation_depth
  const reason = event.scope_reason || event.auth_reason

  return (
    <tr className="bg-pramana-dark">
      <td colSpan={9} className="px-4 py-3 text-xs font-mono text-pramana-muted border-b border-pramana-border">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5">
          {/* Identity */}
          <div className="col-span-1 sm:col-span-2">
            <span className="text-slate-400 font-bold">— Identity —</span>
          </div>
          <div><span className="text-slate-400">agent_did:</span> {shortDid(event.agent_did, 28) || '—'}</div>
          <div><span className="text-slate-400">agent_name:</span> {event.agent_name || '—'}</div>
          <div><span className="text-slate-400">delegator_did:</span> {shortDid(event.delegator_did, 28) || '—'}</div>
          <div><span className="text-slate-400">delegator_name:</span> <span className="text-slate-200">{dc.name || '—'}</span></div>
          {dc.email        && <div><span className="text-slate-400">delegator_email:</span> <span className="text-pramana-teal">{dc.email}</span></div>}
          {dc.organization && <div><span className="text-slate-400">delegator_org:</span> {dc.organization}</div>}
          {dc.role         && <div><span className="text-slate-400">delegator_role:</span> {dc.role}</div>}

          {/* Authorization context */}
          {(depth !== undefined && depth !== null) && (
            <>
              <div className="col-span-1 sm:col-span-2 mt-1">
                <span className="text-slate-400 font-bold">— Delegation Chain —</span>
              </div>
              <div><span className="text-slate-400">delegation_depth:</span> <span className="text-amber-300">{depth} hop{depth !== 1 ? 's' : ''}</span></div>
              {chainDids && chainDids.length > 0 && (
                <div className="col-span-1 sm:col-span-2">
                  <span className="text-slate-400">chain_dids:</span>{' '}
                  <span className="text-pramana-muted">{chainDids.map(d => shortDid(d, 12)).join(' → ')}</span>
                </div>
              )}
            </>
          )}

          {/* Scope */}
          {scope && (
            <>
              <div className="col-span-1 sm:col-span-2 mt-1">
                <span className="text-slate-400 font-bold">— Scope —</span>
              </div>
              <div><span className="text-slate-400">effective_scope:</span> {formatScope(scope)}</div>
              <div><span className="text-slate-400">scope_allowed:</span> <span className={event.scope_allowed ? 'text-emerald-400' : 'text-red-400'}>{String(event.scope_allowed)}</span></div>
            </>
          )}

          {/* Decision explanation */}
          {reason && (
            <>
              <div className="col-span-1 sm:col-span-2 mt-1">
                <span className="text-slate-400 font-bold">— Decision Reason —</span>
              </div>
              <div className="col-span-1 sm:col-span-2 text-amber-300 break-all">{reason}</div>
            </>
          )}

          {/* Trust factors */}
          {event.trust_factors && Object.keys(event.trust_factors).length > 0 && (
            <>
              <div className="col-span-1 sm:col-span-2 mt-1">
                <span className="text-slate-400 font-bold">— Trust Factors —</span>
              </div>
              {Object.entries(event.trust_factors).map(([k, v]) => (
                <div key={k}><span className="text-slate-400">{k}:</span> {String(v)}</div>
              ))}
            </>
          )}

          {/* Latency breakdown */}
          <div className="col-span-1 sm:col-span-2 mt-1">
            <span className="text-slate-400 font-bold">— Latency —</span>
          </div>
          <div><span className="text-slate-400">auth_latency:</span> <span className="text-blue-300">{fmtMs(event.auth_latency_ms)}</span></div>
          <div><span className="text-slate-400">proxy_latency:</span> <span className="text-blue-300">{fmtMs(event.proxy_latency_ms)}</span></div>
          <div><span className="text-slate-400">total_latency:</span> <span className="text-blue-300">{fmtMs(event.total_latency_ms)}</span></div>

          {/* Metadata */}
          <div className="col-span-1 sm:col-span-2 mt-1">
            <span className="text-slate-400 font-bold">— Metadata —</span>
          </div>
          <div><span className="text-slate-400">request_id:</span> {event.request_id || '—'}</div>
          <div><span className="text-slate-400">server:</span> {event.server_name || '—'}</div>
          <div><span className="text-slate-400">blended:</span> {String(event.blended)}</div>
        </div>
      </td>
    </tr>
  )
}

// ── Event row ─────────────────────────────────────────────────────────────────

function EventRow({ event, idx }) {
  const [expanded, setExpanded] = useState(false)
  const dc = event.delegator_claims || {}

  return (
    <>
      <tr
        className="border-b border-pramana-border/50 hover:bg-pramana-card/50 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        title="Click to expand full event detail"
      >
        <td className="py-2 pr-2 text-pramana-muted">{idx}</td>
        <td className="py-2 pr-3 text-pramana-muted text-xs font-mono">
          {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '—'}
        </td>
        <td className="py-2 pr-3 text-slate-300 font-mono text-xs">
          {event.agent_name || shortDid(event.agent_did, 10) || '[shadow]'}
        </td>
        <td className="py-2 pr-3 text-slate-300 text-xs">
          {dc.name || '—'}
        </td>
        <td className="py-2 pr-3 text-slate-200 font-mono text-xs max-w-[120px] truncate">
          {event.tool_name || '—'}
        </td>
        <td className="py-2 pr-3"><StatusBadge decision={event.decision} /></td>
        <td className="py-2 pr-3 font-mono text-xs">
          <span className={
            event.trust_score >= 75 ? 'text-emerald-400' :
            event.trust_score >= 50 ? 'text-yellow-400' : 'text-red-400'
          }>
            {event.trust_score ?? '—'}
          </span>
        </td>
        <td className="py-2 pr-3 text-blue-300 text-xs font-mono">{fmtMs(event.auth_latency_ms)}</td>
        <td className="py-2 text-pramana-muted text-xs font-mono">{fmtMs(event.total_latency_ms)}</td>
      </tr>
      {expanded && <ExpandedDetail event={event} />}
    </>
  )
}

// ── Filter bar ────────────────────────────────────────────────────────────────

function FilterBar({ agentDid, fromTs, toTs, onAgentDidChange, onFromTsChange, onToTsChange, onFilter }) {
  // Convert ISO strings to datetime-local format (remove trailing Z and fractional seconds)
  function toLocalInput(iso) {
    if (!iso) return ''
    return iso.slice(0, 16)
  }

  function fromLocalInput(val) {
    if (!val) return ''
    return new Date(val).toISOString()
  }

  return (
    <div className="bg-pramana-card border border-pramana-border rounded-xl p-4 space-y-3">
      <div className="text-xs font-bold text-slate-400 mb-1">Filter Audit Events</div>
      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-pramana-muted">Agent DID</label>
          <input
            type="text"
            value={agentDid}
            onChange={e => onAgentDidChange(e.target.value)}
            placeholder="did:key:z6Mk…"
            className="bg-pramana-dark border border-pramana-border rounded px-2 py-1 text-xs font-mono text-slate-200 w-56 focus:outline-none focus:border-pramana-teal"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-pramana-muted">From</label>
          <input
            type="datetime-local"
            value={toLocalInput(fromTs)}
            onChange={e => onFromTsChange(fromLocalInput(e.target.value))}
            className="bg-pramana-dark border border-pramana-border rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-pramana-teal"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-pramana-muted">To</label>
          <input
            type="datetime-local"
            value={toLocalInput(toTs)}
            onChange={e => onToTsChange(fromLocalInput(e.target.value))}
            className="bg-pramana-dark border border-pramana-border rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-pramana-teal"
          />
        </div>
        <button
          onClick={onFilter}
          className="px-4 py-1.5 bg-pramana-teal rounded text-white text-xs font-bold hover:bg-teal-600 transition-colors"
        >
          Filter
        </button>
      </div>
    </div>
  )
}

// ── Export buttons ─────────────────────────────────────────────────────────────

function ExportButtons({ csvUrl, jsonUrl }) {
  if (!csvUrl && !jsonUrl) return null
  return (
    <div className="flex gap-2">
      {csvUrl && (
        <a
          href={csvUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="px-3 py-1.5 border border-pramana-teal text-pramana-teal rounded text-xs font-bold hover:bg-pramana-teal/10 transition-colors"
        >
          ↓ Export CSV
        </a>
      )}
      {jsonUrl && (
        <a
          href={jsonUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="px-3 py-1.5 border border-pramana-border text-slate-300 rounded text-xs font-bold hover:bg-pramana-card transition-colors"
        >
          ↓ Export JSON
        </a>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export function AuditTrail({
  events = [],
  chainVerify,
  exportCsvUrl,
  exportJsonUrl,
  initialAgentDid  = '',
  initialFromTs    = '',
  initialToTs      = '',
  onFilterRequest, // optional callback(agentDid, fromTs, toTs) for live filtering
}) {
  const [agentDid, setAgentDid] = useState(initialAgentDid)
  const [fromTs,   setFromTs]   = useState(initialFromTs)
  const [toTs,     setToTs]     = useState(initialToTs)

  function handleFilter() {
    if (onFilterRequest) onFilterRequest(agentDid, fromTs, toTs)
  }

  if (!events.length && !chainVerify) {
    return <div className="text-pramana-muted text-sm">No audit events yet.</div>
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <FilterBar
        agentDid={agentDid}
        fromTs={fromTs}
        toTs={toTs}
        onAgentDidChange={setAgentDid}
        onFromTsChange={setFromTs}
        onToTsChange={setToTs}
        onFilter={handleFilter}
      />

      {/* Hash chain badge + export row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <ChainBadge chainVerify={chainVerify} />
        <ExportButtons
          csvUrl={exportCsvUrl || (initialAgentDid ? `http://localhost:5052/gateway/events/export?format=csv&agent_did=${encodeURIComponent(initialAgentDid)}` : null)}
          jsonUrl={exportJsonUrl || (initialAgentDid ? `http://localhost:5052/gateway/events/export?format=json&agent_did=${encodeURIComponent(initialAgentDid)}` : null)}
        />
      </div>

      {/* Event count */}
      {events.length > 0 && (
        <div className="text-xs text-pramana-muted">
          Showing {Math.min(events.length, 50)} of {events.length} events — click any row to expand full details
        </div>
      )}

      {/* Event table */}
      {events.length > 0 && (
        <div className="bg-pramana-card border border-pramana-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-pramana-dark text-pramana-muted border-b border-pramana-border font-mono">
                  <th className="text-left p-3 pr-2">#</th>
                  <th className="text-left p-3 pr-3">Time</th>
                  <th className="text-left p-3 pr-3">Agent</th>
                  <th className="text-left p-3 pr-3">Authorized by</th>
                  <th className="text-left p-3 pr-3">Tool</th>
                  <th className="text-left p-3 pr-3">Decision</th>
                  <th className="text-left p-3 pr-3">Trust</th>
                  <th className="text-left p-3 pr-3">Auth</th>
                  <th className="text-left p-3">Total</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 50).map((event, i) => (
                  <EventRow key={event.request_id || i} event={event} idx={i + 1} />
                ))}
              </tbody>
            </table>
          </div>
          {events.length > 50 && (
            <div className="text-center text-xs text-pramana-muted py-2 border-t border-pramana-border">
              Showing 50 of {events.length} events — use Export for full dataset
            </div>
          )}
        </div>
      )}

      {/* Compliance note */}
      <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
        <div className="text-xs text-pramana-muted space-y-1">
          <p className="font-bold text-slate-400">Compliance answer</p>
          <p>Every row above is what your compliance team gets when opposing counsel sends a subpoena: every action the agent took, who authorized it (human identity from the blended VP), what the trust score was, and a cryptographic proof the log is intact.</p>
          <p className="text-pramana-teal mt-1">Export CSV to attach to your audit response. Hash chain verification proves the log has not been tampered with.</p>
        </div>
      </div>
    </div>
  )
}
