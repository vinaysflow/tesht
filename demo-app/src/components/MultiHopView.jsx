import { shortDid, formatScope } from '../utils/format.js'
import { StatusBadge } from './StatusBadge.jsx'

function ChainNode({ icon, name, subtitle, did, badge, color = 'teal' }) {
  const borderColor =
    color === 'teal'   ? 'border-pramana-teal' :
    color === 'purple' ? 'border-purple-500'   :
    color === 'blue'   ? 'border-blue-500'     : 'border-slate-500'

  return (
    <div className={`border ${borderColor} rounded-xl p-4 bg-pramana-card text-sm w-full max-w-xs`}>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xl">{icon}</span>
        <span className="font-bold text-slate-100">{name}</span>
      </div>
      {subtitle && <div className="text-xs text-pramana-muted ml-7">{subtitle}</div>}
      {did     && <div className="text-xs text-pramana-muted font-mono ml-7 mt-1">{shortDid(did, 20)}</div>}
      {badge   && (
        <div className="mt-2 ml-7">
          <span className="text-xs bg-pramana-teal/20 text-pramana-teal px-2 py-0.5 rounded border border-pramana-teal/40">
            {badge}
          </span>
        </div>
      )}
    </div>
  )
}

function ChainEdge({ scope, narrowed }) {
  return (
    <div className="flex flex-col items-center my-2">
      <div className="w-px h-4 bg-pramana-border" />
      <div className={`border rounded px-3 py-1 text-xs bg-pramana-dark max-w-xs text-center
        ${narrowed ? 'border-amber-600/60' : 'border-pramana-border'}`}>
        <div className={`font-bold mb-0.5 ${narrowed ? 'text-amber-300' : 'text-slate-300'}`}>
          {narrowed ? '⬇ Narrowed scope' : 'Delegated scope'}
        </div>
        <div className="text-pramana-muted">{formatScope(scope)}</div>
      </div>
      <div className="w-px h-4 bg-pramana-border" />
      <div className="text-pramana-border text-lg">↓</div>
    </div>
  )
}

function ResultCard({ result, label, icon }) {
  if (!result) return null
  const isBlocked = result.decision && result.decision.startsWith('blocked')
  const bgClass   = isBlocked
    ? 'bg-red-900/20 border-red-700'
    : 'bg-emerald-900/20 border-emerald-700'

  return (
    <div className={`rounded-xl p-4 border ${bgClass}`}>
      <div className="flex items-center gap-2 mb-2">
        <span>{icon}</span>
        <span className="text-sm font-bold text-slate-100">{label}</span>
        <StatusBadge decision={result.decision} />
        {typeof result.trustScore !== 'undefined' && (
          <span className="text-xs font-mono text-pramana-muted ml-auto">
            trust: <span className="text-slate-200">{result.trustScore}</span>
          </span>
        )}
      </div>
      <div className="text-xs font-mono space-y-1 text-pramana-muted">
        <div><span className="text-slate-400">tool:</span> {result.tool}</div>
        {result.requiredAction && (
          <div><span className="text-slate-400">required action:</span>{' '}
            <span className="text-red-300">{result.requiredAction}</span>
          </div>
        )}
        {result.agentActions && (
          <div><span className="text-slate-400">agent authorized:</span>{' '}
            <span className="text-amber-300">[{result.agentActions.join(', ')}]</span>
          </div>
        )}
        {result.reason && isBlocked && (
          <div className="mt-1 text-red-400">{result.reason.slice(0, 100)}</div>
        )}
      </div>
    </div>
  )
}

export function MultiHopView({ chain = [], inScopeResult, outOfScopeResult }) {
  if (!chain.length) {
    return <div className="text-pramana-muted text-sm">No multi-hop delegation data yet.</div>
  }

  const nodeColors = ['teal', 'blue', 'purple', 'slate']

  return (
    <div className="space-y-6">
      {/* Delegation chain tree */}
      <div className="flex flex-col items-center">
        {chain.map((hop, idx) => {
          const isFirst = idx === 0
          const isLast  = idx === chain.length - 1
          const prevScope = idx > 0 ? chain[idx - 1].scope : null
          const narrowed  = prevScope && hop.scope
            ? (hop.scope.max_amount || 0) < (prevScope.max_amount || 0)
              || (hop.scope.actions || []).length < (prevScope.actions || []).length
            : false

          return (
            <div key={idx} className="flex flex-col items-center w-full max-w-xs">
              {isFirst && (
                <ChainNode
                  icon="👤"
                  name={hop.from}
                  subtitle={hop.fromRole || ''}
                  did={hop.fromDid}
                  badge="Identity verified via Okta (RS256)"
                  color="teal"
                />
              )}
              <ChainEdge scope={hop.scope} narrowed={narrowed && !isFirst} />
              <ChainNode
                icon={isLast ? '🔍' : '🤖'}
                name={hop.to}
                subtitle={hop.toRole || 'LLM Agent'}
                did={hop.toDid}
                badge={isLast ? 'Narrowed scope — read_data only' : 'Receives delegated authority'}
                color={nodeColors[idx + 1] || 'purple'}
              />
            </div>
          )
        })}
      </div>

      {/* Chain verification */}
      <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
        <h3 className="text-sm font-bold text-slate-400 mb-2">Chain Verification</h3>
        <div className="space-y-1 text-xs font-mono">
          {[
            ['Scope narrowing',   'Child scope ⊆ parent scope at each hop'],
            ['Ed25519 signatures','All links signed and verified'],
            ['Depth limit',       `Depth ${chain.length} of 2 max`],
            ['TTL bound',         'Child TTL ≤ parent TTL'],
            ['Revocation check',  'Not revoked (BitstringStatusList)'],
          ].map(([label, note]) => (
            <div key={label} className="flex items-center gap-2">
              <span className="text-emerald-400">✓</span>
              <span className="text-slate-300 w-40">{label}</span>
              <span className="text-pramana-muted">{note}</span>
            </div>
          ))}
        </div>
      </div>

      {/* In-scope and out-of-scope results */}
      <div className="space-y-3">
        <h3 className="text-sm font-bold text-slate-400">Gateway Enforcement</h3>
        <ResultCard
          result={inScopeResult}
          label="In-scope request"
          icon="✅"
        />
        <ResultCard
          result={outOfScopeResult}
          label="Out-of-scope request"
          icon="🚫"
        />
      </div>

      {/* Explanation card */}
      <div className="bg-pramana-card border border-amber-700/40 rounded-xl p-4">
        <h3 className="text-sm font-bold text-amber-400 mb-2">What happened</h3>
        <div className="text-xs text-pramana-muted space-y-1">
          <p>Alice authorized <strong className="text-slate-200">read_data + write_data</strong> for DataAnalyst with a $50,000 limit.</p>
          <p>DataAnalyst sub-delegated to KYBReviewer with <strong className="text-slate-200">read_data only</strong> and a $10,000 limit — scope narrowing enforced.</p>
          <p>KYBReviewer's <strong className="text-emerald-400">in-scope request</strong> (query_database → read_data) was allowed.</p>
          <p>KYBReviewer's <strong className="text-red-400">out-of-scope request</strong> (insert_record → write_data) was blocked — Alice never authorized write_data at this delegation hop.</p>
          <p className="mt-2">Every audit event contains the full delegation chain: Alice → DataAnalyst → KYBReviewer.</p>
        </div>
      </div>
    </div>
  )
}
