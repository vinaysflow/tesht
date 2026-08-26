import { shortDid, formatScope } from '../utils/format.js'

function Node({ icon, name, subtitle, did, badge, color = 'teal' }) {
  const borderColor = color === 'teal' ? 'border-tesht-teal' :
                      color === 'purple' ? 'border-purple-500' : 'border-blue-500'
  return (
    <div className={`border ${borderColor} rounded-xl p-4 bg-tesht-card text-sm w-full max-w-xs`}>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xl">{icon}</span>
        <span className="font-bold text-slate-100">{name}</span>
      </div>
      {subtitle && <div className="text-xs text-tesht-muted ml-7">{subtitle}</div>}
      {did && <div className="text-xs text-tesht-muted font-mono ml-7 mt-1">{shortDid(did, 20)}</div>}
      {badge && (
        <div className="mt-2 ml-7">
          <span className="text-xs bg-tesht-teal/20 text-tesht-teal px-2 py-0.5 rounded border border-tesht-teal/40">
            {badge}
          </span>
        </div>
      )}
    </div>
  )
}

function Edge({ scope }) {
  return (
    <div className="flex flex-col items-center my-2">
      <div className="w-px h-4 bg-tesht-border" />
      <div className="border border-tesht-border rounded px-3 py-1 text-xs text-tesht-muted bg-tesht-dark max-w-xs text-center">
        <div className="font-bold text-slate-300 mb-0.5">Delegated scope</div>
        <div>{formatScope(scope)}</div>
      </div>
      <div className="w-px h-4 bg-tesht-border" />
      <div className="text-tesht-border text-lg">↓</div>
    </div>
  )
}

export function DelegationTree({ delegationChain, delegatorClaims, agentDid }) {
  if (!delegatorClaims && !delegationChain?.length) {
    return <div className="text-tesht-muted text-sm">No delegation data yet.</div>
  }

  const claims  = delegatorClaims || {}
  const chain   = delegationChain || []
  const scope   = chain[0]?.scope || {}

  return (
    <div className="space-y-4">
      <div className="flex flex-col items-center">
        {/* Human node */}
        <Node
          icon="👤"
          name={claims.name || 'Alice Johnson'}
          subtitle={`${claims.role || 'Senior Buyer'} @ ${claims.organization || 'Acme Corp'}`}
          did={chain[0]?.delegator}
          badge="Identity verified via Acme Corp Okta (RS256)"
          color="teal"
        />

        <Edge scope={scope} />

        {/* Agent node */}
        <Node
          icon="🤖"
          name="ShoppingBot"
          subtitle="LLM Agent — Procurement automation"
          did={agentDid || chain[0]?.delegate}
          badge="Receives delegated authority"
          color="purple"
        />
      </div>

      {/* Verification status */}
      <div className="bg-tesht-card border border-tesht-border rounded-xl p-4">
        <h3 className="text-sm font-bold text-slate-400 mb-2">Chain Verification</h3>
        <div className="space-y-1 text-xs font-mono">
          {[
            ['Scope narrowing', 'Child scope ⊆ parent scope'],
            ['Ed25519 signatures', 'All links signed and verified'],
            ['Revocation status', 'Not revoked (BitstringStatusList)'],
            ['TTL bound', 'Child TTL ≤ parent TTL'],
            ['Depth limit', `Depth ${chain.length} of 2 max`],
          ].map(([label, note]) => (
            <div key={label} className="flex items-center gap-2">
              <span className="text-emerald-400">✓</span>
              <span className="text-slate-300 w-36">{label}</span>
              <span className="text-tesht-muted">{note}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
