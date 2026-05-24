import { useState } from 'react'
import { decodeVP } from '../utils/jwt.js'
import { shortDid, credTypeColor } from '../utils/format.js'

function CredCard({ cred, idx }) {
  const [expanded, setExpanded] = useState(false)
  const colorClass = credTypeColor(cred.type)

  return (
    <div className={`border rounded-lg p-3 mb-2 ${colorClass.split(' ')[0]} bg-pramana-dark`}>
      <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div>
          <span className={`text-xs font-bold px-2 py-0.5 rounded border mr-2 ${colorClass}`}>
            {cred.type}
          </span>
          <span className="text-xs text-pramana-muted">Credential {idx}</span>
        </div>
        <span className="text-pramana-muted text-xs">{expanded ? '▲ collapse' : '▼ expand'}</span>
      </div>

      {expanded && (
        <div className="mt-3 space-y-1 text-xs font-mono">
          <Row label="Issuer"   val={shortDid(cred.issuer, 24)} />
          <Row label="Subject"  val={shortDid(cred.subject, 24)} />
          <Row label="Issued"   val={cred.issuedAt?.slice(0, 19) + 'Z'} />
          <Row label="Expires"  val={cred.expiry?.slice(0, 19)  + 'Z'} />
          {Object.entries(cred.claims).slice(0, 8).map(([k, v]) => (
            <Row key={k} label={k} val={String(v).slice(0, 60)} />
          ))}
          <details className="mt-2">
            <summary className="text-pramana-muted cursor-pointer">Raw JWT</summary>
            <pre className="mt-1 text-xs text-pramana-muted break-all whitespace-pre-wrap">{cred.raw}</pre>
          </details>
        </div>
      )}
    </div>
  )
}

function Row({ label, val }) {
  return (
    <div className="flex gap-2">
      <span className="text-pramana-muted w-24 shrink-0">{label}</span>
      <span className="text-slate-200 break-all">{val}</span>
    </div>
  )
}

export function VPViewer({ vpToken }) {
  if (!vpToken) return <div className="text-pramana-muted text-sm">No VP data yet.</div>

  const vp = decodeVP(vpToken)

  return (
    <div className="space-y-4">
      {/* VP header */}
      <div className="bg-pramana-card border border-pramana-border rounded-xl p-4">
        <h3 className="text-sm font-bold text-pramana-teal mb-3">Verifiable Presentation</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
          <Row label="Holder"   val={shortDid(vp.holder, 22)} />
          <Row label="Audience" val={shortDid(vp.audience, 22)} />
          <Row label="Expires"  val={vp.expiry?.slice(0, 19) + 'Z'} />
          <Row label="Type"     val={(vp.types || []).join(', ')} />
        </div>
      </div>

      {/* Credentials */}
      <div>
        <h3 className="text-sm font-bold text-slate-400 mb-2">
          Bundled Credentials ({vp.credentials?.length || 0})
        </h3>
        {(vp.credentials || []).map((cred, i) => cred && (
          <CredCard key={i} cred={cred} idx={i + 1} />
        ))}
      </div>
    </div>
  )
}
