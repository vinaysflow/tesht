import { shortDid } from '../utils/format.js'

function Side({ title, items }) {
  return (
    <div className="flex-1 min-w-0">
      <h4 className="text-xs font-bold text-tesht-teal mb-3">{title}</h4>
      <div className="space-y-1.5">
        {items.map(({ icon, text, sub }, i) => (
          <div key={i} className="flex items-start gap-1.5 text-xs font-mono">
            <span className={icon === '✓' ? 'text-emerald-400' : 'text-red-400'}>{icon}</span>
            <div>
              <div className="text-slate-200">{text}</div>
              {sub && <div className="text-tesht-muted">{sub}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export function IsolationView({ vpToken, serverEntry }) {
  const vpPreview = vpToken ? `Bearer ${vpToken.slice(0, 22)}…` : 'Bearer <VP-JWT>'
  const apiKey    = serverEntry?.api_key_value || 'secret-api-key-***'
  const vpForwarded = serverEntry?.auth_header?.startsWith('Bearer ey') ?? false

  const agentSide = [
    { icon: '✓', text: 'Sends:', sub: vpPreview },
    { icon: '✓', text: 'Knows: own agent DID' },
    { icon: '✓', text: 'Knows: delegation from Alice' },
    { icon: '✓', text: 'Knows: enterprise identity VC' },
    { icon: '✗', text: 'Never sees: API key' },
    { icon: '✗', text: 'Never sees: server URL' },
    { icon: '✗', text: 'Never sees: server credentials' },
  ]

  const serverSide = [
    { icon: '✓', text: 'Receives:', sub: `X-API-Key: ${apiKey}` },
    { icon: '✓', text: 'Knows: gateway API key' },
    { icon: '✓', text: 'Knows: X-Agent-DID header' },
    { icon: '✓', text: 'Knows: X-Delegator header' },
    { icon: vpForwarded ? '✗' : '✓', text: `VP-JWT: ${vpForwarded ? 'FORWARDED ⚠' : 'NOT forwarded ✓'}` },
    { icon: '✗', text: "Never sees: Alice's OIDC token" },
    { icon: '✗', text: 'Never sees: full delegation chain' },
  ]

  return (
    <div className="space-y-4">
      <div className="bg-tesht-card border border-tesht-border rounded-xl p-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <Side title="🤖 AGENT SIDE" items={agentSide} />

          <div className="flex sm:flex-col items-center justify-center gap-2 px-4">
            <div className="hidden sm:block w-px h-full min-h-[100px] bg-tesht-border" />
            <div className="sm:hidden h-px w-full bg-tesht-border" />
            <div className="bg-tesht-teal/20 border border-tesht-teal rounded-full px-3 py-2 text-center whitespace-nowrap">
              <div className="text-xs font-bold text-tesht-teal">🔐 Gateway</div>
              <div className="text-xs text-tesht-muted">Boundary</div>
            </div>
            <div className="hidden sm:block w-px h-full min-h-[100px] bg-tesht-border" />
            <div className="sm:hidden h-px w-full bg-tesht-border" />
          </div>

          <Side title="🖥 MCP SERVER SIDE" items={serverSide} />
        </div>
      </div>

      {/* Isolation verdict */}
      <div className={`rounded-xl p-3 border text-sm font-mono
        ${vpForwarded
          ? 'bg-red-900/20 border-red-700 text-red-300'
          : 'bg-emerald-900/20 border-emerald-700 text-emerald-300'}`}>
        {vpForwarded
          ? '⚠ ISOLATION BREACH: VP-JWT was forwarded to upstream!'
          : '✓ ISOLATION VERIFIED: Agent credentials ≠ Server credentials'}
      </div>
    </div>
  )
}
