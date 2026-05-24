import { useState, useEffect, useRef, Component } from 'react'
import { DemoRunner } from './components/DemoRunner.jsx'
import { FleetOverview } from './components/FleetOverview.jsx'
import { useDemo } from './hooks/useDemo.js'
import { useFleetOverview } from './hooks/useFleetOverview.js'
import { getGatewayHealth, getBridgeHealth, getMCPHealth, getOIDCHealth } from './api.js'

class FleetErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null } }
  static getDerivedStateFromError(error) { return { error } }
  render() {
    if (this.state.error) {
      return (
        <div className="mb-6 rounded-xl border border-yellow-800 bg-yellow-900/20 p-4 text-xs text-yellow-300">
          <strong>Fleet Overview unavailable</strong> — {this.state.error?.message || 'unexpected error'}
        </div>
      )
    }
    return this.props.children
  }
}

// tab id to jump to after demo completes when a pill is clicked
const CAPABILITIES = [
  { icon: '🏢', label: 'Enterprise Identity',  desc: 'OIDC → W3C Verifiable Credential via Okta (mock RS256)',          tab: 'delegation' },
  { icon: '🪪', label: 'Blended Identity',     desc: 'Agent + Human + Enterprise in one VP-JWT',                        tab: 'vp'         },
  { icon: '🔒', label: 'Scope Enforcement',    desc: 'Gateway blocks out-of-scope tool calls at proxy layer',           tab: 'audit'      },
  { icon: '📈', label: 'Continuous Trust',     desc: 'Dynamic 0-100 scoring with behavioral penalties + recovery',      tab: 'trust'      },
  { icon: '🚨', label: 'Shadow Detection',     desc: '3 categories of unauthorized access detected in real time',       tab: 'detection'  },
  { icon: '🔀', label: 'Multi-Hop Delegation', desc: '2-hop chain: Alice → DataAnalyst → KYBReviewer with scope narrowing', tab: 'multihop' },
  { icon: '🚫', label: 'Instant Revocation',   desc: 'Credential revoked mid-session — next request blocked immediately', tab: 'revocation' },
  { icon: '📊', label: 'CISO Audit Query',     desc: 'Time-range filter, CSV export, SHA-256 hash chain proof',         tab: 'audit'      },
]

function ServiceDot({ ok, label }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <div className={`w-2 h-2 rounded-full ${ok === true ? 'bg-emerald-400' : ok === false ? 'bg-red-400' : 'bg-yellow-400 animate-pulse'}`} />
      <span className={ok === true ? 'text-slate-300' : ok === false ? 'text-red-400' : 'text-pramana-muted'}>{label}</span>
    </div>
  )
}

function ServiceBar({ health }) {
  const allOk = health.every(h => h.ok === true)
  const anyFail = health.some(h => h.ok === false)

  if (allOk) return null  // Don't show bar if everything is healthy

  return (
    <div className={`rounded-xl p-4 mb-6 border text-sm ${anyFail
      ? 'bg-red-900/20 border-red-700'
      : 'bg-yellow-900/20 border-yellow-700'}`}>
      <div className="font-bold mb-2 text-slate-200">
        {anyFail ? '⚠ Some services not reachable' : '⟳ Checking services…'}
      </div>
      <div className="flex gap-4 flex-wrap mb-3">
        {health.map(h => <ServiceDot key={h.label} ok={h.ok} label={h.label} />)}
      </div>
      {anyFail && (
        <div className="text-xs text-slate-400">
          Start all services with:
          <code className="ml-2 bg-pramana-dark px-2 py-0.5 rounded font-mono">./scripts/demo_web.sh</code>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const demo = useDemo()
  const fleet = useFleetOverview()
  const [health, setHealth] = useState([
    { label: 'Mock OIDC :9200',   ok: null },
    { label: 'IdP Bridge :5053',  ok: null },
    { label: 'MCP Gateway :5052', ok: null },
    { label: 'Mock MCP :9100',    ok: null },
  ])
  // controlled active tab — lifted up so pills can drive it
  const [activeTab, setActiveTab] = useState('delegation')
  const demoRef = useRef(null)

  useEffect(() => {
    async function checkHealth() {
      const [oidc, bridge, gw, mcp] = await Promise.all([
        getOIDCHealth(), getBridgeHealth(),
        getGatewayHealth().then(r => r.ok), getMCPHealth(),
      ])
      setHealth([
        { label: 'Mock OIDC :9200',   ok: oidc },
        { label: 'IdP Bridge :5053',  ok: bridge },
        { label: 'MCP Gateway :5052', ok: gw },
        { label: 'Mock MCP :9100',    ok: mcp },
      ])
    }
    checkHealth()
  }, [])

  // Pills only scroll + highlight — never auto-trigger the demo.
  // The demo only runs when the user explicitly clicks "▶ Run One-Click Demo".
  function handlePillClick(tab) {
    setActiveTab(tab)
    demoRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="min-h-screen bg-pramana-dark text-slate-100">
      {/* Header */}
      <header className="border-b border-pramana-border bg-pramana-card sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🔐</span>
            <div>
              <h1 className="font-bold text-slate-100 text-sm sm:text-base">Pramana Protocol</h1>
              <p className="text-xs text-pramana-muted">W3C Decentralized Identity for AI Agents</p>
            </div>
          </div>
          <div className="flex gap-3 items-center">
            {health.map(h => <ServiceDot key={h.label} ok={h.ok} label={h.label.split(':')[0]} />)}
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
        {/* Hero */}
        <div className="text-center mb-10">
          <h2 className="text-2xl sm:text-4xl font-bold mb-3 bg-gradient-to-r from-pramana-teal to-blue-400 bg-clip-text text-transparent">
            Agent Identity & Trust Demo
          </h2>
          <p className="text-pramana-muted max-w-2xl mx-auto text-sm sm:text-base">
            Watch a full lifecycle: Enterprise SSO → Verifiable Credential → Delegation → Blended Identity VP →
            MCP Gateway auth → Shadow detection → Multi-hop delegation → Instant revocation → CISO audit export.
          </p>
        </div>

        {/* Capability pills — now clickable */}
        <div className="flex flex-wrap gap-2 justify-center mb-10">
          {CAPABILITIES.map(c => (
            <button
              key={c.label}
              title={c.desc}
              onClick={() => handlePillClick(c.tab)}
              className={`flex items-center gap-1.5 border rounded-full px-3 py-1.5 text-xs transition-all
                ${activeTab === c.tab && demo.state !== 'idle'
                  ? 'bg-pramana-teal/20 border-pramana-teal text-pramana-teal font-semibold shadow-[0_0_10px_rgba(45,212,191,0.25)]'
                  : 'bg-pramana-card border-pramana-border text-slate-300 hover:border-pramana-teal hover:text-pramana-teal'
                }`}
            >
              <span>{c.icon}</span>
              <span>{c.label}</span>
            </button>
          ))}
        </div>
        {demo.state === 'complete' && (
          <p className="text-center text-xs text-pramana-muted mb-8 -mt-6">
            Click any pill to jump to that view
          </p>
        )}

        {/* Service health warning */}
        <ServiceBar health={health} />

        {/* Fleet Overview — always visible, auto-refreshes every 5s */}
        <FleetErrorBoundary>
          <FleetOverview
            events={fleet.events}
            detections={fleet.detections}
            chainVerify={fleet.chainVerify}
            inventory={fleet.inventory}
            loading={fleet.loading}
            lastUpdated={fleet.lastUpdated}
          />
        </FleetErrorBoundary>

        {/* Main demo area */}
        <div ref={demoRef}>
          <DemoRunner
            state={demo.state}
            currentStep={demo.currentStep}
            stepLogs={demo.stepLogs}
            results={demo.results}
            errorMsg={demo.errorMsg}
            onRun={demo.runDemo}
            onReset={demo.reset}
            activeTab={activeTab}
            onTabChange={setActiveTab}
          />
        </div>

        {/* How it works */}
        <div className="mt-16 grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            {
              title: 'W3C Standards, No Vendor Lock-in',
              body: 'Built on DIDs, Verifiable Credentials, and Verifiable Presentations — open standards anyone can verify.',
            },
            {
              title: 'Graduated Trust, Not Binary',
              body: 'Pramana scores 0-100 per request. Aembit allows or denies. Continuous trust adjusts at runtime without re-auth.',
            },
            {
              title: 'Prevents AND Detects',
              body: '$285M went to NHI detection startups. Pramana enforces identity AND surfaces shadow agents in real time.',
            },
          ].map(c => (
            <div key={c.title} className="bg-pramana-card border border-pramana-border rounded-xl p-5">
              <h3 className="font-bold text-pramana-teal mb-2 text-sm">{c.title}</h3>
              <p className="text-xs text-pramana-muted leading-relaxed">{c.body}</p>
            </div>
          ))}
        </div>
      </main>

      <footer className="border-t border-pramana-border text-center text-xs text-pramana-muted py-6 mt-12">
        Pramana Protocol — W3C DID / VC / VP · MCP Identity Gateway · Continuous Trust · Shadow Detection · Multi-Hop Delegation · Instant Revocation · CISO Audit
      </footer>
    </div>
  )
}
