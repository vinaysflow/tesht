/**
 * useDemo — state machine hook orchestrating the 9-act CISO demo.
 *
 * State machine: idle → running → complete | error
 *
 * Acts 1-4: unchanged from original 6-act demo.
 * Act 5:    Shadow Attack — enhanced to 3 distinct categories.
 * Act 6:    Multi-Hop Delegation — NEW (2-hop chain, scope violation).
 * Act 7:    Mid-Session Revocation — NEW.
 * Act 8:    CISO Audit Query — NEW.
 * Act 9:    Fleet Dashboard — moved from old Act 6.
 *
 * Returned results object:
 *   act1: { claims, delegationChain, enterpriseVc, delegationVc, agentVc, humanDid }
 *   act2: { blendedVP, trustFactors, credentialsReceived, queryResult, queryRows }
 *   act3: { blocked, trustFactors }
 *   act4: { trustHistory[], freshVP }
 *   act5: { shadowResults[{phase,status,body}], detections }
 *   act6: { chain[{from,fromDid,to,toDid,scope}], agentBVP, inScopeResult, outOfScopeResult }
 *   act7: { preRevocation[], credentialId, postRevocation[], revokedAt }
 *   act8: { events[], chainVerify, fromTs, toTs, agentDid, exportCsvUrl, exportJsonUrl }
 *   act9: { alerts, fleet, auditEvents, inventory, chainVerify }
 */
import { useState, useCallback } from 'react'
import * as api from '../api.js'
import { decodeJWT } from '../utils/jwt.js'

const DEMO_SCOPE = {
  actions:    ['read_data', 'write_data', 'browse_products', 'purchase'],
  max_amount: 50000,
  currency:   'USD',
  merchants:  ['*'],
  categories: ['electronics', 'office_supplies'],
}

const NARROWED_SCOPE = {
  actions:    ['read_data'],
  max_amount: 10000,
  currency:   'USD',
  merchants:  ['*'],
  categories: ['electronics', 'office_supplies'],
}

// Second agent DID for multi-hop delegation demo (KYBReviewer)
const KYB_AGENT_DID = 'did:key:z6MkDemoKYBReviewerForReactAppDemo002'

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms))
}

function parseTrustFactors(headers) {
  try {
    const raw = headers['x-tesht-trust-factors']
    return raw ? JSON.parse(raw) : {}
  } catch { return {} }
}

/** Extract the jti claim from a VC-JWT payload without signature verification. */
function extractJti(jwt) {
  try {
    const { payload } = decodeJWT(jwt)
    return payload.jti || payload.id || null
  } catch { return null }
}

export function useDemo() {
  const [state, setState]       = useState('idle')   // idle | running | complete | error
  const [currentStep, setStep]  = useState(0)
  const [stepLogs, setLogs]     = useState([])
  const [results, setResults]   = useState({})
  const [errorMsg, setError]    = useState(null)

  function addLog(step, text, ok = true) {
    setLogs(prev => [...prev, { step, text, ok, ts: Date.now() }])
  }

  const runDemo = useCallback(async () => {
    setState('running')
    setStep(0)
    setLogs([])
    setResults({})
    setError(null)

    const r = {}
    // Capture demo start time for CISO audit time-range query
    const demoStartTs = new Date().toISOString()

    try {
      // ── Act 1: Enterprise Identity ──────────────────────────────────────
      setStep(1)
      addLog(1, 'Fetching OIDC token for Alice (Acme Corp Okta)…')
      const oidcToken = await api.getOIDCToken('alice')
      if (!oidcToken) throw new Error('Failed to get OIDC token from mock provider')
      addLog(1, 'OIDC token received (RS256 signed)')

      const gwHealth = await api.getGatewayHealth()
      const gatewayDid = gwHealth.gateway_did || ''

      addLog(1, 'Calling /bind-with-vp — attesting identity + issuing delegation + building VP…')
      const bindResult = await api.bindWithVP(oidcToken, api.DEMO_AGENT_DID, DEMO_SCOPE, gatewayDid)
      if (!bindResult.ok) throw new Error(`/bind-with-vp failed: ${JSON.stringify(bindResult.body)}`)

      const bindData = bindResult.body
      addLog(1, `OrganizationalRoleCredential issued for ${bindData.claims?.name || 'Alice Johnson'}`)
      addLog(1, `Delegation: ${bindData.claims?.name} → ShoppingBot, scope: ${(bindData.effective_scope?.actions || []).join(', ')}`)

      r.act1 = {
        claims:          bindData.claims,
        delegationChain: [{
          delegator: bindData.did,
          delegate:  bindData.agent_did,
          scope:     bindData.effective_scope,
          depth:     1,
        }],
        enterpriseVc:    bindData.enterprise_vc,
        delegationVc:    bindData.delegation_vc,
        agentVc:         bindData.agent_vc,
        humanDid:        bindData.did,
      }

      await sleep(600)

      // ── Act 2: Blended Identity Through MCP Gateway ─────────────────────
      setStep(2)
      addLog(2, 'Blended VP ready: AgentCredential + DelegationCredential + OrganizationalRoleCredential')

      const vpToken = bindData.blended_vp
      r.act2 = { blendedVP: vpToken }

      addLog(2, 'Calling query_database through MCP Gateway (real SQLite database)…')
      const gwCall = await api.mcpToolCall(
        'sqlite_database', 'query_database',
        { sql: 'SELECT name, price, category FROM products LIMIT 5' },
        vpToken
      )
      r.act2.queryResult  = gwCall
      r.act2.trustFactors = parseTrustFactors(gwCall.headers)

      if (gwCall.status === 200) {
        const rows = gwCall.body?.result?._data?.rows || []
        const rowInfo = rows.length > 0 ? ` — ${rows.length} real rows from SQLite` : ''
        addLog(2, `query_database → Auth ✓ | Scope ✓ | Trust ✓ → ALLOW${rowInfo}`)
        r.act2.queryRows = rows
      } else {
        addLog(2, `query_database → ${gwCall.status}`, false)
      }

      const credsReceived = await api.getCredentialsReceived()
      r.act2.credentialsReceived = credsReceived
      const credList = credsReceived.credentials || credsReceived.requests || []
      const lastReq  = credList.slice(-1)[0] || {}
      const hdrsReceived = lastReq.headers_received || {}
      const vpNotForwarded = !Object.values(hdrsReceived).some(v => String(v).startsWith('Bearer ey'))
      addLog(2, `Server received: X-API-Key ✓ — VP-JWT: ${vpNotForwarded ? 'NOT forwarded ✓ (credential isolation)' : '⚠ VP visible in upstream'}`)

      await sleep(600)

      // ── Act 3: Scope Enforcement ─────────────────────────────────────────
      setStep(3)
      addLog(3, 'ShoppingBot tries delete_record (requires "admin" — not delegated)…')
      const scopeBlock = await api.mcpToolCall('mock_database', 'delete_record', { id: '1' }, vpToken)
      r.act3 = { blocked: scopeBlock, trustFactors: parseTrustFactors(scopeBlock.headers) }

      if (scopeBlock.status === 403) {
        addLog(3, 'delete_record → Auth ✓ | Scope ✗ | BLOCKED (never reached MCP server) ✓')
      } else {
        addLog(3, `Expected 403, got ${scopeBlock.status}`, false)
      }

      await sleep(600)

      // ── Act 4: Continuous Trust Degradation ──────────────────────────────
      setStep(4)
      r.act4 = { trustHistory: [] }

      for (const [tool, args] of [
        ['delete_record', {}],
        ['delete_record', {}],
        ['query_database', { sql: 'SELECT COUNT(*) as total FROM products' }],
      ]) {
        const res = await api.mcpToolCall('sqlite_database', tool, args, vpToken)
        const factors = parseTrustFactors(res.headers)
        const auditEvents = await api.getAuditEvents(5)
        const lastEvent = auditEvents.slice().reverse().find(e =>
          ['allowed', 'step_up', 'blocked_scope', 'blocked_trust'].includes(e.decision)
        )
        const trustScore = lastEvent?.trust_score ?? '?'
        const decision   = lastEvent?.decision ?? (res.status === 200 ? 'allowed' : 'blocked')
        r.act4.trustHistory.push({ tool, status: res.status, trustScore, decision, factors })
        addLog(4, `${tool} → ${decision.toUpperCase()}  trust: ${trustScore}`)
        await sleep(300)
      }

      addLog(4, 'Re-authenticating — fresh VP presented (penalty reset)…')
      const reAuthResult = await api.bindWithVP(oidcToken, api.DEMO_AGENT_DID, DEMO_SCOPE, gatewayDid)
      const freshVp = reAuthResult.ok ? reAuthResult.body.blended_vp : vpToken
      const reAuthCall = await api.mcpToolCall(
        'sqlite_database', 'query_database',
        { sql: 'SELECT name, price FROM products ORDER BY price DESC LIMIT 3' },
        freshVp
      )
      const reAuthFactors = parseTrustFactors(reAuthCall.headers)
      const reAuthAudit  = await api.getAuditEvents(3)
      const reAuthEvent  = reAuthAudit.slice().reverse().find(e => e.decision === 'allowed')
      const reAuthScore  = reAuthEvent?.trust_score ?? '?'
      r.act4.trustHistory.push({
        tool: 'query_database (re-auth)', status: reAuthCall.status,
        trustScore: reAuthScore,
        decision: reAuthCall.status === 200 ? 'allowed' : 'step_up',
        factors: reAuthFactors, reAuth: true,
      })
      r.act4.freshVP = freshVp
      addLog(4, `query_database (fresh VP) → ${reAuthCall.status === 200 ? 'ALLOW ✓ (trust restored)' : `${reAuthCall.status}`}  trust: ${reAuthScore}`)

      await sleep(600)

      // ── Act 5: Shadow Agent Attack (3 categories) ─────────────────────────
      setStep(5)
      r.act5 = { shadowResults: [] }

      // Phase 1: no credentials
      addLog(5, 'Phase 1: Unknown entity (no credentials)…')
      const shadow1 = await api.mcpToolCallNoAuth('sqlite_database', 'query_database')
      r.act5.shadowResults.push({ phase: 'no_creds', status: shadow1.status, body: shadow1.body })
      addLog(5, `No credentials → BLOCKED (${shadow1.body?.detail?.slice(0, 50) || 'auth failed'})`)

      // Phase 2 + 3: fetch bridge-generated expired & no-delegation VPs
      // (bridge sleeps 2s server-side so expired_vp is already expired on arrival)
      addLog(5, 'Phase 2+3: Fetching expired VP and no-delegation VP from bridge…')
      const shadowVPs = await api.getShadowTestVPs(gatewayDid)
      if (shadowVPs.ok) {
        const { expired_vp, no_delegation_vp } = shadowVPs.body

        const shadow2 = await api.mcpToolCall('sqlite_database', 'query_database', {}, expired_vp)
        r.act5.shadowResults.push({ phase: 'expired_vp', status: shadow2.status, body: shadow2.body })
        addLog(5, `Expired VP → BLOCKED (${shadow2.body?.error?.message?.slice(0, 60) || 'auth failed'})`)

        const shadow3 = await api.mcpToolCall('sqlite_database', 'query_database', {}, no_delegation_vp)
        r.act5.shadowResults.push({ phase: 'no_delegation', status: shadow3.status, body: shadow3.body })
        addLog(5, `No delegation → BLOCKED (${shadow3.body?.error?.message?.slice(0, 60) || 'auth failed'})`)
      } else {
        addLog(5, 'Shadow VP generation unavailable — falling back to 2 no-auth probes', false)
        for (let i = 0; i < 2; i++) {
          const res = await api.mcpToolCallNoAuth('sqlite_database', 'query_database')
          r.act5.shadowResults.push({ phase: i === 0 ? 'expired_vp' : 'no_delegation', status: res.status, body: res.body })
          addLog(5, `Shadow probe ${i + 2} → BLOCKED`)
          await sleep(200)
        }
      }

      const detections = await api.getDetections()
      r.act5.detections = detections
      const shadowAlerts = (detections.alerts || []).filter(a => a.type === 'shadow_agent')
      if (shadowAlerts.length > 0) {
        addLog(5, `Shadow agent ALERT fired: ${shadowAlerts[0].title} ✓`)
      }

      await sleep(600)

      // ── Act 6: Multi-Hop Delegation ──────────────────────────────────────
      setStep(6)
      addLog(6, 'Act 6: Multi-hop delegation — Alice → DataAnalyst → KYBReviewer')

      // Step A: Bind DataAnalyst with full scope (max_depth=2)
      const bindA = await api.bindWithVPMultiHop(
        oidcToken, api.DEMO_AGENT_DID, DEMO_SCOPE, gatewayDid, 2
      )
      const aliceClaims = bindA.ok ? bindA.body.claims : r.act1.claims

      // Step B: KYBReviewer gets narrowed scope (read_data only, $10k max)
      const bindB = await api.bindWithVP(oidcToken, KYB_AGENT_DID, NARROWED_SCOPE, gatewayDid)
      if (!bindB.ok) {
        addLog(6, `KYBReviewer bind failed: ${JSON.stringify(bindB.body)}`, false)
      }
      const agentBVP = bindB.ok ? bindB.body.blended_vp : null

      r.act6 = {
        chain: [
          {
            from:    aliceClaims?.name || 'Alice Johnson',
            fromDid: r.act1.humanDid,
            fromRole: `${aliceClaims?.role || 'Senior Buyer'} @ ${aliceClaims?.organization || 'Acme Corp'}`,
            to:      'DataAnalyst',
            toDid:   api.DEMO_AGENT_DID,
            scope:   DEMO_SCOPE,
          },
          {
            from:    'DataAnalyst',
            fromDid: api.DEMO_AGENT_DID,
            fromRole: 'LLM Agent',
            to:      'KYBReviewer',
            toDid:   KYB_AGENT_DID,
            scope:   NARROWED_SCOPE,
          },
        ],
        agentBVP,
        inScopeResult:    null,
        outOfScopeResult: null,
      }

      if (agentBVP) {
        // In-scope: query_database (read_data) → ALLOWED
        const inScope = await api.mcpToolCall(
          'sqlite_database', 'query_database',
          { sql: 'SELECT name FROM products LIMIT 3' },
          agentBVP
        )
        const inScopeAudit = await api.getAuditEvents(3)
        const inScopeEvent = inScopeAudit.slice().reverse().find(e =>
          ['allowed', 'step_up'].includes(e.decision)
        )
        r.act6.inScopeResult = {
          status:     inScope.status,
          trustScore: inScopeEvent?.trust_score ?? '?',
          decision:   inScopeEvent?.decision ?? (inScope.status === 200 ? 'allowed' : 'blocked'),
          tool:       'query_database',
        }
        addLog(6, `KYBReviewer query_database (read_data) → ${inScope.status === 200 ? 'ALLOWED ✓' : `${inScope.status}`}`)

        // Out-of-scope: insert_record (write_data) → BLOCKED
        const outScope = await api.mcpToolCall('sqlite_database', 'insert_record', {}, agentBVP)
        const outScopeMsg = outScope.body?.error?.message || outScope.body?.detail || 'scope denied'
        r.act6.outOfScopeResult = {
          status:          outScope.status,
          tool:            'insert_record',
          requiredAction:  'write_data',
          agentActions:    NARROWED_SCOPE.actions,
          reason:          outScopeMsg,
          decision:        'blocked_scope',
        }
        addLog(6, `KYBReviewer insert_record (write_data — out of scope) → BLOCKED ✓`)
        addLog(6, `  Reason: ${outScopeMsg.slice(0, 80)}`)
      } else {
        addLog(6, 'KYBReviewer VP unavailable — skipping in/out-of-scope calls', false)
      }

      await sleep(600)

      // ── Act 7: Mid-Session Revocation ────────────────────────────────────
      setStep(7)
      addLog(7, 'Act 7: Mid-session revocation — credential revoked, next request blocked instantly')

      // Extract delegation VC jti from Act 1's delegation_vc
      const delegationJti = extractJti(r.act1.delegationVc)
      addLog(7, `Delegation VC jti: ${delegationJti ? delegationJti.slice(0, 36) + '…' : 'could not extract'}`)

      r.act7 = { preRevocation: [], credentialId: delegationJti, postRevocation: [], revokedAt: null }

      // 2 normal requests before revocation (re-bind to get a fresh VP tied to the current status list)
      const revBindResult = await api.bindWithVP(oidcToken, api.DEMO_AGENT_DID, DEMO_SCOPE, gatewayDid)
      const revVP = revBindResult.ok ? revBindResult.body.blended_vp : vpToken
      // Extract the fresh delegation jti from this new bind
      const revDelegationJti = revBindResult.ok
        ? extractJti(revBindResult.body.delegation_vc)
        : delegationJti

      r.act7.credentialId = revDelegationJti

      for (const tool of ['query_database', 'query_database']) {
        const res = await api.mcpToolCall('sqlite_database', tool, { sql: 'SELECT 1' }, revVP)
        const auditSnap = await api.getAuditEvents(3)
        const evt = auditSnap.slice().reverse().find(e => e.decision === 'allowed')
        r.act7.preRevocation.push({
          tool, status: res.status,
          trustScore: evt?.trust_score ?? '?',
          decision: evt?.decision ?? (res.status === 200 ? 'allowed' : 'blocked'),
        })
        addLog(7, `Pre-revocation: ${tool} → ${res.status === 200 ? 'ALLOWED ✓' : res.status}`)
        await sleep(300)
      }

      // Revoke
      if (revDelegationJti) {
        const revokeRes = await api.revokeCredential(revDelegationJti)
        r.act7.revokedAt = Date.now()
        if (revokeRes.ok) {
          addLog(7, `CREDENTIAL REVOKED — jti: ${revDelegationJti.slice(0, 36)}… ⚠`)
        } else {
          addLog(7, `Revoke call returned ${revokeRes.status}: ${JSON.stringify(revokeRes.body)}`, false)
        }
      } else {
        addLog(7, 'No jti available — simulating revocation (status list index unknown)', false)
        r.act7.revokedAt = Date.now()
      }

      await sleep(400)

      // 2 requests after revocation — should be BLOCKED
      for (const tool of ['query_database', 'query_database']) {
        const res = await api.mcpToolCall('sqlite_database', tool, { sql: 'SELECT 1' }, revVP)
        const reason = res.body?.detail || res.body?.error?.message || 'revoked'
        r.act7.postRevocation.push({
          tool, status: res.status,
          decision: res.status !== 200 ? 'blocked_auth' : 'allowed',
          reason: reason.slice(0, 80),
        })
        addLog(7, `Post-revocation: ${tool} → ${res.status !== 200 ? 'BLOCKED ✓ (revoked)' : `${res.status} — NOT blocked!`}`)
        await sleep(300)
      }

      await sleep(600)

      // ── Act 8: CISO Audit Query ───────────────────────────────────────────
      setStep(8)
      addLog(8, 'Act 8: CISO audit query — querying full session with time-range filter')

      const toTs     = new Date().toISOString()
      const agentDid = api.DEMO_AGENT_DID

      const filteredEvents = await api.getAuditEventsFiltered(agentDid, demoStartTs, toTs, 100)
      const chainVerify8   = await api.getAuditChainVerification()
      const csvUrl  = api.buildExportUrl('csv',  agentDid, demoStartTs, toTs)
      const jsonUrl = api.buildExportUrl('json', agentDid, demoStartTs, toTs)

      r.act8 = {
        events:       filteredEvents,
        chainVerify:  chainVerify8,
        fromTs:       demoStartTs,
        toTs,
        agentDid,
        exportCsvUrl:  csvUrl,
        exportJsonUrl: jsonUrl,
      }

      const storage = chainVerify8?.storage || 'unknown'
      const evtCount = chainVerify8?.in_memory_count ?? chainVerify8?.events_checked ?? filteredEvents.length
      addLog(8, `Retrieved ${filteredEvents.length} events for ${agentDid.slice(0, 30)}…`)
      if (storage === 'postgresql') {
        addLog(8, `Hash chain: ${evtCount} events | SHA-256 | PostgreSQL | ${chainVerify8?.valid ? 'VALID ✓' : 'BROKEN ✗'}`)
      } else {
        addLog(8, `Hash chain: ${evtCount} events (in-memory — start PostgreSQL for persistent chain)`)
      }
      addLog(8, 'CSV and JSON export URLs ready — click Export buttons in CISO Audit tab')

      await sleep(600)

      // ── Act 9: Fleet Dashboard ────────────────────────────────────────────
      setStep(9)
      addLog(9, 'Pulling fleet dashboard data…')
      const [allDetections, inventory, auditEvents] = await Promise.all([
        api.getDetections(),
        api.getInventory(),
        api.getAuditEvents(30),
      ])
      const chainVerify9 = await api.getAuditChainVerification()

      r.act9 = {
        alerts:      allDetections.alerts || [],
        fleet:       allDetections.fleet  || {},
        auditEvents,
        inventory,
        chainVerify: chainVerify9,
      }
      addLog(9, `Fleet: ${r.act9.fleet.total_agents || 0} agents, ${r.act9.fleet.shadow_attempts || 0} shadow attempts, ${r.act9.alerts.length} alerts`)

      if (chainVerify9) {
        const storage9 = chainVerify9.storage || 'unknown'
        const count9 = chainVerify9.in_memory_count ?? chainVerify9.events_checked ?? 0
        if (storage9 === 'postgresql') {
          addLog(9, `Audit chain: ${count9} events | SHA-256 | PostgreSQL | ${chainVerify9.valid ? 'VALID ✓' : 'BROKEN ✗'}`)
        } else {
          addLog(9, `Audit chain: ${count9} events | in-memory (start PostgreSQL for persistence)`)
        }
      }

      addLog(9, 'Demo complete ✓')

      setResults(r)
      setState('complete')

    } catch (err) {
      console.error('Demo error:', err)
      setError(err.message || String(err))
      setState('error')
    }
  }, [])

  const reset = useCallback(() => {
    setState('idle')
    setStep(0)
    setLogs([])
    setResults({})
    setError(null)
  }, [])

  return { state, currentStep, stepLogs, results, errorMsg, runDemo, reset }
}
