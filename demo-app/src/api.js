/**
 * Pramana Demo API Client
 * Calls all four demo services: Mock OIDC, IdP Bridge, Gateway, Mock MCP.
 */

export const GATEWAY    = import.meta.env.VITE_GATEWAY_URL      || 'http://localhost:5052'
export const IDP_BRIDGE = import.meta.env.VITE_IDP_BRIDGE_URL   || 'http://localhost:5053'
export const MOCK_OIDC  = import.meta.env.VITE_MOCK_OIDC_URL    || 'http://localhost:9200'
export const MOCK_MCP   = import.meta.env.VITE_MOCK_MCP_URL     || 'http://localhost:9100'
export const SQLITE_MCP = import.meta.env.VITE_SQLITE_MCP_URL   || 'http://localhost:9102'

/** Agent DID used as delegate — generated fresh on each demo run.
 *  We use a well-known placeholder for the browser; the bridge signs the VP. */
export const DEMO_AGENT_DID = 'did:key:z6MkDemoShoppingBotForReactAppDemo001'

async function apiCall(url, options = {}) {
  const resp = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  })
  const body = await resp.json().catch(() => ({}))
  const hdrs = {}
  resp.headers.forEach((v, k) => { hdrs[k] = v })
  return { status: resp.status, ok: resp.ok, body, headers: hdrs }
}

// ── Mock OIDC ────────────────────────────────────────────────────────────────

export async function getOIDCToken(user = 'alice') {
  const r = await fetch(`${MOCK_OIDC}/token?user=${user}`)
  const data = await r.json()
  return data.id_token || null
}

export async function getOIDCHealth() {
  try {
    const r = await fetch(`${MOCK_OIDC}/health`, { signal: AbortSignal.timeout(3000) })
    return r.ok
  } catch { return false }
}

// ── IdP Bridge ───────────────────────────────────────────────────────────────

export async function attestIdentity(oidcToken) {
  return apiCall(`${IDP_BRIDGE}/attest`, {
    method: 'POST',
    body: JSON.stringify({ oidc_token: oidcToken }),
  })
}

export async function bindAgent(oidcToken, agentDid, scope) {
  return apiCall(`${IDP_BRIDGE}/bind`, {
    method: 'POST',
    body: JSON.stringify({ oidc_token: oidcToken, agent_did: agentDid, scope }),
  })
}

export async function bindWithVP(oidcToken, agentDid, scope, gatewayDid = '') {
  return apiCall(`${IDP_BRIDGE}/bind-with-vp`, {
    method: 'POST',
    body: JSON.stringify({
      oidc_token: oidcToken,
      agent_did: agentDid,
      scope,
      gateway_did: gatewayDid,
    }),
  })
}

export async function getBridgeHealth() {
  try {
    const r = await fetch(`${IDP_BRIDGE}/health`, { signal: AbortSignal.timeout(3000) })
    return r.ok
  } catch { return false }
}

// ── MCP Gateway ──────────────────────────────────────────────────────────────

export async function getGatewayHealth() {
  try {
    const r = await fetch(`${GATEWAY}/gateway/health`, { signal: AbortSignal.timeout(3000) })
    if (!r.ok) return { ok: false }
    const data = await r.json()
    return { ok: true, gateway_did: data.gateway_did }
  } catch { return { ok: false } }
}

export async function mcpToolCall(server, tool, args, vpToken) {
  return apiCall(`${GATEWAY}/mcp/${server}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${vpToken}` },
    body: JSON.stringify({
      jsonrpc: '2.0', id: Date.now(), method: 'tools/call',
      params: { name: tool, arguments: args || {} },
    }),
  })
}

export async function mcpToolCallNoAuth(server, tool) {
  return apiCall(`${GATEWAY}/mcp/${server}`, {
    method: 'POST',
    body: JSON.stringify({
      jsonrpc: '2.0', id: Date.now(), method: 'tools/call',
      params: { name: tool, arguments: {} },
    }),
  })
}

export async function getDetections() {
  const r = await fetch(`${GATEWAY}/gateway/detections`)
  return r.json().catch(() => ({}))
}

export async function getInventory() {
  const r = await fetch(`${GATEWAY}/gateway/inventory`)
  return r.json().catch(() => ({}))
}

export async function getAuditEvents(n = 30) {
  const r = await fetch(`${GATEWAY}/gateway/events?n=${n}`)
  return r.json().catch(() => [])
}

export async function getAuditChainVerification() {
  try {
    const r = await fetch(`${GATEWAY}/gateway/audit/verify`, { signal: AbortSignal.timeout(5000) })
    if (!r.ok) return null
    return r.json()
  } catch { return null }
}

// ── Mock MCP server ──────────────────────────────────────────────────────────

export async function getCredentialsReceived() {
  // Try SQLite MCP first (used in Act 2 gateway calls), fall back to mock MCP
  try {
    const r = await fetch(`${SQLITE_MCP}/credentials-received`, { signal: AbortSignal.timeout(3000) })
    if (r.ok) {
      const data = await r.json()
      if (data.credentials && data.credentials.length > 0) return data
    }
  } catch { /* fall through */ }
  try {
    const r = await fetch(`${MOCK_MCP}/credentials-received`)
    return r.json()
  } catch { return { requests: [] } }
}

export async function getMCPHealth() {
  try {
    const r = await fetch(`${MOCK_MCP}/health`, { signal: AbortSignal.timeout(3000) })
    return r.ok
  } catch { return false }
}

export async function getSQLiteMCPHealth() {
  try {
    const r = await fetch(`${SQLITE_MCP}/health`, { signal: AbortSignal.timeout(3000) })
    return r.ok
  } catch { return false }
}

// ── Shadow demo helpers ───────────────────────────────────────────────────────

/** Returns { expired_vp, no_delegation_vp } for Act 5 shadow categories.
 *  The bridge sleeps 2s server-side so expired_vp is already expired. */
export async function getShadowTestVPs(gatewayDid = '') {
  return apiCall(`${IDP_BRIDGE}/bridge/shadow-test-vps`, {
    method: 'POST',
    body: JSON.stringify({ gateway_did: gatewayDid }),
  })
}

// ── Revocation ────────────────────────────────────────────────────────────────

/** Revoke a credential by its jti.  Instant — gateway enforces on next request. */
export async function revokeCredential(credentialId) {
  return apiCall(`${IDP_BRIDGE}/bridge/revoke`, {
    method: 'POST',
    body: JSON.stringify({ credential_id: credentialId }),
  })
}

// ── Multi-hop delegation ──────────────────────────────────────────────────────

/** Like bindWithVP but passes max_depth so the bridge issues a re-delegatable VC. */
export async function bindWithVPMultiHop(oidcToken, agentDid, scope, gatewayDid = '', maxDepth = 2) {
  // max_depth is not yet a field on BindWithVPRequest — we pass it via the
  // underlying /bind call.  Use /bind directly to get the delegation_vc, then
  // call bindWithVP for the full VP.  For the React demo we just call /bind with
  // max_depth and use that delegation in the chain display.
  return apiCall(`${IDP_BRIDGE}/bind`, {
    method: 'POST',
    body: JSON.stringify({
      oidc_token: oidcToken,
      agent_did: agentDid,
      scope,
      max_depth: maxDepth,
    }),
  })
}

// ── Filtered audit query ──────────────────────────────────────────────────────

/** Query audit events with optional time-range and agent filter. */
export async function getAuditEventsFiltered(agentDid = '', fromTs = '', toTs = '', n = 100) {
  const params = new URLSearchParams()
  if (agentDid) params.set('agent_did', agentDid)
  if (fromTs)   params.set('from_ts', fromTs)
  if (toTs)     params.set('to_ts', toTs)
  params.set('n', String(n))
  const r = await fetch(`${GATEWAY}/gateway/events?${params}`)
  return r.json().catch(() => [])
}

/** Build the CSV export URL (browser opens it to trigger download). */
export function buildExportUrl(format = 'csv', agentDid = '', fromTs = '', toTs = '') {
  const params = new URLSearchParams({ format })
  if (agentDid) params.set('agent_did', agentDid)
  if (fromTs)   params.set('from_ts', fromTs)
  if (toTs)     params.set('to_ts', toTs)
  return `${GATEWAY}/gateway/events/export?${params}`
}
