/**
 * Client-side JWT decode (no signature verification).
 * Safe for browser — uses only base64 decoding.
 */

function b64UrlDecode(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  return atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
}

export function decodeJWT(token) {
  if (!token || typeof token !== 'string') return { header: {}, payload: {} }
  try {
    const [headerB64, payloadB64] = token.split('.')
    const header  = JSON.parse(b64UrlDecode(headerB64))
    const payload = JSON.parse(b64UrlDecode(payloadB64))
    return { header, payload }
  } catch {
    return { header: {}, payload: {} }
  }
}

/** Decode a VP-JWT and return holder, audience, expiry, type, and embedded VCs. */
export function decodeVP(vpToken) {
  const { payload } = decodeJWT(vpToken)
  const vpBody = payload.vp || {}
  const vcTokens = vpBody.verifiableCredential || []

  return {
    holder:      payload.iss || payload.sub || '—',
    audience:    Array.isArray(payload.aud) ? payload.aud[0] : (payload.aud || '—'),
    expiry:      payload.exp ? new Date(payload.exp * 1000).toISOString() : '—',
    types:       vpBody.type || ['VerifiablePresentation'],
    credentials: vcTokens.map(decodeVC),
    raw:         vpToken,
  }
}

/** Decode a VC-JWT and return its fields. */
export function decodeVC(vcToken) {
  if (!vcToken || typeof vcToken !== 'string') return null
  const { payload } = decodeJWT(vcToken)
  const vcBody = payload.vc || {}
  const types  = vcBody.type || []
  const cs     = vcBody.credentialSubject || {}
  const { id: _id, ...claims } = cs

  return {
    type:      types[types.length - 1] || 'VerifiableCredential',
    allTypes:  types,
    issuer:    payload.iss || '—',
    subject:   payload.sub || '—',
    issuedAt:  payload.iat ? new Date(payload.iat * 1000).toISOString() : '—',
    expiry:    payload.exp ? new Date(payload.exp * 1000).toISOString() : '—',
    claims,
    raw:       vcToken,
  }
}
