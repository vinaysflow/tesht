/**
 * useFleetOverview
 * ────────────────
 * Fetches live gateway data for the Fleet Overview panel.
 * Polls every 5 seconds so the UI stays current during demo runs.
 *
 * Returns:
 *   events      – most recent 100 audit events (array)
 *   detections  – { alerts, fleet } from /gateway/detections
 *   chainVerify – result of /gateway/audit/verify (or null)
 *   inventory   – result of /gateway/inventory (or {})
 *   loading     – true on first fetch, false after
 *   error       – last error string or null
 *   refresh     – manual trigger function
 *   lastUpdated – Date of last successful fetch
 */
import { useState, useEffect, useCallback, useRef } from 'react'
import {
  getAuditEvents,
  getDetections,
  getAuditChainVerification,
  getInventory,
} from '../api.js'

const POLL_INTERVAL_MS = 5000

export function useFleetOverview() {
  const [events,      setEvents]      = useState([])
  const [detections,  setDetections]  = useState({ alerts: [], fleet: {} })
  const [chainVerify, setChainVerify] = useState(null)
  const [inventory,   setInventory]   = useState({})
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)

  const timerRef = useRef(null)

  const fetchAll = useCallback(async () => {
    try {
      const [evts, det, chain, inv] = await Promise.allSettled([
        getAuditEvents(100),
        getDetections(),
        getAuditChainVerification(),
        getInventory(),
      ])

      if (evts.status      === 'fulfilled') setEvents(evts.value      || [])
      if (det.status       === 'fulfilled') setDetections(det.value   || { alerts: [], fleet: {} })
      if (chain.status     === 'fulfilled') setChainVerify(chain.value)
      if (inv.status       === 'fulfilled') setInventory(inv.value    || {})

      setLastUpdated(new Date())
      setError(null)
    } catch (err) {
      setError(err?.message || 'Fetch failed')
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial fetch + polling
  useEffect(() => {
    fetchAll()
    timerRef.current = setInterval(fetchAll, POLL_INTERVAL_MS)
    return () => clearInterval(timerRef.current)
  }, [fetchAll])

  return {
    events,
    detections,
    chainVerify,
    inventory,
    loading,
    error,
    refresh: fetchAll,
    lastUpdated,
  }
}
