import { useEffect, useRef, useState, useCallback } from 'react'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000'
const RECONNECT_DELAY = 3000
const MAX_ALERTS = 50

export function useWebSocket() {
  const [alerts, setAlerts]           = useState([])
  const [connected, setConnected]     = useState(false)
  const [lastAlert, setLastAlert]     = useState(null)
  const wsRef                         = useRef(null)
  const reconnectTimer                = useRef(null)
  const mountedRef                    = useRef(true)

  const connect = useCallback(() => {
    const token = localStorage.getItem('access_token')
    if (!token || !mountedRef.current) return

    try {
      const ws = new WebSocket(`${WS_URL}/ws?token=${token}`)
      wsRef.current = ws

      ws.onopen = () => {
        if (!mountedRef.current) return
        setConnected(true)
        clearTimeout(reconnectTimer.current)
      }

      ws.onmessage = (event) => {
        if (!mountedRef.current) return
        try {
          const data = JSON.parse(event.data)
          if (data.type === 'ALERT') {
            const enriched = { ...data, receivedAt: Date.now(), id: `${Date.now()}-${Math.random()}` }
            setLastAlert(enriched)
            setAlerts((prev) => [enriched, ...prev].slice(0, MAX_ALERTS))
          }
        } catch { /* ignore parse errors */ }
      }

      ws.onclose = () => {
        if (!mountedRef.current) return
        setConnected(false)
        reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY)
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch { /* ignore connection errors */ }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const clearAlerts = useCallback(() => setAlerts([]), [])

  const ping = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'ping' }))
    }
  }, [])

  return { alerts, connected, lastAlert, clearAlerts, ping }
}