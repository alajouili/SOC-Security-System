import React, { useEffect, useState, useCallback } from 'react'
import { Bell, CheckCircle, Filter, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import { alertsApi } from '../services/api'
import LevelBadge from '../components/LevelBadge'
import ScoreBar from '../components/ScoreBar'
import { formatDate, truncate } from '../utils/format'
import { useAuth } from '../context/AuthContext'

const LEVELS = ['', 'HIGH', 'MEDIUM', 'LOW']

export default function Alerts({ liveAlerts }) {
  const { user } = useAuth()
  const [alerts, setAlerts]   = useState([])
  const [total, setTotal]     = useState(0)
  const [page, setPage]       = useState(1)
  const [pages, setPages]     = useState(1)
  const [loading, setLoading] = useState(true)
  const [level, setLevel]     = useState('')
  const [ackFilter, setAckFilter] = useState('')
  const [ackingId, setAckingId]   = useState(null)

  const canAcknowledge = user?.role === 'admin' || user?.role === 'analyst'

  const loadAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: 15 }
      if (level)       params.level       = level
      if (ackFilter)   params.acknowledged = ackFilter === 'true'
      const { data } = await alertsApi.getAlerts(params)
      setAlerts(data.items || [])
      setTotal(data.total || 0)
      setPages(data.pages || 1)
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [page, level, ackFilter])

  useEffect(() => { loadAlerts() }, [loadAlerts])

  // Intégrer les alertes live en tête de liste
  useEffect(() => {
    if (liveAlerts?.length > 0) {
      setAlerts(prev => {
        const newOnes = liveAlerts.filter(la => !prev.find(a => a.id === la.id || a.id === la.alert_id))
        return [...newOnes, ...prev].slice(0, 15)
      })
    }
  }, [liveAlerts])

  const handleAcknowledge = async (id) => {
    setAckingId(id)
    try {
      await alertsApi.acknowledge(id)
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, acknowledged: true } : a))
    } catch { /* silent */ }
    finally { setAckingId(null) }
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '28px 28px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{
            fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 800,
            letterSpacing: '0.04em', color: 'var(--text-primary)', marginBottom: 4,
          }}>Alertes</h1>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
            {total} alerte{total > 1 ? 's' : ''} · Score ≥ 31
          </p>
        </div>
        <button onClick={loadAlerts} style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '8px 14px',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 5, color: 'var(--text-secondary)',
          cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-mono)',
          letterSpacing: '0.08em',
        }}>
          <RefreshCw size={12} /> Actualiser
        </button>
      </div>

      {/* Filters */}
      <div style={{
        display: 'flex', gap: 10, marginBottom: 20,
        padding: '14px 16px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: 8,
        alignItems: 'center',
      }}>
        <Filter size={13} style={{ color: 'var(--text-muted)' }} />
        <span style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', marginRight: 4 }}>FILTRES</span>

        <select value={level} onChange={e => { setLevel(e.target.value); setPage(1) }}
          style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 4, color: 'var(--text-primary)',
            padding: '5px 10px', fontSize: 11, fontFamily: 'var(--font-mono)',
            cursor: 'pointer', outline: 'none',
          }}>
          <option value="">Tous niveaux</option>
          {LEVELS.slice(1).map(l => <option key={l} value={l}>{l}</option>)}
        </select>

        <select value={ackFilter} onChange={e => { setAckFilter(e.target.value); setPage(1) }}
          style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 4, color: 'var(--text-primary)',
            padding: '5px 10px', fontSize: 11, fontFamily: 'var(--font-mono)',
            cursor: 'pointer', outline: 'none',
          }}>
          <option value="">Tous statuts</option>
          <option value="false">Non acquittées</option>
          <option value="true">Acquittées</option>
        </select>

        <div style={{
          marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)',
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <Bell size={11} />
          Page {page}/{pages}
        </div>
      </div>

      {/* Table */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
        overflow: 'hidden',
      }}>
        {/* Table header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '90px 1fr 120px 80px 100px 100px',
          gap: 0,
          padding: '10px 16px',
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border)',
          fontSize: 9, letterSpacing: '0.15em',
          color: 'var(--text-muted)', textTransform: 'uppercase',
        }}>
          <span>Niveau</span>
          <span>Message</span>
          <span>IP source</span>
          <span>Score</span>
          <span>Date</span>
          <span>Action</span>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11, letterSpacing: '0.1em' }}>
            CHARGEMENT...
          </div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11 }}>
            Aucune alerte correspondante
          </div>
        ) : alerts.map((alert, i) => (
          <div key={alert.id || i} style={{
            display: 'grid',
            gridTemplateColumns: '90px 1fr 120px 80px 100px 100px',
            gap: 0,
            padding: '12px 16px',
            borderBottom: '1px solid var(--border)',
            alignItems: 'center',
            background: alert.level === 'HIGH' && !alert.acknowledged
              ? 'rgba(255,59,92,0.03)'
              : 'transparent',
            opacity: alert.acknowledged ? 0.55 : 1,
            transition: 'background 0.15s',
          }}>
            <div><LevelBadge level={alert.level} /></div>

            <div style={{ paddingRight: 16 }}>
              <div style={{ fontSize: 11, color: 'var(--text-primary)', marginBottom: 3 }}>
                {truncate(alert.message, 55)}
              </div>
              {alert.techniques?.length > 0 && (
                <div style={{ display: 'flex', gap: 4 }}>
                  {(Array.isArray(alert.techniques) ? alert.techniques : JSON.parse(alert.techniques || '[]')).slice(0, 3).map(t => (
                    <span key={t} style={{
                      fontSize: 9, padding: '1px 5px',
                      background: 'var(--bg-surface)', border: '1px solid var(--border)',
                      borderRadius: 2, color: 'var(--text-muted)', letterSpacing: '0.04em',
                    }}>{t.replace(/_/g, ' ')}</span>
                  ))}
                </div>
              )}
            </div>

            <code style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>
              {alert.ip || '—'}
            </code>

            <div style={{ width: 70 }}>
              <ScoreBar score={alert.score} />
            </div>

            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              {formatDate(alert.created_at).split(' ').slice(0, 2).join(' ')}
            </div>

            <div>
              {alert.acknowledged ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: 'var(--low)' }}>
                  <CheckCircle size={11} /> ACK
                </span>
              ) : canAcknowledge ? (
                <button
                  onClick={() => handleAcknowledge(alert.id)}
                  disabled={ackingId === alert.id}
                  style={{
                    padding: '4px 10px',
                    background: 'transparent',
                    border: '1px solid var(--border-bright)',
                    borderRadius: 3, color: 'var(--text-secondary)',
                    cursor: 'pointer', fontSize: 9,
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '0.08em',
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => { e.target.style.borderColor = 'var(--low)'; e.target.style.color = 'var(--low)' }}
                  onMouseLeave={e => { e.target.style.borderColor = 'var(--border-bright)'; e.target.style.color = 'var(--text-secondary)' }}
                >
                  {ackingId === alert.id ? '...' : 'ACQUITTER'}
                </button>
              ) : (
                <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>—</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginTop: 16 }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
            style={{
              padding: '6px 12px', background: 'var(--bg-card)',
              border: '1px solid var(--border)', borderRadius: 4,
              color: page === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
              cursor: page === 1 ? 'not-allowed' : 'pointer', fontSize: 11,
            }}>
            <ChevronLeft size={13} />
          </button>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {page} / {pages}
          </span>
          <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}
            style={{
              padding: '6px 12px', background: 'var(--bg-card)',
              border: '1px solid var(--border)', borderRadius: 4,
              color: page === pages ? 'var(--text-muted)' : 'var(--text-primary)',
              cursor: page === pages ? 'not-allowed' : 'pointer', fontSize: 11,
            }}>
            <ChevronRight size={13} />
          </button>
        </div>
      )}
    </div>
  )
}