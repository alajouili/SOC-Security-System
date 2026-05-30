import React, { useEffect, useState, useCallback } from 'react'
import { Search, Filter, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { logsApi } from '../services/api'
import LevelBadge from '../components/LevelBadge'
import ScoreBar from '../components/ScoreBar'
import { formatDate, truncate } from '../utils/format'

const METHOD_COLOR = {
  GET: '#00d4ff', POST: '#a855f7', PUT: '#ffb800',
  DELETE: '#ff3b5c', PATCH: '#00ff88',
}

export default function Logs() {
  const [logs, setLogs]       = useState([])
  const [total, setTotal]     = useState(0)
  const [page, setPage]       = useState(1)
  const [pages, setPages]     = useState(1)
  const [loading, setLoading] = useState(true)
  const [ipFilter, setIpFilter]         = useState('')
  const [anomalyOnly, setAnomalyOnly]   = useState(false)
  const [minScore, setMinScore]         = useState('')
  const [expanded, setExpanded]         = useState(null)

  const loadLogs = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: 20 }
      if (ipFilter)    params.ip = ipFilter
      if (anomalyOnly) params.anomaly_only = true
      if (minScore)    params.min_score = Number(minScore)
      const { data } = await logsApi.getLogs(params)
      setLogs(data.items || [])
      setTotal(data.total || 0)
      setPages(data.pages || 1)
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [page, ipFilter, anomalyOnly, minScore])

  useEffect(() => { loadLogs() }, [loadLogs])

  const scoreLevel = (s) => s >= 71 ? 'HIGH' : s >= 31 ? 'MEDIUM' : 'LOW'

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '28px 28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{
            fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 800,
            letterSpacing: '0.04em', color: 'var(--text-primary)', marginBottom: 4,
          }}>Logs d'analyse</h1>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
            {total.toLocaleString()} entrée{total > 1 ? 's' : ''} enregistrée{total > 1 ? 's' : ''}
          </p>
        </div>
        <button onClick={loadLogs} style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '8px 14px', background: 'var(--bg-card)',
          border: '1px solid var(--border)', borderRadius: 5,
          color: 'var(--text-secondary)', cursor: 'pointer',
          fontSize: 11, fontFamily: 'var(--font-mono)', letterSpacing: '0.08em',
        }}>
          <RefreshCw size={12} /> Actualiser
        </button>
      </div>

      {/* Filters */}
      <div style={{
        display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap',
        padding: '14px 16px', background: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: 8, alignItems: 'center',
      }}>
        <Filter size={13} style={{ color: 'var(--text-muted)' }} />

        {/* IP filter */}
        <div style={{ position: 'relative' }}>
          <Search size={11} style={{
            position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)',
            color: 'var(--text-muted)',
          }} />
          <input placeholder="Filtrer par IP..."
            value={ipFilter}
            onChange={e => { setIpFilter(e.target.value); setPage(1) }}
            style={{
              background: 'var(--bg-surface)', border: '1px solid var(--border)',
              borderRadius: 4, color: 'var(--text-primary)',
              padding: '5px 10px 5px 26px', fontSize: 11,
              fontFamily: 'var(--font-mono)', outline: 'none', width: 160,
            }} />
        </div>

        {/* Min score */}
        <input placeholder="Score min (0-100)" type="number" min="0" max="100"
          value={minScore}
          onChange={e => { setMinScore(e.target.value); setPage(1) }}
          style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 4, color: 'var(--text-primary)',
            padding: '5px 10px', fontSize: 11,
            fontFamily: 'var(--font-mono)', outline: 'none', width: 150,
          }} />

        {/* Anomaly toggle */}
        <label style={{
          display: 'flex', alignItems: 'center', gap: 8,
          cursor: 'pointer', fontSize: 11, color: anomalyOnly ? 'var(--high)' : 'var(--text-muted)',
          padding: '5px 10px',
          background: anomalyOnly ? 'rgba(255,59,92,0.08)' : 'transparent',
          border: `1px solid ${anomalyOnly ? 'rgba(255,59,92,0.3)' : 'var(--border)'}`,
          borderRadius: 4,
          transition: 'all 0.15s',
        }}>
          <input type="checkbox" checked={anomalyOnly}
            onChange={e => { setAnomalyOnly(e.target.checked); setPage(1) }}
            style={{ accentColor: 'var(--high)' }} />
          Anomalies seulement
        </label>

        <div style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)' }}>
          Page {page}/{pages}
        </div>
      </div>

      {/* Table */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 8, overflow: 'hidden',
      }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '120px 60px 1fr 60px 110px 100px 80px',
          padding: '10px 16px',
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border)',
          fontSize: 9, letterSpacing: '0.15em',
          color: 'var(--text-muted)', textTransform: 'uppercase',
        }}>
          <span>IP</span><span>Méth.</span><span>Endpoint</span>
          <span>Status</span><span>Score</span><span>Timestamp</span><span>Anomalie</span>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11, letterSpacing: '0.1em' }}>
            CHARGEMENT...
          </div>
        ) : logs.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11 }}>
            Aucun log correspondant
          </div>
        ) : logs.map((log) => (
          <React.Fragment key={log.id}>
            <div
              onClick={() => setExpanded(expanded === log.id ? null : log.id)}
              style={{
                display: 'grid',
                gridTemplateColumns: '120px 60px 1fr 60px 110px 100px 80px',
                padding: '11px 16px',
                borderBottom: '1px solid var(--border)',
                alignItems: 'center',
                cursor: 'pointer',
                background: expanded === log.id ? 'var(--bg-elevated)' : 'transparent',
                transition: 'background 0.12s',
              }}>
              <code style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>{log.ip}</code>
              <span style={{
                fontSize: 10, fontWeight: 700,
                color: METHOD_COLOR[log.method] || 'var(--text-muted)',
              }}>{log.method}</span>
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                {truncate(log.endpoint, 45)}
              </span>
              <span style={{
                fontSize: 11, fontWeight: 700,
                color: log.status_code >= 400 ? 'var(--high)'
                    : log.status_code >= 300 ? 'var(--medium)'
                    : 'var(--low)',
              }}>{log.status_code}</span>
              <div style={{ width: 90 }}>
                <ScoreBar score={log.risk_score} />
              </div>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {formatDate(log.timestamp).split(' ').slice(0, 2).join(' ')}
              </span>
              <div>
                {log.anomaly
                  ? <LevelBadge level={scoreLevel(log.risk_score)} />
                  : <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>—</span>}
              </div>
            </div>

            {/* Expanded detail row */}
            {expanded === log.id && (
              <div style={{
                padding: '14px 16px',
                background: 'var(--bg-elevated)',
                borderBottom: '1px solid var(--border)',
                display: 'grid',
                gridTemplateColumns: 'repeat(4, 1fr)',
                gap: 16,
              }}>
                {[
                  ['RPM', log.requests_per_minute?.toFixed(1)],
                  ['Temps réponse', `${log.response_time?.toFixed(0)} ms`],
                  ['Timestamp complet', formatDate(log.timestamp)],
                  ['Log ID', `#${log.id}`],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 4 }}>{k}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-primary)' }}>{v}</div>
                  </div>
                ))}
              </div>
            )}
          </React.Fragment>
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
              cursor: page === 1 ? 'not-allowed' : 'pointer',
            }}>
            <ChevronLeft size={13} />
          </button>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{page} / {pages}</span>
          <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}
            style={{
              padding: '6px 12px', background: 'var(--bg-card)',
              border: '1px solid var(--border)', borderRadius: 4,
              color: page === pages ? 'var(--text-muted)' : 'var(--text-primary)',
              cursor: page === pages ? 'not-allowed' : 'pointer',
            }}>
            <ChevronRight size={13} />
          </button>
        </div>
      )}
    </div>
  )
}