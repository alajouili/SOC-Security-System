import React, { useState } from 'react'
import { Send, AlertTriangle, CheckCircle, Zap, Info } from 'lucide-react'
import { analyzeApi } from '../services/api'
import LevelBadge from '../components/LevelBadge'
import ScoreBar from '../components/ScoreBar'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

const PRESETS = [
  {
    label: 'Normal', color: 'var(--low)',
    data: { ip: '10.0.1.42', endpoint: '/api/products', method: 'GET', status_code: 200, requests_per_minute: 12, response_time: 145, user_agent: 'Mozilla/5.0 Chrome/120.0', timestamp: new Date().toISOString() },
  },
  {
    label: 'SQLi + Brute', color: 'var(--high)',
    data: { ip: '185.220.101.42', endpoint: "/login?user=admin'--", method: 'POST', status_code: 401, requests_per_minute: 250, response_time: 35, user_agent: 'sqlmap/1.7.8#stable', timestamp: new Date().toISOString() },
  },
  {
    label: 'XSS', color: 'var(--medium)',
    data: { ip: '94.102.49.190', endpoint: '/search?q=<script>alert(1)</script>', method: 'GET', status_code: 200, requests_per_minute: 30, response_time: 80, user_agent: 'Mozilla/5.0', timestamp: new Date().toISOString() },
  },
  {
    label: 'SSRF', color: 'var(--high)',
    data: { ip: '45.33.32.156', endpoint: '/api/fetch?url=http://169.254.169.254/latest/meta-data/', method: 'GET', status_code: 403, requests_per_minute: 5, response_time: 2000, user_agent: 'python-requests/2.31.0', timestamp: new Date().toISOString() },
  },
]

const FieldLabel = ({ children }) => (
  <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: 5, textTransform: 'uppercase' }}>
    {children}
  </div>
)

const Input = ({ value, onChange, ...props }) => (
  <input value={value} onChange={onChange}
    style={{
      width: '100%', background: 'var(--bg-surface)',
      border: '1px solid var(--border)', borderRadius: 4,
      padding: '9px 12px', color: 'var(--text-primary)',
      fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none',
      transition: 'border-color 0.15s',
    }}
    onFocus={e => e.target.style.borderColor = 'var(--accent-cyan)'}
    onBlur={e => e.target.style.borderColor = 'var(--border)'}
    {...props} />
)

export default function Analyze() {
  const [form, setForm] = useState({
    ip: '', endpoint: '', method: 'GET', status_code: 200,
    requests_per_minute: 10, response_time: 100,
    user_agent: 'Mozilla/5.0', timestamp: new Date().toISOString(),
  })
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState('')

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target?.value ?? e }))

  const applyPreset = (preset) => {
    setForm(preset.data)
    setResult(null)
    setError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const payload = {
        ...form,
        status_code: Number(form.status_code),
        requests_per_minute: Number(form.requests_per_minute),
        response_time: Number(form.response_time),
      }
      const { data } = await analyzeApi.analyze(payload)
      setResult(data)
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail) ? detail.map(d => d.msg).join(', ') : detail || 'Erreur d\'analyse')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '28px 28px' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{
          fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 800,
          letterSpacing: '0.04em', color: 'var(--text-primary)', marginBottom: 4,
        }}>Analyser un log</h1>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
          Soumettre manuellement un log au pipeline IA · Résultat en &lt; 200ms
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', gap: 20, alignItems: 'flex-start' }}>
        {/* Form */}
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: 24,
        }}>
          {/* Presets */}
          <div style={{ marginBottom: 22 }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: 10 }}>
              SCÉNARIOS PRÉDÉFINIS
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {PRESETS.map((p) => (
                <button key={p.label} onClick={() => applyPreset(p)}
                  style={{
                    padding: '5px 12px',
                    background: 'transparent',
                    border: `1px solid ${p.color}44`,
                    borderRadius: 4,
                    color: p.color,
                    cursor: 'pointer', fontSize: 10,
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '0.08em',
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = p.color + '15'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleSubmit}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <div>
                <FieldLabel>Adresse IP *</FieldLabel>
                <Input value={form.ip} onChange={set('ip')} placeholder="192.168.1.1" required />
              </div>
              <div>
                <FieldLabel>Méthode HTTP *</FieldLabel>
                <select value={form.method} onChange={set('method')} style={{
                  width: '100%', background: 'var(--bg-surface)',
                  border: '1px solid var(--border)', borderRadius: 4,
                  padding: '9px 12px', color: 'var(--text-primary)',
                  fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none',
                }}>
                  {METHODS.map(m => <option key={m}>{m}</option>)}
                </select>
              </div>
              <div style={{ gridColumn: '1/-1' }}>
                <FieldLabel>Endpoint *</FieldLabel>
                <Input value={form.endpoint} onChange={set('endpoint')} placeholder="/api/users" required />
              </div>
              <div>
                <FieldLabel>Code HTTP *</FieldLabel>
                <Input value={form.status_code} onChange={set('status_code')} type="number" min="100" max="599" required />
              </div>
              <div>
                <FieldLabel>Req/min *</FieldLabel>
                <Input value={form.requests_per_minute} onChange={set('requests_per_minute')} type="number" min="0" max="10000" required />
              </div>
              <div>
                <FieldLabel>Temps réponse (ms) *</FieldLabel>
                <Input value={form.response_time} onChange={set('response_time')} type="number" min="0" required />
              </div>
              <div>
                <FieldLabel>User-Agent *</FieldLabel>
                <Input value={form.user_agent} onChange={set('user_agent')} required />
              </div>
              <div style={{ gridColumn: '1/-1' }}>
                <FieldLabel>Timestamp (ISO 8601 UTC) *</FieldLabel>
                <Input value={form.timestamp} onChange={set('timestamp')}
                  placeholder="2026-01-01T10:00:00Z" required />
              </div>
            </div>

            {error && (
              <div style={{
                display: 'flex', alignItems: 'flex-start', gap: 8,
                padding: '10px 12px', marginTop: 14,
                background: 'rgba(255,59,92,0.08)',
                border: '1px solid rgba(255,59,92,0.3)',
                borderRadius: 4, color: 'var(--high)', fontSize: 11,
              }}>
                <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                {error}
              </div>
            )}

            <button type="submit" disabled={loading}
              style={{
                width: '100%', marginTop: 18,
                padding: '12px 0',
                background: loading ? 'var(--bg-surface)' : 'var(--accent-cyan)',
                border: 'none', borderRadius: 5,
                color: loading ? 'var(--text-muted)' : 'var(--bg-void)',
                fontSize: 12, fontWeight: 700,
                letterSpacing: '0.15em', cursor: loading ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-mono)',
                boxShadow: loading ? 'none' : '0 0 20px rgba(0,212,255,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                transition: 'all 0.15s',
              }}>
              <Zap size={14} />
              {loading ? 'ANALYSE EN COURS...' : 'LANCER L\'ANALYSE'}
            </button>
          </form>
        </div>

        {/* Result */}
        <div>
          {!result && !loading && (
            <div style={{
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 8, padding: 28, textAlign: 'center',
            }}>
              <div style={{
                width: 48, height: 48, margin: '0 auto 14px',
                border: '1px solid var(--border)',
                borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Info size={22} style={{ color: 'var(--text-muted)' }} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                Soumettez un log pour voir<br />le résultat de l'analyse ML
              </div>
            </div>
          )}

          {loading && (
            <div style={{
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 8, padding: 40, textAlign: 'center',
            }}>
              <div style={{ fontSize: 11, color: 'var(--accent-cyan)', letterSpacing: '0.2em', marginBottom: 14 }}>
                ANALYSE EN COURS...
              </div>
              <div style={{
                width: '100%', height: 2, background: 'var(--border)',
                borderRadius: 1, overflow: 'hidden',
              }}>
                <div style={{
                  width: '40%', height: '100%',
                  background: 'var(--accent-cyan)',
                  animation: 'glow-pulse 0.8s infinite',
                  borderRadius: 1,
                }} />
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 10 }}>
                Pipeline ML · Isolation Forest · Scoring
              </div>
            </div>
          )}

          {result && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Score principal */}
              <div style={{
                background: 'var(--bg-card)',
                border: `1px solid ${result.risk_level === 'HIGH' ? 'var(--high)' : result.risk_level === 'MEDIUM' ? 'var(--medium)' : 'var(--low)'}44`,
                borderRadius: 8, padding: 20,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  {result.is_anomaly
                    ? <AlertTriangle size={20} style={{ color: 'var(--high)' }} />
                    : <CheckCircle size={20} style={{ color: 'var(--low)' }} />}
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: 2 }}>
                      RÉSULTAT D'ANALYSE
                    </div>
                    <LevelBadge level={result.risk_level} size="lg" />
                  </div>
                  <div style={{
                    marginLeft: 'auto',
                    fontFamily: 'var(--font-display)',
                    fontSize: 42, fontWeight: 800,
                    color: result.risk_level === 'HIGH' ? 'var(--high)'
                         : result.risk_level === 'MEDIUM' ? 'var(--medium)'
                         : 'var(--low)',
                    letterSpacing: '-0.03em',
                  }}>{Math.round(result.risk_score)}</div>
                </div>

                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 6 }}>RISK SCORE</div>
                  <ScoreBar score={result.risk_score} />
                </div>

                {result.techniques?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: 8 }}>TECHNIQUES DÉTECTÉES</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {result.techniques.map(t => (
                        <span key={t} style={{
                          padding: '3px 10px',
                          background: 'rgba(255,59,92,0.1)',
                          border: '1px solid rgba(255,59,92,0.3)',
                          borderRadius: 3, color: 'var(--high)',
                          fontSize: 10, letterSpacing: '0.06em',
                        }}>{t.replace(/_/g, ' ')}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Score breakdown */}
              <div style={{
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: 8, padding: 18,
              }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: 12 }}>
                  DÉTAIL DU SCORE
                </div>
                {Object.entries(result.score_breakdown || {}).map(([key, val]) => (
                  <div key={key} style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    marginBottom: 8,
                  }}>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', width: 160, flexShrink: 0 }}>
                      {key.replace(/_/g, ' ')}
                    </span>
                    <div style={{
                      flex: 1, height: 4, background: 'var(--bg-surface)',
                      borderRadius: 2, overflow: 'hidden',
                    }}>
                      <div style={{
                        width: `${(val / 20) * 100}%`, height: '100%',
                        background: val > 0 ? 'var(--accent-cyan)' : 'transparent',
                        borderRadius: 2,
                      }} />
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 700, color: val > 0 ? 'var(--accent-cyan)' : 'var(--text-muted)', minWidth: 28, textAlign: 'right' }}>
                      +{val}
                    </span>
                  </div>
                ))}
              </div>

              {/* Perf info */}
              <div style={{
                display: 'flex', gap: 10,
                padding: '10px 14px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)', borderRadius: 6,
                fontSize: 10, color: 'var(--text-muted)',
              }}>
                <span>ML: <strong style={{ color: 'var(--accent-cyan)' }}>{result.inference_time_ms}ms</strong></span>
                <span style={{ color: 'var(--border)' }}>|</span>
                <span>Total: <strong style={{ color: 'var(--accent-cyan)' }}>{result.total_latency_ms}ms</strong></span>
                {result.owasp_ref && <>
                  <span style={{ color: 'var(--border)' }}>|</span>
                  <span>OWASP: <strong style={{ color: 'var(--accent-amber)' }}>{result.owasp_ref}</strong></span>
                </>}
                {result.alert_id && <>
                  <span style={{ color: 'var(--border)' }}>|</span>
                  <span>Alerte <strong style={{ color: 'var(--high)' }}>#{result.alert_id}</strong> créée</span>
                </>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}