import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, Terminal, AlertCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const INPUT_STYLE = {
  width: '100%',
  background: 'var(--bg-surface)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  padding: '10px 14px',
  color: 'var(--text-primary)',
  fontSize: 13,
  fontFamily: 'var(--font-mono)',
  outline: 'none',
  transition: 'border-color 0.15s',
}

function Field({ label, type, value, onChange, placeholder }) {
  const [show, setShow] = useState(false)
  const isPassword = type === 'password'
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
        {label}
      </label>
      <div style={{ position: 'relative' }}>
        <input
          type={isPassword && !show ? 'password' : 'text'}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          style={INPUT_STYLE}
          onFocus={e => e.target.style.borderColor = 'var(--accent-cyan)'}
          onBlur={e => e.target.style.borderColor = 'var(--border)'}
        />
        {isPassword && (
          <button type="button" onClick={() => setShow(s => !s)}
            style={{
              position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', display: 'flex',
            }}>
            {show ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        )}
      </div>
    </div>
  )
}

export default function Login() {
  const { login, register } = useAuth()
  const navigate            = useNavigate()
  const [mode, setMode]     = useState('login')
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')
  const [form, setForm]     = useState({ username: '', email: '', password: '' })

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'login') {
        await login(form.email, form.password)
        navigate('/dashboard')
      } else {
        await register(form.username, form.email, form.password)
        await login(form.email, form.password)
        navigate('/dashboard')
      }
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail)
        ? detail.map(d => d.msg).join(', ')
        : detail || 'Erreur de connexion')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-void)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Grid background */}
      <div className="grid-bg" style={{
        position: 'absolute', inset: 0, opacity: 0.3,
      }} />

      {/* Radial glow */}
      <div style={{
        position: 'absolute',
        width: 500, height: 500,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 70%)',
        top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        pointerEvents: 'none',
      }} />

      <div style={{
        width: 400,
        position: 'relative',
        animation: 'slide-in-up 0.4s cubic-bezier(.22,1,.36,1) both',
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            width: 52, height: 52,
            margin: '0 auto 16px',
            border: '2px solid var(--accent-cyan)',
            borderRadius: 12,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            position: 'relative',
            boxShadow: '0 0 30px rgba(0,212,255,0.25)',
          }}>
            <Shield size={24} style={{ color: 'var(--accent-cyan)' }} />
            <span style={{
              position: 'absolute', top: -5, right: -5,
              width: 10, height: 10, borderRadius: '50%',
              background: 'var(--accent-green)',
              border: '2px solid var(--bg-void)',
              animation: 'pulse-dot 1.5s infinite',
            }} />
          </div>
          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: 26, fontWeight: 800,
            letterSpacing: '0.06em',
            color: 'var(--text-primary)',
            marginBottom: 4,
          }}>SOC v2.0</h1>
          <p style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.2em' }}>
            SECURITY OPERATIONS CENTER
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          padding: 28,
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        }}>
          {/* Mode toggle */}
          <div style={{
            display: 'flex',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            padding: 3,
            marginBottom: 24,
            gap: 3,
          }}>
            {['login', 'register'].map(m => (
              <button key={m} onClick={() => { setMode(m); setError('') }}
                style={{
                  flex: 1, padding: '7px 0',
                  background: mode === m ? 'var(--bg-elevated)' : 'transparent',
                  border: mode === m ? '1px solid var(--border-bright)' : '1px solid transparent',
                  borderRadius: 4,
                  color: mode === m ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  fontSize: 10, fontWeight: mode === m ? 700 : 400,
                  letterSpacing: '0.12em', cursor: 'pointer',
                  fontFamily: 'var(--font-mono)',
                  transition: 'all 0.15s',
                }}>
                {m === 'login' ? 'CONNEXION' : 'CRÉER UN COMPTE'}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit}>
            {mode === 'register' && (
              <Field label="IDENTIFIANT" type="text" value={form.username}
                onChange={set('username')} placeholder="alice_admin" />
            )}
            <Field label="EMAIL" type="text" value={form.email}
              onChange={set('email')} placeholder="admin@soc.internal" />
            <Field label="MOT DE PASSE" type="password" value={form.password}
              onChange={set('password')} placeholder={mode === 'register' ? 'Min. 12 car., maj, chiffre, spécial' : '••••••••••••'} />

            {error && (
              <div style={{
                display: 'flex', alignItems: 'flex-start', gap: 8,
                padding: '10px 12px',
                background: 'rgba(255,59,92,0.08)',
                border: '1px solid rgba(255,59,92,0.3)',
                borderRadius: 4,
                marginBottom: 16,
                color: 'var(--high)',
                fontSize: 11,
              }}>
                <AlertCircle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                {error}
              </div>
            )}

            <button type="submit" disabled={loading}
              style={{
                width: '100%',
                padding: '11px 0',
                background: loading ? 'var(--bg-surface)' : 'var(--accent-cyan)',
                border: 'none',
                borderRadius: 5,
                color: loading ? 'var(--text-muted)' : 'var(--bg-void)',
                fontSize: 12, fontWeight: 700,
                letterSpacing: '0.15em',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-mono)',
                transition: 'all 0.15s',
                boxShadow: loading ? 'none' : '0 0 20px rgba(0,212,255,0.35)',
              }}>
              {loading ? 'AUTHENTIFICATION...' : mode === 'login' ? 'ACCÉDER AU SOC' : 'CRÉER LE COMPTE'}
            </button>
          </form>
        </div>

        {/* Footer hint */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center',
          marginTop: 20, color: 'var(--text-muted)', fontSize: 10, letterSpacing: '0.1em',
        }}>
          <Terminal size={11} />
          <span>OWASP Top 10 2021 · JWT RS256 · bcrypt cost=12</span>
        </div>
      </div>
    </div>
  )
}