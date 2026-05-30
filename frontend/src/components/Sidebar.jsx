import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, FileText, Bell, Shield,
  LogOut, Radio, ChevronRight, Lock
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard',  roles: ['admin','analyst','viewer'] },
  { to: '/analyze',   icon: Shield,          label: 'Analyser',   roles: ['admin','analyst'] },
  { to: '/logs',      icon: FileText,         label: 'Logs',       roles: ['admin','analyst','viewer'] },
  { to: '/alerts',    icon: Bell,             label: 'Alertes',    roles: ['admin','analyst','viewer'] },
]

const ROLE_COLOR = { admin: '#a855f7', analyst: '#00d4ff', viewer: '#00ff88' }

export default function Sidebar({ wsConnected, alertCount }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate('/login') }

  return (
    <aside style={{
      width: 220,
      minHeight: '100vh',
      background: 'var(--bg-deep)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      flexShrink: 0,
      position: 'relative',
      zIndex: 10,
    }}>
      {/* ── Logo ── */}
      <div style={{
        padding: '28px 20px 20px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <div style={{
            width: 32, height: 32,
            border: '2px solid var(--accent-cyan)',
            borderRadius: 6,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            position: 'relative',
          }}>
            <Shield size={16} style={{ color: 'var(--accent-cyan)' }} />
            <span style={{
              position: 'absolute', top: -4, right: -4,
              width: 8, height: 8,
              borderRadius: '50%',
              background: wsConnected ? 'var(--accent-green)' : 'var(--high)',
              border: '1px solid var(--bg-deep)',
              animation: wsConnected ? 'pulse-dot 1.5s infinite' : 'none',
            }} />
          </div>
          <div>
            <div style={{
              fontFamily: 'var(--font-display)',
              fontWeight: 800,
              fontSize: 15,
              letterSpacing: '0.05em',
              color: 'var(--text-primary)',
            }}>SOC v2.0</div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.15em' }}>
              SECURITY OPS
            </div>
          </div>
        </div>

        {/* WS status */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 8px',
          background: wsConnected ? 'rgba(0,255,136,0.05)' : 'rgba(255,59,92,0.05)',
          border: `1px solid ${wsConnected ? 'rgba(0,255,136,0.2)' : 'rgba(255,59,92,0.2)'}`,
          borderRadius: 4,
          marginTop: 12,
        }}>
          <Radio size={10} style={{ color: wsConnected ? 'var(--low)' : 'var(--high)' }} />
          <span style={{ fontSize: 10, color: wsConnected ? 'var(--low)' : 'var(--high)', letterSpacing: '0.1em' }}>
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </span>
          {alertCount > 0 && (
            <span style={{
              marginLeft: 'auto',
              background: 'var(--high)',
              color: '#fff',
              fontSize: 9,
              fontWeight: 700,
              padding: '1px 5px',
              borderRadius: 99,
            }}>{alertCount}</span>
          )}
        </div>
      </div>

      {/* ── Nav ── */}
      <nav style={{ flex: 1, padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {NAV.map(({ to, icon: Icon, label, roles }) => {
          const allowed = user && roles.includes(user.role)
          return (
            <NavLink key={to} to={allowed ? to : '#'}
              style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 10px',
                borderRadius: 6,
                textDecoration: 'none',
                fontSize: 12,
                letterSpacing: '0.05em',
                fontWeight: isActive ? 700 : 400,
                color: !allowed ? 'var(--text-muted)'
                      : isActive ? 'var(--accent-cyan)'
                      : 'var(--text-secondary)',
                background: isActive ? 'rgba(0,212,255,0.08)' : 'transparent',
                border: isActive ? '1px solid rgba(0,212,255,0.15)' : '1px solid transparent',
                transition: 'all 0.15s',
                cursor: allowed ? 'pointer' : 'not-allowed',
                opacity: allowed ? 1 : 0.45,
              })}>
              {allowed ? <Icon size={15} /> : <Lock size={13} />}
              {label}
              {to === '/alerts' && alertCount > 0 && allowed && (
                <span style={{
                  marginLeft: 'auto', background: 'var(--high)',
                  color: '#fff', fontSize: 9, fontWeight: 700,
                  padding: '1px 5px', borderRadius: 99,
                }}>{alertCount}</span>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* ── User ── */}
      <div style={{
        padding: '14px 16px',
        borderTop: '1px solid var(--border)',
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '8px 10px',
          background: 'var(--bg-surface)',
          borderRadius: 6,
          border: '1px solid var(--border)',
          marginBottom: 8,
        }}>
          <div style={{
            width: 28, height: 28,
            borderRadius: 4,
            background: ROLE_COLOR[user?.role] + '22',
            border: `1px solid ${ROLE_COLOR[user?.role] || '#666'}55`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 700,
            color: ROLE_COLOR[user?.role],
            letterSpacing: '0.05em',
          }}>
            {user?.role?.[0]?.toUpperCase()}
          </div>
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <div style={{ fontSize: 11, color: 'var(--text-primary)', fontWeight: 700, letterSpacing: '0.03em' }}>
              {user?.role?.toUpperCase()}
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              ID #{user?.id}
            </div>
          </div>
        </div>

        <button onClick={handleLogout} style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 10px',
          background: 'transparent',
          border: '1px solid var(--border)',
          borderRadius: 6,
          color: 'var(--text-muted)',
          cursor: 'pointer', fontSize: 11,
          letterSpacing: '0.05em',
          transition: 'all 0.15s',
        }}
          onMouseEnter={e => { e.target.style.color = 'var(--high)'; e.target.style.borderColor = 'rgba(255,59,92,0.3)' }}
          onMouseLeave={e => { e.target.style.color = 'var(--text-muted)'; e.target.style.borderColor = 'var(--border)' }}
        >
          <LogOut size={13} /> DÉCONNEXION
        </button>
      </div>
    </aside>
  )
}