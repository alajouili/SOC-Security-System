import React, { useEffect, useState } from 'react'
import { AlertTriangle, X, ChevronRight } from 'lucide-react'
import { levelColor, levelBg } from '../utils/format'

export default function AlertToast({ alert, onDismiss }) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true))
    const timer = setTimeout(() => {
      setVisible(false)
      setTimeout(onDismiss, 350)
    }, 6000)
    return () => clearTimeout(timer)
  }, [onDismiss])

  const color = levelColor(alert.level)

  return (
    <div style={{
      width: 340,
      background: 'var(--bg-elevated)',
      border: `1px solid ${color}44`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 6,
      padding: '12px 14px',
      boxShadow: `0 4px 24px rgba(0,0,0,0.6), 0 0 20px ${color}22`,
      transform: visible ? 'translateX(0)' : 'translateX(110%)',
      opacity: visible ? 1 : 0,
      transition: 'all 0.35s cubic-bezier(.22,1,.36,1)',
      cursor: 'pointer',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Scanline accent */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 1,
        background: `linear-gradient(90deg, transparent, ${color}88, transparent)`,
      }} />

      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <AlertTriangle size={16} style={{ color, flexShrink: 0, marginTop: 1 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{
              fontSize: 10, fontWeight: 700, letterSpacing: '0.15em',
              color, padding: '1px 6px',
              background: levelBg(alert.level),
              border: `1px solid ${color}33`,
              borderRadius: 3,
            }}>{alert.level}</span>
            {alert.owasp_ref && (
              <span style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
                {alert.owasp_ref}
              </span>
            )}
            <span style={{
              fontSize: 18, fontWeight: 700, color,
              marginLeft: 'auto', letterSpacing: '-0.02em',
            }}>{Math.round(alert.score)}</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.4, marginBottom: 6 }}>
            {alert.message}
          </div>
          {alert.techniques?.length > 0 && (
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {alert.techniques.slice(0, 3).map((t) => (
                <span key={t} style={{
                  fontSize: 9, padding: '1px 5px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderRadius: 3, color: 'var(--text-muted)',
                  letterSpacing: '0.05em',
                }}>{t.replace('_', ' ')}</span>
              ))}
            </div>
          )}
        </div>
        <button onClick={(e) => { e.stopPropagation(); setVisible(false); setTimeout(onDismiss, 350) }}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 2,
            flexShrink: 0,
          }}>
          <X size={12} />
        </button>
      </div>
    </div>
  )
}

export function ToastContainer({ alerts, onDismiss }) {
  return (
    <div style={{
      position: 'fixed', top: 20, right: 20,
      display: 'flex', flexDirection: 'column', gap: 10,
      zIndex: 1000, maxHeight: 'calc(100vh - 40px)',
      overflow: 'hidden',
    }}>
      {alerts.slice(0, 5).map((alert) => (
        <AlertToast key={alert.id} alert={alert} onDismiss={() => onDismiss(alert.id)} />
      ))}
    </div>
  )
}