import React from 'react'

export default function StatCard({ label, value, sub, color, icon: Icon, trend }) {
  const c = color || 'var(--accent-cyan)'
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderTop: `2px solid ${c}`,
      borderRadius: 8,
      padding: '18px 20px',
      position: 'relative',
      overflow: 'hidden',
      transition: 'border-color 0.2s',
    }}
      onMouseEnter={e => e.currentTarget.style.borderColor = c}
      onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
    >
      {/* Glow */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 60,
        background: `radial-gradient(ellipse at top, ${c}10, transparent)`,
        pointerEvents: 'none',
      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', position: 'relative' }}>
        <div>
          <div style={{
            fontSize: 9, color: 'var(--text-muted)',
            letterSpacing: '0.18em', textTransform: 'uppercase',
            marginBottom: 10,
          }}>{label}</div>
          <div style={{
            fontSize: 32, fontWeight: 800,
            fontFamily: 'var(--font-display)',
            color: c, lineHeight: 1,
            letterSpacing: '-0.02em',
          }}>
            {value ?? '—'}
          </div>
          {sub && (
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6, letterSpacing: '0.05em' }}>
              {sub}
            </div>
          )}
          {trend !== undefined && (
            <div style={{
              fontSize: 10, marginTop: 6,
              color: trend > 0 ? 'var(--high)' : 'var(--low)',
            }}>
              {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}% / 5min
            </div>
          )}
        </div>
        {Icon && (
          <div style={{
            width: 36, height: 36,
            background: `${c}12`,
            border: `1px solid ${c}30`,
            borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Icon size={18} style={{ color: c }} />
          </div>
        )}
      </div>
    </div>
  )
}