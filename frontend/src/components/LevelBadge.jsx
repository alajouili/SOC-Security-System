import React from 'react'

export default function LevelBadge({ level, size = 'sm' }) {
  const pad = size === 'lg' ? '4px 12px' : '2px 7px'
  const fs  = size === 'lg' ? 11 : 9
  return (
    <span className={`badge-${level}`} style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: pad, borderRadius: 3,
      fontSize: fs, fontWeight: 700,
      letterSpacing: '0.12em',
      border: '1px solid',
      fontFamily: 'var(--font-mono)',
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: 'currentColor',
        animation: level === 'HIGH' ? 'pulse-dot 1s infinite' : 'none',
      }} />
      {level}
    </span>
  )
}