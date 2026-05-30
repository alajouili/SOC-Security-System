import React from 'react'
import { scoreColor } from '../utils/format'

export default function ScoreBar({ score }) {
  const pct   = Math.min(Math.max(score, 0), 100)
  const color = scoreColor(score)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{
        flex: 1, height: 4,
        background: 'var(--bg-surface)',
        borderRadius: 2, overflow: 'hidden',
      }}>
        <div style={{
          width: `${pct}%`, height: '100%',
          background: color,
          borderRadius: 2,
          boxShadow: `0 0 6px ${color}88`,
          transition: 'width 0.4s ease',
        }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color, minWidth: 28, textAlign: 'right' }}>
        {Math.round(score)}
      </span>
    </div>
  )
}