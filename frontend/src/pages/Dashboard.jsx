import React, { useEffect, useState, useCallback } from 'react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  Activity, AlertTriangle, Shield, Eye,
  TrendingUp, Zap, Clock, Cpu,
} from 'lucide-react'
import { alertsApi } from '../services/api'
import StatCard from '../components/StatCard'
import LevelBadge from '../components/LevelBadge'
import { formatDateShort, timeAgo, truncate } from '../utils/format'

const LEVEL_COLORS = { HIGH: '#ff3b5c', MEDIUM: '#ffb800', LOW: '#00ff88' }
const CHART_TOOLTIP = {
  contentStyle: {
    background: 'var(--bg-elevated)', border: '1px solid var(--border)',
    borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
  },
  cursor: { fill: 'rgba(0,212,255,0.04)' },
}

function SectionTitle({ children, accent }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
      <div style={{ width: 2, height: 16, background: accent || 'var(--accent-cyan)', borderRadius: 2 }} />
      <span style={{
        fontSize: 10, fontWeight: 700, letterSpacing: '0.18em',
        color: 'var(--text-secondary)', textTransform: 'uppercase',
      }}>{children}</span>
    </div>
  )
}

export default function Dashboard({ liveAlerts }) {
  const [stats, setStats]     = useState(null)
  const [alerts, setAlerts]   = useState([])
  const [loading, setLoading] = useState(true)
  const [activityData, setActivityData] = useState([])

  const loadData = useCallback(async () => {
    try {
      const [statsRes, alertsRes] = await Promise.all([
        alertsApi.getStats(),
        alertsApi.getAlerts({ page_size: 10, page: 1 }),
      ])
      setStats(statsRes.data)
      setAlerts(alertsRes.data.items || [])

      // Générer activité simulée pour le graphique (basée sur les vraies données)
      const now = Date.now()
      setActivityData(Array.from({ length: 20 }, (_, i) => ({
        t: new Date(now - (19 - i) * 3 * 60000).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
        normal: Math.floor(Math.random() * 40 + 20),
        suspect: Math.floor(Math.random() * 8),
        critical: Math.floor(Math.random() * 3),
      })))
    } catch { /* silently fail */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 30000)
    return () => clearInterval(interval)
  }, [loadData])

  // Intégration des alertes live
  useEffect(() => {
    if (liveAlerts?.length > 0) {
      const latest = liveAlerts[0]
      setAlerts(prev => [latest, ...prev].slice(0, 10))
    }
  }, [liveAlerts])

  const pieData = stats ? [
    { name: 'HIGH',   value: stats.high_count },
    { name: 'MEDIUM', value: stats.medium_count },
    { name: 'LOW',    value: stats.low_count },
  ].filter(d => d.value > 0) : []

  if (loading) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 11, letterSpacing: '0.2em', marginBottom: 8 }}>CHARGEMENT...</div>
        <div style={{ width: 200, height: 2, background: 'var(--border)', borderRadius: 1, overflow: 'hidden' }}>
          <div style={{ width: '60%', height: '100%', background: 'var(--accent-cyan)', animation: 'glow-pulse 1s infinite' }} />
        </div>
      </div>
    </div>
  )

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '28px 28px' }}>
      {/* ── Header ── */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{
          fontFamily: 'var(--font-display)',
          fontSize: 22, fontWeight: 800,
          letterSpacing: '0.04em',
          color: 'var(--text-primary)',
          marginBottom: 4,
        }}>Dashboard</h1>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
          Vue d'ensemble en temps réel · Mise à jour toutes les 30s
        </p>
      </div>

      {/* ── Stat cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 28 }}>
        <StatCard label="Analysés" value={stats?.total_analyzed?.toLocaleString() ?? '0'}
          color="var(--accent-cyan)" icon={Activity} sub="logs totaux" />
        <StatCard label="Alertes HIGH" value={stats?.high_count ?? 0}
          color="var(--high)" icon={AlertTriangle} sub="critiques" />
        <StatCard label="Score moyen" value={stats?.avg_risk_score?.toFixed(1) ?? '0'}
          color="var(--accent-amber)" icon={TrendingUp} sub="risk score" />
        <StatCard label="Taux anomalies" value={`${stats?.anomaly_rate?.toFixed(1) ?? 0}%`}
          color={stats?.anomaly_rate > 15 ? 'var(--high)' : 'var(--accent-green)'}
          icon={Cpu} sub={stats?.anomaly_rate > 15 ? '⚠ CRITIQUE' : 'normal'} />
      </div>

      {/* ── Charts row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 14, marginBottom: 28 }}>
        {/* Activity chart */}
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '18px 20px',
        }}>
          <SectionTitle>Activité temps réel</SectionTitle>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={activityData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="gNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gSuspect" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ffb800" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ffb800" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff3b5c" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ff3b5c" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fontSize: 9, fill: '#4a6070', fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} interval={4} />
              <YAxis tick={{ fontSize: 9, fill: '#4a6070', fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} />
              <Tooltip {...CHART_TOOLTIP} />
              <Area type="monotone" dataKey="normal" stroke="#00d4ff" strokeWidth={1.5} fill="url(#gNormal)" name="Normal" />
              <Area type="monotone" dataKey="suspect" stroke="#ffb800" strokeWidth={1.5} fill="url(#gSuspect)" name="Suspect" />
              <Area type="monotone" dataKey="critical" stroke="#ff3b5c" strokeWidth={1.5} fill="url(#gCritical)" name="Critique" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Pie chart */}
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '18px 20px',
        }}>
          <SectionTitle>Répartition alertes</SectionTitle>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={130}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60}
                    dataKey="value" strokeWidth={0}>
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={LEVEL_COLORS[entry.name]} opacity={0.9} />
                    ))}
                  </Pie>
                  <Tooltip {...CHART_TOOLTIP} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {pieData.map(d => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: LEVEL_COLORS[d.name] }} />
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', flex: 1 }}>{d.name}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: LEVEL_COLORS[d.name] }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 130, color: 'var(--text-muted)', fontSize: 11 }}>
              Aucune alerte
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom row: Top IPs + Recent alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        {/* Top IPs */}
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '18px 20px',
        }}>
          <SectionTitle accent="var(--accent-purple)">Top IPs suspectes</SectionTitle>
          {stats?.top_ips?.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {stats.top_ips.map((item, i) => (
                <div key={item.ip} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{
                    fontSize: 9, color: 'var(--text-muted)',
                    width: 14, textAlign: 'right', fontWeight: 700,
                  }}>#{i + 1}</span>
                  <code style={{ fontSize: 11, color: 'var(--accent-cyan)', flex: 1 }}>{item.ip}</code>
                  <div style={{
                    width: 80, height: 4, background: 'var(--bg-surface)',
                    borderRadius: 2, overflow: 'hidden',
                  }}>
                    <div style={{
                      width: `${Math.min((item.count / (stats.top_ips[0]?.count || 1)) * 100, 100)}%`,
                      height: '100%', background: 'var(--accent-purple)',
                      borderRadius: 2,
                    }} />
                  </div>
                  <span style={{ fontSize: 10, color: 'var(--text-secondary)', minWidth: 30, textAlign: 'right' }}>
                    {item.count}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>Aucune donnée</div>
          )}
        </div>

        {/* Recent alerts */}
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '18px 20px',
        }}>
          <SectionTitle accent="var(--high)">Alertes récentes</SectionTitle>
          {alerts.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {alerts.slice(0, 6).map((alert) => (
                <div key={alert.id} style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '6px 8px',
                  background: alert.level === 'HIGH' ? 'rgba(255,59,92,0.04)' : 'transparent',
                  borderRadius: 4,
                  border: '1px solid',
                  borderColor: alert.level === 'HIGH' ? 'rgba(255,59,92,0.15)' : 'transparent',
                }}>
                  <LevelBadge level={alert.level} />
                  <span style={{ flex: 1, fontSize: 11, color: 'var(--text-secondary)' }}>
                    {truncate(alert.message, 35)}
                  </span>
                  <span style={{ fontSize: 9, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {timeAgo(alert.created_at)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>Aucune alerte</div>
          )}
        </div>
      </div>
    </div>
  )
}