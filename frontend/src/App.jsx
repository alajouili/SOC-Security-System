import React, { useState, useCallback } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { useWebSocket } from './hooks/useWebSocket'
import Sidebar from './components/Sidebar'
import { ToastContainer } from './components/AlertToast'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Logs from './pages/Logs'
import Alerts from './pages/Alerts'
import Analyze from './pages/Analyze'

// ── Protected route wrapper ─────────────────────────────────────────────────
function ProtectedRoute({ children, roles }) {
  const { user, loading } = useAuth()

  if (loading) return (
    <div style={{
      flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-void)', color: 'var(--text-muted)',
      fontSize: 11, letterSpacing: '0.2em',
    }}>
      INITIALISATION...
    </div>
  )

  if (!user) return <Navigate to="/login" replace />
  if (roles && !roles.includes(user.role)) return <Navigate to="/dashboard" replace />
  return children
}

// ── Main app layout with sidebar ───────────────────────────────────────────
function AppLayout() {
  const { alerts, connected, lastAlert, clearAlerts } = useWebSocket()
  const [toasts, setToasts] = useState([])

  // When a new live alert arrives, add it as a toast
  React.useEffect(() => {
    if (lastAlert) {
      setToasts(prev => [lastAlert, ...prev].slice(0, 5))
    }
  }, [lastAlert])

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(a => a.id !== id))
  }, [])

  const unackedCount = alerts.filter(a => a.level === 'HIGH').length

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-void)' }}>
      <Sidebar wsConnected={connected} alertCount={unackedCount} />

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
        <Routes>
          <Route path="/dashboard" element={
            <ProtectedRoute>
              <Dashboard liveAlerts={alerts} />
            </ProtectedRoute>
          } />
          <Route path="/analyze" element={
            <ProtectedRoute roles={['admin', 'analyst']}>
              <Analyze />
            </ProtectedRoute>
          } />
          <Route path="/logs" element={
            <ProtectedRoute>
              <Logs />
            </ProtectedRoute>
          } />
          <Route path="/alerts" element={
            <ProtectedRoute>
              <Alerts liveAlerts={alerts} />
            </ProtectedRoute>
          } />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>

      {/* Live alert toasts */}
      <ToastContainer alerts={toasts} onDismiss={dismissToast} />
    </div>
  )
}

// ── Root ────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
          <Route path="/*" element={<AppLayout />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

function PublicRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return null
  if (user) return <Navigate to="/dashboard" replace />
  return children
}