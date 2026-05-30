import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authApi } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null)
  const [loading, setLoading] = useState(true)

  // Décoder le JWT sans librairie externe
  const decodeToken = (token) => {
    try {
      const payload = token.split('.')[1]
      const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
      return decoded
    } catch {
      return null
    }
  }

  const loadUserFromToken = useCallback(() => {
    const token = localStorage.getItem('access_token')
    if (!token) { setLoading(false); return }

    const payload = decodeToken(token)
    if (!payload) { localStorage.removeItem('access_token'); setLoading(false); return }

    // Vérifier expiration
    if (payload.exp * 1000 < Date.now()) {
      localStorage.removeItem('access_token')
      setLoading(false)
      return
    }

    setUser({ id: payload.sub, role: payload.role })
    setLoading(false)
  }, [])

  useEffect(() => { loadUserFromToken() }, [loadUserFromToken])

  const login = async (email, password) => {
    const { data } = await authApi.login({ email, password })
    localStorage.setItem('access_token', data.access_token)
    const payload = decodeToken(data.access_token)
    setUser({ id: payload.sub, role: payload.role })
    return payload.role
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    setUser(null)
  }

  const register = async (username, email, password) => {
    const { data } = await authApi.register({ username, email, password })
    return data
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}