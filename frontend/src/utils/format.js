export const formatDate = (dateStr) => {
  if (!dateStr) return '—'
  const d = new Date(dateStr)
  return d.toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export const formatDateShort = (dateStr) => {
  if (!dateStr) return '—'
  const d = new Date(dateStr)
  return d.toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

export const timeAgo = (dateStr) => {
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const diff = Math.floor((now - then) / 1000)
  if (diff < 60)   return `il y a ${diff}s`
  if (diff < 3600) return `il y a ${Math.floor(diff / 60)}min`
  if (diff < 86400)return `il y a ${Math.floor(diff / 3600)}h`
  return `il y a ${Math.floor(diff / 86400)}j`
}

export const levelColor = (level) => ({
  HIGH:   'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW:    'var(--low)',
}[level] || 'var(--text-muted)')

export const levelBg = (level) => ({
  HIGH:   'rgba(255,59,92,0.1)',
  MEDIUM: 'rgba(255,184,0,0.1)',
  LOW:    'rgba(0,255,136,0.1)',
}[level] || 'transparent')

export const truncate = (str, n = 40) =>
  str && str.length > n ? str.slice(0, n) + '…' : str || '—'

export const scoreColor = (score) => {
  if (score >= 71) return 'var(--high)'
  if (score >= 31) return 'var(--medium)'
  return 'var(--low)'
}