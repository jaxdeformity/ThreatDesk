import { formatDistanceToNow, parseISO } from 'date-fns'

export function relTime(iso?: string | null): string {
  if (!iso) return ''
  try {
    return formatDistanceToNow(parseISO(iso), { addSuffix: true })
  } catch { return '' }
}

export function shortTs(iso?: string | null): string {
  if (!iso) return ''
  try {
    return parseISO(iso).toISOString().slice(11, 19)
  } catch { return '' }
}

export function bytes(n?: number): string {
  if (!n || n < 0) return ', '
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`
}

export function initials(label?: string): string {
  if (!label) return '??'
  return label.split(/[\s-_]+/).filter(Boolean)
    .slice(0, 2).map(s => s[0]?.toUpperCase() ?? '').join('') || '??'
}
