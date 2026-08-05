import { api } from './client'
import type { AuditEvent, StatsResponse } from './types'

export interface AuditQuery {
  server_slug?: string
  decision?: string
  tool?: string
  before_id?: number
  limit?: number
  api_key_id?: number
  after?: string
  before?: string
  search?: string
}

// Filters shared between the history query and the CSV export — before_id/limit are
// pagination controls, not filters, so they're excluded from the export querystring.
type AuditFilters = Omit<AuditQuery, 'before_id' | 'limit'>

function filtersToQueryString(params: AuditFilters): string {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') qs.set(key, String(value))
  }
  return qs.toString()
}

export const auditApi = {
  query: (params: AuditQuery = {}) => {
    const qs = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) qs.set(key, String(value))
    }
    const suffix = qs.toString() ? `?${qs}` : ''
    return api.get<AuditEvent[]>(`/audit${suffix}`)
  },
  stats: () => api.get<StatsResponse>('/stats'),
  // Not fetched through the API client — the browser handles the download (and its
  // Content-Disposition attachment header) natively via a plain <a href>.
  exportCsvUrl: (params: AuditFilters = {}) => {
    const qs = filtersToQueryString(params)
    return `/api/v1/audit/export.csv${qs ? `?${qs}` : ''}`
  },
}
