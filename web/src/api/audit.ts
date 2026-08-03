import { api } from './client'
import type { AuditEvent, StatsResponse } from './types'

export interface AuditQuery {
  server_slug?: string
  decision?: string
  tool?: string
  before_id?: number
  limit?: number
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
}
