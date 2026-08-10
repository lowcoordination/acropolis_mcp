import { api } from './client'
import type { UsageResponse } from './types'

export interface UsageQuery {
  api_key_id?: number
  server_slug?: string
  tool?: string
  period?: 'day' | 'month' | 'all'
  // Enterprise #4: optional project filter — instance-wide (unfiltered) by default.
  project_id?: number
}

export const usageApi = {
  query: (params: UsageQuery = {}) => {
    const qs = new URLSearchParams()
    if (params.api_key_id !== undefined) qs.set('api_key_id', String(params.api_key_id))
    if (params.server_slug) qs.set('server_slug', params.server_slug)
    if (params.tool) qs.set('tool', params.tool)
    if (params.project_id !== undefined) qs.set('project_id', String(params.project_id))
    qs.set('period', params.period ?? 'day')
    const suffix = qs.toString() ? `?${qs.toString()}` : ''
    return api.get<UsageResponse>(`/usage${suffix}`)
  },
}
