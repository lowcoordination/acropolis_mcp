import { api } from './client'
import type { KeyCreatedResponse, KeyResponse, QuotaPeriod } from './types'

export interface QuotaFields {
  quota_calls?: number | null
  quota_period?: QuotaPeriod | null
}

export const keysApi = {
  list: (projectId?: number) =>
    api.get<KeyResponse[]>(`/keys${projectId != null ? `?project_id=${projectId}` : ''}`),
  create: (name: string, server_scopes?: string[], quota?: QuotaFields, project_slug?: string) =>
    api.post<KeyCreatedResponse>('/keys', { name, server_scopes, project_slug, ...quota }),
  setEnabled: (id: number, enabled: boolean) =>
    api.patch<KeyResponse>(`/keys/${id}`, { enabled: String(enabled) }),
  setQuota: (id: number, quota: QuotaFields) =>
    api.patchJson<KeyResponse>(`/keys/${id}/quota`, quota),
  delete: (id: number) => api.delete<void>(`/keys/${id}`),
}
