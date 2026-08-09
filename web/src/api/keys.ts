import { api } from './client'
import type { KeyCreatedResponse, KeyResponse, QuotaPeriod } from './types'

export interface QuotaFields {
  quota_calls?: number | null
  quota_period?: QuotaPeriod | null
}

export const keysApi = {
  list: () => api.get<KeyResponse[]>('/keys'),
  create: (name: string, server_scopes?: string[], quota?: QuotaFields) =>
    api.post<KeyCreatedResponse>('/keys', { name, server_scopes, ...quota }),
  setEnabled: (id: number, enabled: boolean) =>
    api.patch<KeyResponse>(`/keys/${id}`, { enabled: String(enabled) }),
  setQuota: (id: number, quota: QuotaFields) =>
    api.patchJson<KeyResponse>(`/keys/${id}/quota`, quota),
  delete: (id: number) => api.delete<void>(`/keys/${id}`),
}
