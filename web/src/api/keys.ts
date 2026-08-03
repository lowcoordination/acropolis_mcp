import { api } from './client'
import type { KeyCreatedResponse, KeyResponse } from './types'

export const keysApi = {
  list: () => api.get<KeyResponse[]>('/keys'),
  create: (name: string, server_scopes?: string[]) =>
    api.post<KeyCreatedResponse>('/keys', { name, server_scopes }),
  setEnabled: (id: number, enabled: boolean) =>
    api.patch<KeyResponse>(`/keys/${id}`, { enabled: String(enabled) }),
  delete: (id: number) => api.delete<void>(`/keys/${id}`),
}
