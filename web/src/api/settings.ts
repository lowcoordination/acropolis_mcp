import { api } from './client'
import type { ConfigImportResponse, SettingsResponse, SetupStatusResponse } from './types'

export interface SettingsUpdateRequest {
  auth_mode?: 'open' | 'keyed'
  aggregate_enabled?: boolean
  default_ttl_ms?: number
  audit_retention_days?: number
}

export const settingsApi = {
  get: () => api.get<SettingsResponse>('/settings'),
  update: (body: SettingsUpdateRequest) => api.put<SettingsResponse>('/settings', body),
}

export const configApi = {
  // Plain href, not a fetch — let the browser handle the download and its
  // Content-Disposition, same approach as the audit CSV export.
  exportUrl: (includeCredentials = false) =>
    `/api/v1/config/export${includeCredentials ? '?include_credentials=true' : ''}`,
  import: (yamlText: string, apply: boolean) =>
    api.post<ConfigImportResponse>('/config/import', { yaml: yamlText, apply }),
}

export const setupApi = {
  status: () => api.get<SetupStatusResponse>('/setup/status'),
  complete: (admin_password: string, auth_mode: 'open' | 'keyed') =>
    api.post<SetupStatusResponse>('/setup', { admin_password, auth_mode }),
  login: (admin_password: string) => api.post<{ status: string }>('/login', { admin_password }),
  logout: () => api.post<{ status: string }>('/logout'),
}
