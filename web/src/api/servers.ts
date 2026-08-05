import { api } from './client'
import type {
  PolicyResponse,
  ServerCreateRequest,
  ServerResponse,
  ServerToolsResponse,
  ServerUpdateRequest,
} from './types'

export const serversApi = {
  list: () => api.get<ServerResponse[]>('/servers'),
  get: (slug: string) => api.get<ServerResponse>(`/servers/${slug}`),
  create: (body: ServerCreateRequest) => api.post<ServerResponse>('/servers', body),
  update: (slug: string, body: ServerUpdateRequest) => api.put<ServerResponse>(`/servers/${slug}`, body),
  delete: (slug: string) => api.delete<void>(`/servers/${slug}`),
  getPolicy: (slug: string) => api.get<PolicyResponse>(`/servers/${slug}/policy`),
  setPolicy: (slug: string, body: PolicyResponse) => api.put<PolicyResponse>(`/servers/${slug}/policy`, body),
  getTools: (slug: string, opts?: { force_refresh?: boolean }) =>
    api.get<ServerToolsResponse>(
      `/servers/${slug}/tools${opts?.force_refresh ? '?force_refresh=true' : ''}`,
    ),
  probe: (slug: string) => api.post<ServerResponse>(`/servers/${slug}/probe`),
}
