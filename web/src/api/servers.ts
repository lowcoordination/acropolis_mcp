import { api } from './client'
import type {
  PolicyResponse,
  ServerCreateRequest,
  ServerResponse,
  ServerTool,
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
  getTools: (slug: string) => api.get<ServerTool[]>(`/servers/${slug}/tools`),
}
