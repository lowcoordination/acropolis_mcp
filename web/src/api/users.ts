import { api } from './client'
import type { CurrentUserResponse, OidcStatusResponse, Role, UserCreateRequest, UserResponse } from './types'

export const usersApi = {
  list: () => api.get<UserResponse[]>('/users'),
  create: (body: UserCreateRequest) => api.post<UserResponse>('/users', body),
  setRole: (id: number, role: Role) => api.patchJson<UserResponse>(`/users/${id}/role`, { role }),
  setEnabled: (id: number, enabled: boolean) => api.patchJson<UserResponse>(`/users/${id}/enabled`, { enabled }),
}

export const meApi = {
  get: () => api.get<CurrentUserResponse>('/me'),
}

export const oidcApi = {
  status: () => api.get<OidcStatusResponse>('/auth/oidc/status'),
}
