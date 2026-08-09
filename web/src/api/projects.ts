import { api } from './client'
import type {
  ProjectCreateRequest,
  ProjectMemberResponse,
  ProjectMemberUpsertRequest,
  ProjectResponse,
} from './types'

export const projectsApi = {
  list: () => api.get<ProjectResponse[]>('/projects'),
  create: (body: ProjectCreateRequest) => api.post<ProjectResponse>('/projects', body),
  delete: (slug: string) => api.delete<void>(`/projects/${slug}`),
  listMembers: (projectId: number) => api.get<ProjectMemberResponse[]>(`/projects/${projectId}/members`),
  upsertMember: (projectId: number, body: ProjectMemberUpsertRequest) =>
    api.put<ProjectMemberResponse>(`/projects/${projectId}/members`, body),
  removeMember: (projectId: number, userId: number) =>
    api.delete<void>(`/projects/${projectId}/members/${userId}`),
}
