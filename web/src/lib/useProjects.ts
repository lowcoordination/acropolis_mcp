import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { projectsApi } from '../api/projects'
import type { ProjectCreateRequest, ProjectMemberUpsertRequest, ProjectRole } from '../api/types'

export function useProjects() {
  return useQuery({
    queryKey: ['projects'],
    queryFn: () => projectsApi.list(),
    staleTime: 30_000,
  })
}

export function useCreateProject() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: ProjectCreateRequest) => projectsApi.create(body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['projects'] }),
  })
}

export function useDeleteProject() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (slug: string) => projectsApi.delete(slug),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['projects'] }),
  })
}

export function useProjectMembers(projectId: number | undefined) {
  return useQuery({
    queryKey: ['projects', projectId, 'members'],
    queryFn: () => projectsApi.listMembers(projectId!),
    enabled: projectId != null,
  })
}

export function useUpsertProjectMember(projectId: number) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, role }: { userId: number; role: ProjectRole }) =>
      projectsApi.upsertMember(projectId, { user_id: userId, role } satisfies ProjectMemberUpsertRequest),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'members'] }),
  })
}

export function useRemoveProjectMember(projectId: number) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (userId: number) => projectsApi.removeMember(projectId, userId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'members'] }),
  })
}
