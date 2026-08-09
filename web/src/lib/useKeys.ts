import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { keysApi, type QuotaFields } from '../api/keys'

export function useKeys(projectId?: number | null) {
  return useQuery({
    queryKey: ['keys', projectId ?? 'all'],
    queryFn: () => keysApi.list(projectId ?? undefined),
  })
}

export function useCreateKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      name, scopes, quota, projectSlug,
    }: { name: string; scopes?: string[]; quota?: QuotaFields; projectSlug?: string }) =>
      keysApi.create(name, scopes, quota, projectSlug),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['keys'] }),
  })
}

export function useSetKeyQuota() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, quota }: { id: number; quota: QuotaFields }) => keysApi.setQuota(id, quota),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['keys'] }),
  })
}

export function useSetKeyEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => keysApi.setEnabled(id, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['keys'] }),
  })
}

export function useDeleteKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => keysApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['keys'] }),
  })
}
