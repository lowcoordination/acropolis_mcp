import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { keysApi, type QuotaFields } from '../api/keys'

export function useKeys() {
  return useQuery({
    queryKey: ['keys'],
    queryFn: () => keysApi.list(),
  })
}

export function useCreateKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ name, scopes, quota }: { name: string; scopes?: string[]; quota?: QuotaFields }) =>
      keysApi.create(name, scopes, quota),
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
