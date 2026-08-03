import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { keysApi } from '../api/keys'

export function useKeys() {
  return useQuery({
    queryKey: ['keys'],
    queryFn: () => keysApi.list(),
  })
}

export function useCreateKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ name, scopes }: { name: string; scopes?: string[] }) => keysApi.create(name, scopes),
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
