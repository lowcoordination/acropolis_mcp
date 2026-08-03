import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { serversApi } from '../api/servers'
import type { PolicyResponse, ServerCreateRequest, ServerUpdateRequest } from '../api/types'

export function useServers() {
  return useQuery({
    queryKey: ['servers'],
    queryFn: () => serversApi.list(),
    refetchInterval: 10_000,
  })
}

export function useServer(slug: string) {
  return useQuery({
    queryKey: ['servers', slug],
    queryFn: () => serversApi.get(slug),
    enabled: !!slug,
  })
}

export function useServerPolicy(slug: string) {
  return useQuery({
    queryKey: ['servers', slug, 'policy'],
    queryFn: () => serversApi.getPolicy(slug),
    enabled: !!slug,
  })
}

export function useServerTools(slug: string) {
  return useQuery({
    queryKey: ['servers', slug, 'tools'],
    queryFn: () => serversApi.getTools(slug),
    enabled: !!slug,
  })
}

export function useCreateServer() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: ServerCreateRequest) => serversApi.create(body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['servers'] }),
  })
}

export function useUpdateServer(slug: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: ServerUpdateRequest) => serversApi.update(slug, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      queryClient.invalidateQueries({ queryKey: ['servers', slug] })
    },
  })
}

export function useDeleteServer() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (slug: string) => serversApi.delete(slug),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['servers'] }),
  })
}

export function useSetServerPolicy(slug: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: PolicyResponse) => serversApi.setPolicy(slug, body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['servers', slug, 'policy'] }),
  })
}

export function useProbeServer(slug: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => serversApi.probe(slug),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      queryClient.invalidateQueries({ queryKey: ['servers', slug] })
      queryClient.invalidateQueries({ queryKey: ['servers', slug, 'tools'] })
    },
  })
}
