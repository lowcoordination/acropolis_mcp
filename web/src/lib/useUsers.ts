import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { meApi, oidcApi, usersApi } from '../api/users'
import type { Role, UserCreateRequest } from '../api/types'

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list(),
  })
}

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: UserCreateRequest) => usersApi.create(body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useSetUserRole() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, role }: { id: number; role: Role }) => usersApi.setRole(id, role),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useSetUserEnabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => usersApi.setEnabled(id, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
}

// Current-principal — used for the sidebar display and role-aware UI hiding. `retry: false` and
// a modest staleTime: this backs UI decisions, not a security boundary (see hasRole's own
// comment in api/types.ts), so a brief staleness after a role change is an acceptable trade for
// not hammering /me on every render.
export function useCurrentUser() {
  return useQuery({
    queryKey: ['current-user'],
    queryFn: () => meApi.get(),
    staleTime: 30_000,
    retry: false,
  })
}

export function useOidcStatus() {
  return useQuery({
    queryKey: ['oidc-status'],
    queryFn: () => oidcApi.status(),
    staleTime: 60_000,
    retry: false,
  })
}
