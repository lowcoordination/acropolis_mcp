import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settingsApi, tracingApi, webhooksApi, type SettingsUpdateRequest } from '../api/settings'

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.get(),
  })
}

export function useUpdateSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: SettingsUpdateRequest) => settingsApi.update(body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings'] }),
  })
}

export function useSendTestWebhook() {
  return useMutation({
    mutationFn: () => webhooksApi.test(),
  })
}

// Enterprise #9: read-only, informational — this instance never toggles tracing from the UI
// (it's an ACROPOLIS_OTEL_ENABLED environment gate, matching the "standard OTel env vars, one
// Acropolis-specific gate" design decision in docs/observability.md), so there's no matching
// mutation hook here, unlike useSettings/useUpdateSettings above.
export function useTracingStatus() {
  return useQuery({
    queryKey: ['tracing-status'],
    queryFn: () => tracingApi.status(),
  })
}
