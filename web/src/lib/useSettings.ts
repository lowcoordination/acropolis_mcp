import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settingsApi, webhooksApi, type SettingsUpdateRequest } from '../api/settings'

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
