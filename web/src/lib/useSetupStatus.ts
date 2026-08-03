import { useQuery } from '@tanstack/react-query'
import { setupApi } from '../api/settings'

export function useSetupStatus() {
  return useQuery({
    queryKey: ['setup-status'],
    queryFn: () => setupApi.status(),
    // Setup status rarely changes after first boot — no need to poll aggressively.
    staleTime: 30_000,
  })
}
