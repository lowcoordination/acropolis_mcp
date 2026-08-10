import { useQuery } from '@tanstack/react-query'
import { auditApi } from '../api/audit'

export function useStats(projectId?: number | null) {
  return useQuery({
    queryKey: ['stats', projectId ?? 'all'],
    queryFn: () => auditApi.stats(projectId ?? undefined),
    // Cheap enough to poll, and the dashboard is exactly the page where "is this fresh"
    // matters most to a first-time user checking things are working.
    refetchInterval: 10_000,
  })
}
