import { useQuery } from '@tanstack/react-query'
import { usageApi, type UsageQuery } from '../api/usage'

// `enabled` lets a caller (e.g. Keys.tsx's per-row usage bar) skip the network round-trip
// entirely for a key with no quota configured — there's nothing to show progress toward, so
// firing the query anyway would be a wasted request on every unlimited key on the list.
export function useUsage(query: UsageQuery, enabled = true) {
  return useQuery({
    queryKey: ['usage', query],
    queryFn: () => usageApi.query(query),
    enabled,
  })
}
