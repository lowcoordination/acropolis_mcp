import { useQuery } from '@tanstack/react-query'
import { usageApi, type UsageQuery } from '../api/usage'

export function useUsage(query: UsageQuery) {
  return useQuery({
    queryKey: ['usage', query],
    queryFn: () => usageApi.query(query),
  })
}
