import { useQuery } from '@tanstack/react-query'
import { auditApi, type AuditQuery } from '../api/audit'

export function useAuditQuery(query: AuditQuery) {
  return useQuery({
    queryKey: ['audit', query],
    queryFn: () => auditApi.query(query),
  })
}
