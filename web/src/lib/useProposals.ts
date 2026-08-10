import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { proposalsApi } from '../api/proposals'
import type { ProposalState } from '../api/types'

export function useProposals(state?: ProposalState) {
  return useQuery({
    queryKey: ['proposals', state ?? 'all'],
    queryFn: () => proposalsApi.list(state),
  })
}

export function useProposalDetail(id: number | null) {
  return useQuery({
    queryKey: ['proposal', id],
    queryFn: () => proposalsApi.get(id!),
    enabled: id != null,
  })
}

export function useApproveProposal() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) =>
      proposalsApi.approve(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proposals'] })
      queryClient.invalidateQueries({ queryKey: ['proposal'] })
    },
  })
}

export function useRejectProposal() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) =>
      proposalsApi.reject(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proposals'] })
      queryClient.invalidateQueries({ queryKey: ['proposal'] })
    },
  })
}
