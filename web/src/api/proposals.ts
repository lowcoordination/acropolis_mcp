import { api } from './client'
import type { ProposalDetailResponse, ProposalResponse } from './types'

export const proposalsApi = {
  list: (state?: ProposalResponse['state']) =>
    api.get<ProposalResponse[]>(`/proposals${state ? `?state=${state}` : ''}`),
  get: (id: number) => api.get<ProposalDetailResponse>(`/proposals/${id}`),
  approve: (id: number, reason?: string) =>
    api.post<ProposalResponse>(`/proposals/${id}/approve`, { reason: reason ?? null }),
  reject: (id: number, reason?: string) =>
    api.post<ProposalResponse>(`/proposals/${id}/reject`, { reason: reason ?? null }),
}
