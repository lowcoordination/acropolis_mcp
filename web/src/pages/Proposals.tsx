import { useState } from 'react'
import { Modal } from '../components/Modal'
import { ApiError } from '../api/client'
import { useApproveProposal, useProposalDetail, useProposals, useRejectProposal } from '../lib/useProposals'
import type { ProposalResponse, ProposalState } from '../api/types'

const STATE_TABS: { value: ProposalState | undefined; label: string }[] = [
  { value: undefined, label: 'All' },
  { value: 'pending', label: 'Pending' },
  { value: 'approved', label: 'Approved' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'expired', label: 'Expired' },
]

const STATE_COLORS: Record<ProposalState, string> = {
  pending: 'var(--accent)',
  approved: 'var(--success)',
  rejected: 'var(--danger)',
  expired: 'var(--text-muted)',
}

function targetLabel(p: ProposalResponse): string {
  return p.target_type === 'config_import' ? 'Config import' : `Policy · ${p.target_id}`
}

function ProposalDetailModal({ proposal, onClose }: { proposal: ProposalResponse; onClose: () => void }) {
  const { data: detail, isLoading } = useProposalDetail(proposal.id)
  const approve = useApproveProposal()
  const reject = useRejectProposal()
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)

  function resolve(kind: 'approve' | 'reject') {
    setError(null)
    const mutate = kind === 'approve' ? approve : reject
    mutate.mutate(
      { id: proposal.id, reason: reason || undefined },
      {
        onSuccess: onClose,
        onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong'),
      },
    )
  }

  return (
    <Modal title={`Proposal #${proposal.id} — ${targetLabel(proposal)}`} onClose={onClose}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
          <span>
            State:{' '}
            <span style={{ color: STATE_COLORS[proposal.state], fontWeight: 600 }}>{proposal.state}</span>
          </span>
          <span>
            Proposed by <span className="font-medium">{proposal.proposer}</span> ·{' '}
            {new Date(proposal.created_at).toLocaleString()}
          </span>
          {proposal.resolver && (
            <span>
              Resolved by <span className="font-medium">{proposal.resolver}</span>
              {proposal.resolution_reason ? ` — ${proposal.resolution_reason}` : ''}
            </span>
          )}
        </div>

        {isLoading && <p style={{ color: 'var(--text-muted)' }}>Recomputing plan…</p>}

        {detail && (
          <>
            {detail.stale && proposal.state === 'pending' && (
              <p className="text-sm rounded-md px-3 py-2" style={{ background: 'var(--danger-bg, #3a1d1d)', color: 'var(--danger)' }}>
                ⚠ This target has changed since the proposal was created. Approving will be
                refused with “state changed, re-review” — the change needs to be re-proposed.
              </p>
            )}
            <div>
              <p className="text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
                Plan (recomputed against current state)
              </p>
              <ul className="space-y-1 text-sm rounded-md px-3 py-2" style={{ background: 'var(--bg-muted, #1a1d24)' }}>
                {detail.preview.length === 0 && <li>No changes.</li>}
                {detail.preview.map((line, i) => (
                  <li key={i} style={{ fontFamily: 'var(--font-mono, monospace)' }}>
                    {line}
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}

        {proposal.state === 'pending' && (
          <>
            <div>
              <label className="block text-sm font-medium mb-1" htmlFor="resolve-reason">
                Reason (optional)
              </label>
              <input
                id="resolve-reason"
                className="w-full rounded-md px-3 py-2 text-sm"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Shown in the audit log"
              />
            </div>
            {error && (
              <p className="text-sm" style={{ color: 'var(--danger)' }}>
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => resolve('reject')}
                className="rounded-md px-4 py-2 text-sm font-medium"
                style={{ border: '1px solid var(--border)', color: 'var(--text)' }}
                disabled={reject.isPending}
              >
                {reject.isPending ? 'Rejecting…' : 'Reject'}
              </button>
              <button
                type="button"
                onClick={() => resolve('approve')}
                className="rounded-md px-4 py-2 text-sm font-medium disabled:opacity-60"
                style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
                disabled={approve.isPending}
              >
                {approve.isPending ? 'Approving…' : 'Approve'}
              </button>
            </div>
          </>
        )}
      </div>
    </Modal>
  )
}

export function Proposals() {
  const [state, setState] = useState<ProposalState | undefined>(undefined)
  const [selected, setSelected] = useState<ProposalResponse | null>(null)
  const { data: proposals, isLoading, isError } = useProposals(state)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Approvals</h1>
      </div>

      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        Four-eyes change control: policy and config-import changes are queued here until a second
        admin approves them. Disabled by default — GitOps shops should keep it off and use pull
        requests instead (see docs/approvals.md).
      </p>

      <div className="flex gap-2">
        {STATE_TABS.map((tab) => (
          <button
            key={tab.label}
            type="button"
            onClick={() => setState(tab.value)}
            className="rounded-md px-3 py-1.5 text-sm font-medium capitalize"
            style={
              state === tab.value
                ? { background: 'var(--accent)', color: 'var(--accent-contrast)' }
                : { border: '1px solid var(--border)', color: 'var(--text)' }
            }
          >
            {tab.label}
          </button>
        ))}
      </div>

      {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}
      {isError && <p style={{ color: 'var(--danger)' }}>Could not load proposals.</p>}

      {proposals && proposals.length === 0 && (
        <p style={{ color: 'var(--text-muted)' }}>No proposals{state ? ` in “${state}” state` : ''}.</p>
      )}

      {proposals && proposals.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs" style={{ color: 'var(--text-muted)' }}>
                <th className="px-4 py-2 font-medium">#</th>
                <th className="px-4 py-2 font-medium">Target</th>
                <th className="px-4 py-2 font-medium">Proposer</th>
                <th className="px-4 py-2 font-medium">State</th>
                <th className="px-4 py-2 font-medium">Created</th>
                <th className="px-4 py-2 font-medium">Resolved</th>
              </tr>
            </thead>
            <tbody>
              {proposals.map((p) => (
                <tr
                  key={p.id}
                  className="cursor-pointer border-t"
                  style={{ borderColor: 'var(--border)' }}
                  onClick={() => setSelected(p)}
                >
                  <td className="px-4 py-2">{p.id}</td>
                  <td className="px-4 py-2">{targetLabel(p)}</td>
                  <td className="px-4 py-2">{p.proposer}</td>
                  <td className="px-4 py-2" style={{ color: STATE_COLORS[p.state] }}>
                    {p.state}
                  </td>
                  <td className="px-4 py-2">{new Date(p.created_at).toLocaleString()}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--text-muted)' }}>
                    {p.resolved_at ? new Date(p.resolved_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <ProposalDetailModal proposal={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
