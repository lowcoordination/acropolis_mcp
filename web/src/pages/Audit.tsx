import { useState } from 'react'
import { useAuditQuery } from '../lib/useAuditQuery'
import { useAuditTail } from '../lib/useAuditTail'
import { useServers } from '../lib/useServers'
import { DecisionBadge } from '../components/DecisionBadge'
import type { AuditEvent } from '../api/types'

function EventRow({ event }: { event: AuditEvent }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <li className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        className="w-full px-4 py-2.5 flex items-center justify-between gap-3 text-left text-sm"
      >
        <div className="flex items-center gap-3 min-w-0">
          <DecisionBadge decision={event.decision} />
          <span className="font-mono text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>
            {new Date(event.ts).toLocaleTimeString()}
          </span>
          <span className="font-medium truncate">
            {event.server_slug ?? 'aggregate'} · {event.tool ?? event.rpc_method ?? '—'}
          </span>
        </div>
        {event.rule && (
          <span className="text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>
            {event.rule}
          </span>
        )}
      </button>
      {expanded && (
        <div className="px-4 pb-3 text-xs space-y-1" style={{ color: 'var(--text-muted)' }}>
          {event.reason && <div>Reason: {event.reason}</div>}
          {event.matched && <div className="font-mono">Matched: {event.matched}</div>}
          {event.args_summary && <div className="font-mono break-all">Args: {event.args_summary}</div>}
          {!!event.bridged && <div>Bridged (2026 stateless client)</div>}
          {event.latency_ms !== null && <div>Latency: {event.latency_ms}ms</div>}
        </div>
      )}
    </li>
  )
}

export function Audit() {
  const { data: servers } = useServers()
  const [serverFilter, setServerFilter] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [tailPaused, setTailPaused] = useState(false)

  const { data: history, isLoading } = useAuditQuery({
    server_slug: serverFilter || undefined,
    decision: decisionFilter || undefined,
    limit: 100,
  })

  const liveEvents = useAuditTail(tailPaused)

  // Live-tail events matching current filters are shown above the historical query results,
  // newest first — the two lists never overlap since the tail only started after page load.
  const filteredLive = liveEvents.filter((e) => {
    if (serverFilter && e.server_slug !== serverFilter) return false
    if (decisionFilter && e.decision !== decisionFilter) return false
    return true
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Audit Log</h1>
        <button
          type="button"
          onClick={() => setTailPaused((p) => !p)}
          className="btn-secondary rounded-md px-3 py-1.5 text-xs font-medium"
        >
          {tailPaused ? 'Resume live tail' : 'Pause live tail'}
        </button>
      </div>

      <div className="flex gap-3">
        <select
          className="rounded-md px-3 py-2 text-sm"
          value={serverFilter}
          onChange={(e) => setServerFilter(e.target.value)}
        >
          <option value="">All servers</option>
          {(servers ?? []).map((s) => (
            <option key={s.slug} value={s.slug}>
              {s.slug}
            </option>
          ))}
        </select>
        <select
          className="rounded-md px-3 py-2 text-sm"
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value)}
        >
          <option value="">All decisions</option>
          <option value="ALLOWED">Allowed</option>
          <option value="BLOCKED">Blocked</option>
          <option value="PASSTHROUGH">Passthrough</option>
          <option value="ERROR">Error</option>
        </select>
      </div>

      <div className="card">
        {!tailPaused && filteredLive.length > 0 && (
          <div className="px-4 py-2 text-xs font-medium border-b" style={{ borderColor: 'var(--border)', color: 'var(--accent)' }}>
            Live
          </div>
        )}
        <ul>
          {!tailPaused && filteredLive.map((e, i) => <EventRow key={`live-${e.id}-${i}`} event={e} />)}
        </ul>

        {isLoading && (
          <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            Loading…
          </p>
        )}
        {history && history.length === 0 && filteredLive.length === 0 && (
          <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            No audit events match these filters.
          </p>
        )}
        {history && history.length > 0 && (
          <>
            <div className="px-4 py-2 text-xs font-medium border-b" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
              History
            </div>
            <ul>
              {history.map((e) => (
                <EventRow key={e.id} event={e} />
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  )
}
