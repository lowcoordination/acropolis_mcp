import { useEffect, useState } from 'react'
import { useAuditQuery } from '../lib/useAuditQuery'
import { useAuditTail } from '../lib/useAuditTail'
import { useServers } from '../lib/useServers'
import { useKeys } from '../lib/useKeys'
import { useActiveProject } from '../lib/ProjectContext'
import { auditApi } from '../api/audit'
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
          {event.dlp_detector && (
            // Deliberately shows ONLY the detector name and action, never the matched/redacted
            // value — that value never leaves the backend (see argus/dlp.py's audit-safety
            // invariant), so there is nothing more specific to show here even in expanded view.
            <div>
              DLP: <span className="font-mono">{event.dlp_detector}</span> ({event.dlp_action}
              {event.dlp_match_count ? `, ${event.dlp_match_count} match(es)` : ''})
            </div>
          )}
          {event.args_summary && <div className="font-mono break-all">Args: {event.args_summary}</div>}
          {!!event.bridged && <div>Bridged (2026 stateless client)</div>}
          {event.latency_ms !== null && <div>Latency: {event.latency_ms}ms</div>}
        </div>
      )}
    </li>
  )
}

// datetime-local inputs give "YYYY-MM-DDTHH:mm" in the browser's local time zone — convert to
// a UTC ISO string for the API, which compares against `ts` (stored UTC) lexicographically.
function localDateTimeToIso(value: string): string | undefined {
  if (!value) return undefined
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

export function Audit() {
  const { activeProjectId } = useActiveProject()
  const { data: servers } = useServers(activeProjectId)
  const { data: keys } = useKeys(activeProjectId)
  const [serverFilter, setServerFilter] = useState('')
  const [decisionFilter, setDecisionFilter] = useState('')
  const [apiKeyFilter, setApiKeyFilter] = useState('')
  const [afterInput, setAfterInput] = useState('')
  const [beforeInput, setBeforeInput] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [tailPaused, setTailPaused] = useState(false)

  // Debounce the free-text search so every keystroke doesn't re-fire the query.
  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput), 300)
    return () => clearTimeout(t)
  }, [searchInput])

  const after = localDateTimeToIso(afterInput)
  const before = localDateTimeToIso(beforeInput)
  const apiKeyId = apiKeyFilter ? Number(apiKeyFilter) : undefined

  const { data: history, isLoading } = useAuditQuery({
    server_slug: serverFilter || undefined,
    decision: decisionFilter || undefined,
    api_key_id: apiKeyId,
    after,
    before,
    search: search || undefined,
    limit: 100,
    project_id: activeProjectId ?? undefined,
  })

  const liveEvents = useAuditTail(tailPaused)

  // Live-tail events matching current filters are shown above the historical query results,
  // newest first — the two lists never overlap since the tail only started after page load.
  const filteredLive = liveEvents.filter((e) => {
    if (serverFilter && e.server_slug !== serverFilter) return false
    if (decisionFilter && e.decision !== decisionFilter) return false
    if (apiKeyId !== undefined && e.api_key_id !== apiKeyId) return false
    if (after && e.ts < after) return false
    if (before && e.ts > before) return false
    if (search) {
      const term = search.toLowerCase()
      const haystack = `${e.reason ?? ''} ${e.args_summary ?? ''} ${e.matched ?? ''}`.toLowerCase()
      if (!haystack.includes(term)) return false
    }
    return true
  })

  const exportHref = auditApi.exportCsvUrl({
    server_slug: serverFilter || undefined,
    decision: decisionFilter || undefined,
    api_key_id: apiKeyId,
    after,
    before,
    search: search || undefined,
    project_id: activeProjectId ?? undefined,
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Audit Log</h1>
        <div className="flex items-center gap-2">
          <a href={exportHref} download className="btn-secondary rounded-md px-3 py-1.5 text-xs font-medium">
            Export CSV
          </a>
          <button
            type="button"
            onClick={() => setTailPaused((p) => !p)}
            className="btn-secondary rounded-md px-3 py-1.5 text-xs font-medium"
          >
            {tailPaused ? 'Resume live tail' : 'Pause live tail'}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
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
        <select
          className="rounded-md px-3 py-2 text-sm"
          value={apiKeyFilter}
          onChange={(e) => setApiKeyFilter(e.target.value)}
        >
          <option value="">All API keys</option>
          {(keys ?? []).map((k) => (
            <option key={k.id} value={k.id}>
              {k.name} ({k.key_prefix})
            </option>
          ))}
        </select>
        <input
          type="datetime-local"
          className="rounded-md px-3 py-2 text-sm"
          value={afterInput}
          onChange={(e) => setAfterInput(e.target.value)}
          aria-label="After"
        />
        <input
          type="datetime-local"
          className="rounded-md px-3 py-2 text-sm"
          value={beforeInput}
          onChange={(e) => setBeforeInput(e.target.value)}
          aria-label="Before"
        />
        <input
          type="search"
          className="rounded-md px-3 py-2 text-sm flex-1 min-w-[12rem]"
          placeholder="Search reason, args, matched rule…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
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
