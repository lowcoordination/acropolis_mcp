import { useState } from 'react'
import { useServers } from '../lib/useServers'
import { useKeys } from '../lib/useKeys'
import { useUsage } from '../lib/useUsage'
import { useActiveProject } from '../lib/ProjectContext'

export function Usage() {
  const { activeProjectId } = useActiveProject()
  const { data: servers } = useServers(activeProjectId)
  const { data: keys } = useKeys(activeProjectId)
  const [apiKeyFilter, setApiKeyFilter] = useState('')
  const [serverFilter, setServerFilter] = useState('')
  const [toolFilter, setToolFilter] = useState('')
  const [period, setPeriod] = useState<'day' | 'month' | 'all'>('day')

  const { data: usage, isLoading, isError } = useUsage({
    api_key_id: apiKeyFilter ? Number(apiKeyFilter) : undefined,
    server_slug: serverFilter || undefined,
    tool: toolFilter || undefined,
    period,
    project_id: activeProjectId ?? undefined,
  })

  const keyName = (id: number | null) => keys?.find((k) => k.id === id)?.name ?? null

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Usage</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
          Call counts by key, server, and tool — not tokens or cost. See docs/quotas.md for why
          Acropolis can only count JSON-RPC calls, not model spend.
        </p>
      </div>

      <div className="card p-4 flex flex-wrap gap-3 items-end">
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
            API key
          </label>
          <select
            className="rounded-md px-3 py-2 text-sm min-w-[10rem]"
            value={apiKeyFilter}
            onChange={(e) => setApiKeyFilter(e.target.value)}
          >
            <option value="">All keys</option>
            {(keys ?? []).map((k) => (
              <option key={k.id} value={k.id}>
                {k.name} ({k.key_prefix}…)
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
            Server
          </label>
          <select
            className="rounded-md px-3 py-2 text-sm min-w-[10rem]"
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
        </div>
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
            Tool
          </label>
          <input
            className="rounded-md px-3 py-2 text-sm min-w-[10rem]"
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            placeholder="e.g. read_file"
          />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
            Period
          </label>
          <select
            className="rounded-md px-3 py-2 text-sm"
            value={period}
            onChange={(e) => setPeriod(e.target.value as 'day' | 'month' | 'all')}
          >
            <option value="day">Today (UTC)</option>
            <option value="month">This month (UTC)</option>
            <option value="all">All time</option>
          </select>
        </div>
      </div>

      {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}
      {isError && <p style={{ color: 'var(--danger)' }}>Could not load usage.</p>}

      {usage && usage.buckets.length === 0 && (
        <div className="card p-8 text-center">
          <p style={{ color: 'var(--text-muted)' }}>No usage recorded for this filter/period.</p>
        </div>
      )}

      {usage && usage.buckets.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: 'var(--border)' }}>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Key
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Server
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Tool
                </th>
                <th className="px-4 py-2 font-medium text-right" style={{ color: 'var(--text-muted)' }}>
                  Calls
                </th>
              </tr>
            </thead>
            <tbody>
              {usage.buckets.map((b, i) => (
                <tr key={i} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                  <td className="px-4 py-2.5">
                    {b.api_key_id === null
                      ? 'No key (open auth)'
                      : (keyName(b.api_key_id) ?? b.key_prefix ?? `key #${b.api_key_id}`)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    {b.server_slug ?? '—'}
                  </td>
                  <td className="px-4 py-2.5">{b.tool ?? '—'}</td>
                  <td className="px-4 py-2.5 text-right font-medium">{b.calls.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
