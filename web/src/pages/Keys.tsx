import { useState } from 'react'
import { useServers } from '../lib/useServers'
import { useCreateKey, useDeleteKey, useKeys, useSetKeyEnabled, useSetKeyQuota } from '../lib/useKeys'
import { useUsage } from '../lib/useUsage'
import { Modal } from '../components/Modal'
import { ApiError } from '../api/client'
import type { KeyCreatedResponse, KeyResponse, QuotaPeriod } from '../api/types'

function QuotaFieldset({
  quotaEnabled,
  setQuotaEnabled,
  quotaCalls,
  setQuotaCalls,
  quotaPeriod,
  setQuotaPeriod,
}: {
  quotaEnabled: boolean
  setQuotaEnabled: (v: boolean) => void
  quotaCalls: string
  setQuotaCalls: (v: string) => void
  quotaPeriod: QuotaPeriod
  setQuotaPeriod: (v: QuotaPeriod) => void
}) {
  return (
    <div>
      <label className="flex items-center gap-2 text-sm font-medium mb-2">
        <input type="checkbox" checked={quotaEnabled} onChange={(e) => setQuotaEnabled(e.target.checked)} />
        Limit call volume (quota)
      </label>
      {quotaEnabled && (
        <div className="pl-6 flex items-center gap-2">
          <input
            type="number"
            min={1}
            className="w-28 rounded-md px-3 py-2 text-sm"
            value={quotaCalls}
            onChange={(e) => setQuotaCalls(e.target.value)}
            placeholder="10000"
            required={quotaEnabled}
          />
          <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
            calls per
          </span>
          <select
            className="rounded-md px-3 py-2 text-sm"
            value={quotaPeriod}
            onChange={(e) => setQuotaPeriod(e.target.value as QuotaPeriod)}
          >
            <option value="day">day</option>
            <option value="month">month</option>
          </select>
        </div>
      )}
      {quotaEnabled && (
        <p className="text-xs pl-6 mt-1" style={{ color: 'var(--text-muted)' }}>
          Counts JSON-RPC tool calls, not tokens or cost — see docs/quotas.md. Leave unchecked
          for unlimited.
        </p>
      )}
    </div>
  )
}

function CreateKeyModal({ onClose, onCreated }: { onClose: () => void; onCreated: (k: KeyCreatedResponse) => void }) {
  const { data: servers } = useServers()
  const [name, setName] = useState('')
  const [scopeAll, setScopeAll] = useState(true)
  const [selectedScopes, setSelectedScopes] = useState<string[]>([])
  const [quotaEnabled, setQuotaEnabled] = useState(false)
  const [quotaCalls, setQuotaCalls] = useState('')
  const [quotaPeriod, setQuotaPeriod] = useState<QuotaPeriod>('day')
  const [error, setError] = useState<string | null>(null)
  const create = useCreateKey()

  function toggleScope(slug: string) {
    setSelectedScopes((s) => (s.includes(slug) ? s.filter((x) => x !== slug) : [...s, slug]))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    const quota = quotaEnabled
      ? { quota_calls: Number(quotaCalls), quota_period: quotaPeriod }
      : undefined
    if (quotaEnabled && (!quotaCalls || Number(quotaCalls) <= 0)) {
      setError('Quota must be a positive number of calls')
      return
    }
    create.mutate(
      { name, scopes: scopeAll ? undefined : selectedScopes, quota },
      {
        onSuccess: (created) => onCreated(created),
        onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong'),
      },
    )
  }

  return (
    <Modal title="Create API key" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="key-name">
            Name
          </label>
          <input
            id="key-name"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="my-laptop"
            required
          />
        </div>
        <div>
          <label className="flex items-center gap-2 text-sm font-medium mb-2">
            <input type="checkbox" checked={scopeAll} onChange={(e) => setScopeAll(e.target.checked)} />
            Access to all servers
          </label>
          {!scopeAll && (
            <div className="space-y-1 pl-6">
              {(servers ?? []).map((s) => (
                <label key={s.slug} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes(s.slug)}
                    onChange={() => toggleScope(s.slug)}
                  />
                  {s.slug}
                </label>
              ))}
              {(servers ?? []).length === 0 && (
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  No servers registered yet.
                </p>
              )}
            </div>
          )}
        </div>
        <QuotaFieldset
          quotaEnabled={quotaEnabled}
          setQuotaEnabled={setQuotaEnabled}
          quotaCalls={quotaCalls}
          setQuotaCalls={setQuotaCalls}
          quotaPeriod={quotaPeriod}
          setQuotaPeriod={setQuotaPeriod}
        />
        {error && (
          <p className="text-sm" style={{ color: 'var(--danger)' }}>
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary rounded-md px-4 py-2 text-sm font-medium">
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary rounded-md px-4 py-2 text-sm font-medium disabled:opacity-60"
            disabled={create.isPending}
          >
            {create.isPending ? 'Creating…' : 'Create key'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function EditQuotaModal({ apiKey, onClose }: { apiKey: KeyResponse; onClose: () => void }) {
  const [quotaEnabled, setQuotaEnabled] = useState(apiKey.quota_calls !== null)
  const [quotaCalls, setQuotaCalls] = useState(apiKey.quota_calls != null ? String(apiKey.quota_calls) : '')
  const [quotaPeriod, setQuotaPeriod] = useState<QuotaPeriod>(apiKey.quota_period ?? 'day')
  const [error, setError] = useState<string | null>(null)
  const setQuota = useSetKeyQuota()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (quotaEnabled && (!quotaCalls || Number(quotaCalls) <= 0)) {
      setError('Quota must be a positive number of calls')
      return
    }
    setQuota.mutate(
      {
        id: apiKey.id,
        quota: quotaEnabled
          ? { quota_calls: Number(quotaCalls), quota_period: quotaPeriod }
          : { quota_calls: null, quota_period: null },
      },
      {
        onSuccess: onClose,
        onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong'),
      },
    )
  }

  return (
    <Modal title={`Edit quota — ${apiKey.name}`} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <QuotaFieldset
          quotaEnabled={quotaEnabled}
          setQuotaEnabled={setQuotaEnabled}
          quotaCalls={quotaCalls}
          setQuotaCalls={setQuotaCalls}
          quotaPeriod={quotaPeriod}
          setQuotaPeriod={setQuotaPeriod}
        />
        {error && (
          <p className="text-sm" style={{ color: 'var(--danger)' }}>
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary rounded-md px-4 py-2 text-sm font-medium">
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary rounded-md px-4 py-2 text-sm font-medium disabled:opacity-60"
            disabled={setQuota.isPending}
          >
            {setQuota.isPending ? 'Saving…' : 'Save quota'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function ShowKeyModal({ created, onClose }: { created: KeyCreatedResponse; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    await navigator.clipboard.writeText(created.plaintext)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <Modal title="Key created" onClose={onClose}>
      <p className="text-sm mb-3" style={{ color: 'var(--text-muted)' }}>
        Copy this key now — it will not be shown again.
      </p>
      <div
        className="font-mono text-xs rounded-md px-3 py-2 break-all mb-4"
        style={{ background: 'var(--code-bg)', border: '1px solid var(--border)' }}
      >
        {created.plaintext}
      </div>
      <div className="flex justify-end gap-2">
        <button type="button" onClick={handleCopy} className="btn-secondary rounded-md px-4 py-2 text-sm font-medium">
          {copied ? 'Copied!' : 'Copy'}
        </button>
        <button type="button" onClick={onClose} className="btn-primary rounded-md px-4 py-2 text-sm font-medium">
          Done
        </button>
      </div>
    </Modal>
  )
}

/** Usage-vs-quota progress bar for one key. Fetches usage for the key's OWN quota_period (so
 * a monthly-quota key is measured against month-to-date, not the row's arbitrary default) —
 * renders nothing for a key with no quota configured, since there's nothing to show progress
 * toward (see docs/quotas.md: null quota = unlimited). */
function QuotaUsageBar({ apiKey }: { apiKey: KeyResponse }) {
  const period = apiKey.quota_period ?? 'day'
  const { data: usage } = useUsage({ api_key_id: apiKey.id, period })

  if (apiKey.quota_calls == null) {
    return (
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Unlimited
      </span>
    )
  }

  const used = (usage?.buckets ?? []).reduce((sum, b) => sum + b.calls, 0)
  const pct = Math.min(100, Math.round((used / apiKey.quota_calls) * 100))
  const barColor = pct >= 100 ? 'var(--danger)' : pct >= 80 ? 'var(--warning, #d97706)' : 'var(--success)'

  return (
    <div className="w-32">
      <div className="flex justify-between text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        <span>
          {used}/{apiKey.quota_calls}
        </span>
        <span>{pct}%</span>
      </div>
      <div
        className="h-1.5 rounded-full overflow-hidden"
        style={{ background: 'var(--border)' }}
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: barColor }} />
      </div>
    </div>
  )
}

export function Keys() {
  const { data: keys, isLoading, isError } = useKeys()
  const setEnabled = useSetKeyEnabled()
  const deleteKey = useDeleteKey()
  const [showCreate, setShowCreate] = useState(false)
  const [justCreated, setJustCreated] = useState<KeyCreatedResponse | null>(null)
  const [editingQuotaFor, setEditingQuotaFor] = useState<KeyResponse | null>(null)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">API Keys</h1>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="btn-primary rounded-md px-4 py-2 text-sm font-medium"
        >
          Create key
        </button>
      </div>

      {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}
      {isError && <p style={{ color: 'var(--danger)' }}>Could not load keys.</p>}

      {keys && keys.length === 0 && (
        <div className="card p-8 text-center">
          <p style={{ color: 'var(--text-muted)' }}>No API keys yet.</p>
        </div>
      )}

      {keys && keys.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: 'var(--border)' }}>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Name
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Key
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Scopes
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Usage
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Last used
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Status
                </th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                  <td className="px-4 py-3 font-medium">{key.name}</td>
                  <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    {key.key_prefix}…
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {key.server_scopes ? key.server_scopes.join(', ') : 'All servers'}
                  </td>
                  <td className="px-4 py-3">
                    <button type="button" onClick={() => setEditingQuotaFor(key)} className="text-left">
                      <QuotaUsageBar apiKey={key} />
                    </button>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={() => setEnabled.mutate({ id: key.id, enabled: !key.enabled })}
                      className="text-xs font-medium"
                      style={{ color: key.enabled ? 'var(--success)' : 'var(--text-muted)' }}
                    >
                      {key.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => setEditingQuotaFor(key)}
                      className="text-xs mr-3"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      Quota
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (confirm(`Delete key "${key.name}"? This cannot be undone.`)) {
                          deleteKey.mutate(key.id)
                        }
                      }}
                      className="text-xs"
                      style={{ color: 'var(--danger)' }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateKeyModal
          onClose={() => setShowCreate(false)}
          onCreated={(created) => {
            setShowCreate(false)
            setJustCreated(created)
          }}
        />
      )}
      {justCreated && <ShowKeyModal created={justCreated} onClose={() => setJustCreated(null)} />}
      {editingQuotaFor && (
        <EditQuotaModal apiKey={editingQuotaFor} onClose={() => setEditingQuotaFor(null)} />
      )}
    </div>
  )
}
