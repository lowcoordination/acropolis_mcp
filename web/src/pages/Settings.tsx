import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../lib/useSettings'

export function Settings() {
  const { data: settings, isLoading } = useSettings()
  const update = useUpdateSettings()

  const [authMode, setAuthMode] = useState<'open' | 'keyed'>('keyed')
  const [aggregateEnabled, setAggregateEnabled] = useState(true)
  const [retentionDays, setRetentionDays] = useState(30)

  useEffect(() => {
    if (settings) {
      setAuthMode(settings.auth_mode)
      setAggregateEnabled(settings.aggregate_enabled)
      setRetentionDays(settings.audit_retention_days)
    }
  }, [settings])

  if (isLoading || !settings) {
    return <p style={{ color: 'var(--text-muted)' }}>Loading…</p>
  }

  const isDirty =
    authMode !== settings.auth_mode ||
    aggregateEnabled !== settings.aggregate_enabled ||
    retentionDays !== settings.audit_retention_days

  function handleSave() {
    update.mutate({
      auth_mode: authMode,
      aggregate_enabled: aggregateEnabled,
      audit_retention_days: retentionDays,
    })
  }

  const isInsecure = authMode === 'open' && window.location.protocol === 'http:'

  return (
    <div className="space-y-6 max-w-xl">
      <h1 className="text-xl font-semibold">Settings</h1>

      {isInsecure && (
        <div
          className="card p-4 text-sm"
          style={{ borderColor: '#c0524b', background: 'color-mix(in srgb, #c0524b 8%, transparent)' }}
        >
          <strong>Open auth mode over plain HTTP.</strong> Anyone who can reach this instance can
          call your MCP servers without a key. If this is reachable beyond your own machine, put it
          behind TLS and switch to keyed mode.
        </div>
      )}

      <div className="card p-5 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="auth-mode">
            Data-plane authentication
          </label>
          <select
            id="auth-mode"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={authMode}
            onChange={(e) => setAuthMode(e.target.value as 'open' | 'keyed')}
          >
            <option value="keyed">Keyed — require an API key on /mcp/*</option>
            <option value="open">Open — no key required (trusted LAN only)</option>
          </select>
        </div>

        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={aggregateEnabled}
            onChange={(e) => setAggregateEnabled(e.target.checked)}
          />
          Enable the aggregate /mcp endpoint
        </label>

        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="retention">
            Audit log retention (days)
          </label>
          <input
            id="retention"
            type="number"
            min={1}
            className="rounded-md px-3 py-2 text-sm w-32"
            value={retentionDays}
            onChange={(e) => setRetentionDays(Number(e.target.value))}
          />
        </div>

        {isDirty && (
          <button
            type="button"
            onClick={handleSave}
            className="btn-primary rounded-md px-4 py-2 text-sm font-medium disabled:opacity-60"
            disabled={update.isPending}
          >
            {update.isPending ? 'Saving…' : 'Save settings'}
          </button>
        )}
      </div>
    </div>
  )
}
