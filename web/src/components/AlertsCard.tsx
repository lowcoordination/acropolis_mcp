import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings, useSendTestWebhook } from '../lib/useSettings'
import { ApiError } from '../api/client'

const EVENT_OPTIONS: { key: string; label: string }[] = [
  { key: 'blocked', label: 'A tool call is blocked' },
  { key: 'unhealthy', label: 'A server goes unhealthy' },
  // Enterprise #9: a policy/config change is queued awaiting a second admin's approval.
  { key: 'approval_pending', label: 'A change is queued for approval' },
]

export function AlertsCard() {
  const { data: settings } = useSettings()
  const update = useUpdateSettings()
  const sendTest = useSendTestWebhook()

  const [url, setUrl] = useState('')
  const [enabled, setEnabled] = useState(false)
  const [events, setEvents] = useState<string[]>(['blocked', 'unhealthy'])
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [urlError, setUrlError] = useState<string | null>(null)

  useEffect(() => {
    if (settings) {
      setUrl(settings.webhook_url ?? '')
      setEnabled(settings.webhook_enabled)
      setEvents(settings.webhook_events)
      setAllowPrivate(settings.webhook_allow_private)
    }
  }, [settings])

  if (!settings) return null

  const isDirty =
    url !== (settings.webhook_url ?? '') ||
    enabled !== settings.webhook_enabled ||
    JSON.stringify([...events].sort()) !== JSON.stringify([...settings.webhook_events].sort()) ||
    allowPrivate !== settings.webhook_allow_private

  function toggleEvent(key: string) {
    setEvents((prev) => (prev.includes(key) ? prev.filter((e) => e !== key) : [...prev, key]))
  }

  async function handleSave() {
    setUrlError(null)
    try {
      await update.mutateAsync({
        webhook_url: url,
        webhook_enabled: enabled,
        webhook_events: events,
        webhook_allow_private: allowPrivate,
      })
    } catch (e) {
      setUrlError(e instanceof ApiError ? e.message : 'Could not save.')
    }
  }

  return (
    <div className="card p-5 space-y-4">
      <div>
        <h2 className="text-sm font-semibold">Alerts</h2>
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
          POST a notification when a tool call is blocked or a server's health changes. The
          gateway will make outbound requests to this URL unattended — treat it with the same
          care as any credential.
        </p>
      </div>

      <div className="space-y-1">
        <label className="block text-xs font-medium" htmlFor="webhook-url">
          Webhook URL
        </label>
        <input
          id="webhook-url"
          type="text"
          placeholder="https://example.com/hooks/acropolis"
          className="w-full rounded-md px-3 py-2 text-sm"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        {urlError && (
          <p className="text-xs" style={{ color: 'var(--danger)' }}>
            {urlError}
          </p>
        )}
      </div>

      <label className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
        <input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} />
        Allow a private-network URL (loopback / RFC1918) — for a LAN collector only
      </label>

      <div className="space-y-1.5">
        <p className="text-xs font-medium">Notify on</p>
        {EVENT_OPTIONS.map((opt) => (
          <label key={opt.key} className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={events.includes(opt.key)} onChange={() => toggleEvent(opt.key)} />
            {opt.label}
          </label>
        ))}
      </div>

      <label className="flex items-center gap-2 text-sm font-medium">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        Enable webhook alerts
      </label>

      <div className="flex items-center gap-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
        {isDirty && (
          <button
            type="button"
            onClick={handleSave}
            disabled={update.isPending}
            className="btn-primary rounded-md px-3 py-1.5 text-xs font-medium disabled:opacity-60"
          >
            {update.isPending ? 'Saving…' : 'Save alert settings'}
          </button>
        )}
        <button
          type="button"
          onClick={() => sendTest.mutate()}
          disabled={sendTest.isPending || !settings.webhook_url}
          className="btn-secondary rounded-md px-3 py-1.5 text-xs font-medium disabled:opacity-60"
        >
          {sendTest.isPending ? 'Sending…' : 'Send test webhook'}
        </button>
      </div>

      {sendTest.data && (
        <p
          className="text-xs"
          style={{ color: sendTest.data.ok ? 'var(--success)' : 'var(--danger)' }}
        >
          {sendTest.data.ok
            ? `Delivered — receiver responded ${sendTest.data.status_code}.`
            : sendTest.data.error
              ? `Failed: ${sendTest.data.error}`
              : `Receiver responded ${sendTest.data.status_code}, which isn't a 2xx.`}
        </p>
      )}
      {sendTest.isError && (
        <p className="text-xs" style={{ color: 'var(--danger)' }}>
          Could not reach the test endpoint.
        </p>
      )}
    </div>
  )
}
