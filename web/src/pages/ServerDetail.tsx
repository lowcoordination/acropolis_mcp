import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { serversApi } from '../api/servers'
import {
  useProbeServer,
  useRefreshServerTools,
  useServer,
  useServerPolicy,
  useServerTools,
} from '../lib/useServers'
import { POLICY_PRESETS } from '../lib/policyPresets'
import { HealthBadge, ProtocolBadge } from '../components/HealthBadge'
import type { ParamRule, PolicyMode, PolicyResponse } from '../api/types'

function relativeTime(isoTimestamp: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(isoTimestamp).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function CopyableEndpoint({ slug }: { slug: string }) {
  const [copied, setCopied] = useState(false)
  const url = `${window.location.origin}/mcp/${slug}`

  async function handleCopy() {
    await navigator.clipboard.writeText(url)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="font-mono text-xs rounded px-2 py-1 text-left"
      style={{ background: 'var(--code-bg, var(--bg))', border: '1px solid var(--border)' }}
      title="Click to copy"
    >
      {copied ? 'Copied!' : url}
    </button>
  )
}

function ParamRuleEditor({
  rules,
  onChange,
}: {
  rules: Record<string, ParamRule>
  onChange: (rules: Record<string, ParamRule>) => void
}) {
  const [paramName, setParamName] = useState('')

  function addParam() {
    if (!paramName.trim()) return
    onChange({ ...rules, [paramName.trim()]: { block_patterns: [], denied: false } })
    setParamName('')
  }

  function updateRule(name: string, patch: Partial<ParamRule>) {
    onChange({ ...rules, [name]: { ...rules[name], ...patch } })
  }

  function removeParam(name: string) {
    const next = { ...rules }
    delete next[name]
    onChange(next)
  }

  return (
    <div className="mt-2 pl-4 border-l-2 space-y-2" style={{ borderColor: 'var(--border)' }}>
      {Object.entries(rules).map(([name, rule]) => (
        <div key={name} className="text-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-mono font-medium">{name}</span>
            <button type="button" onClick={() => removeParam(name)} style={{ color: '#c0524b' }}>
              remove
            </button>
          </div>
          <label className="flex items-center gap-1.5">
            <input
              type="checkbox"
              checked={rule.denied}
              onChange={(e) => updateRule(name, { denied: e.target.checked })}
            />
            Block this param entirely
          </label>
          {!rule.denied && (
            <>
              <label className="flex items-center gap-1.5">
                Max length
                <input
                  type="number"
                  className="w-20 rounded px-1.5 py-0.5 text-xs"
                  value={rule.max_length ?? ''}
                  onChange={(e) =>
                    updateRule(name, { max_length: e.target.value ? Number(e.target.value) : null })
                  }
                />
              </label>
              <label className="flex items-center gap-1.5">
                Block patterns (regex, one per line)
              </label>
              <textarea
                className="w-full rounded px-1.5 py-1 text-xs font-mono"
                rows={2}
                value={rule.block_patterns.join('\n')}
                onChange={(e) =>
                  updateRule(name, {
                    block_patterns: e.target.value.split('\n').filter((p) => p.trim()),
                  })
                }
              />
            </>
          )}
        </div>
      ))}
      <div className="flex items-center gap-2">
        <input
          className="rounded px-2 py-1 text-xs font-mono flex-1"
          placeholder="param name"
          value={paramName}
          onChange={(e) => setParamName(e.target.value)}
        />
        <button type="button" onClick={addParam} className="btn-secondary rounded px-2 py-1 text-xs">
          + rule
        </button>
      </div>
    </div>
  )
}

export function ServerDetail() {
  const { slug } = useParams<{ slug: string }>()
  const queryClient = useQueryClient()

  const { data: server } = useServer(slug ?? '')
  const { data: policy, isLoading: policyLoading } = useServerPolicy(slug ?? '')
  const { data: toolsResponse, isLoading: toolsLoading } = useServerTools(slug ?? '')
  const tools = toolsResponse?.tools
  const probeServer = useProbeServer(slug ?? '')
  const refreshTools = useRefreshServerTools(slug ?? '')

  const [draft, setDraft] = useState<PolicyResponse | null>(null)
  const [expandedTool, setExpandedTool] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [selectedPresetId, setSelectedPresetId] = useState('')

  useEffect(() => {
    if (policy) setDraft(policy)
  }, [policy])

  const savePolicy = useMutation({
    mutationFn: (body: PolicyResponse) => serversApi.setPolicy(slug!, body),
    onSuccess: () => {
      setSaveError(null)
      queryClient.invalidateQueries({ queryKey: ['servers', slug, 'policy'] })
      queryClient.invalidateQueries({ queryKey: ['servers', slug, 'tools'] })
    },
    onError: (err) => {
      // Deliberately not auto-redirected to /login even on a 401 (see api/client.ts) — this
      // draft may be the only copy of unsaved edits, so surface the failure here instead of
      // navigating away and silently discarding it.
      setSaveError(
        err instanceof ApiError && err.status === 401
          ? 'Your session expired — log in again, then Save policy to retry.'
          : err instanceof ApiError
            ? err.message
            : 'Something went wrong saving the policy.',
      )
    },
  })

  if (!slug) return null

  if (policyLoading || !draft) {
    return <p style={{ color: 'var(--text-muted)' }}>Loading…</p>
  }

  function setMode(mode: PolicyMode) {
    setDraft((d) => (d ? { ...d, mode } : d))
  }

  function toggleTool(toolName: string, currentlyAllowed: boolean) {
    setDraft((d) => {
      if (!d) return d
      if (d.mode === 'allowlist') {
        const allowed = currentlyAllowed
          ? d.allowed.filter((t) => t !== toolName)
          : [...d.allowed, toolName]
        return { ...d, allowed }
      }
      if (d.mode === 'denylist') {
        const denied = currentlyAllowed
          ? [...d.denied, toolName]
          : d.denied.filter((t) => t !== toolName)
        return { ...d, denied }
      }
      return d
    })
  }

  function setParamRules(toolName: string, rules: Record<string, ParamRule>) {
    setDraft((d) => {
      if (!d) return d
      const param_rules = { ...d.param_rules }
      if (Object.keys(rules).length === 0) {
        delete param_rules[toolName]
      } else {
        param_rules[toolName] = rules
      }
      return { ...d, param_rules }
    })
  }

  function setRateLimit(value: string) {
    setDraft((d) => (d ? { ...d, rate_limit: value || null } : d))
  }

  function applyPreset(presetId: string) {
    setSelectedPresetId(presetId)
    const preset = POLICY_PRESETS.find((p) => p.id === presetId)
    if (!preset) return
    setDraft((d) => (d ? preset.apply(d, tools ?? []) : d))
  }

  const isDirty = JSON.stringify(draft) !== JSON.stringify(policy)
  const selectedPreset = POLICY_PRESETS.find((p) => p.id === selectedPresetId)

  return (
    <div className="space-y-6">
      <div>
        <Link to="/servers" className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
          ← Servers
        </Link>
        <div className="flex items-center gap-3 mt-1">
          <h1 className="text-xl font-semibold">{server?.name ?? slug}</h1>
          {server && <HealthBadge status={server.health_status} />}
          {server && <ProtocolBadge protocol={server.upstream_protocol} />}
          <button
            type="button"
            onClick={() => probeServer.mutate()}
            disabled={probeServer.isPending}
            className="text-xs font-medium disabled:opacity-60"
            style={{ color: 'var(--accent)' }}
          >
            {probeServer.isPending ? 'Probing…' : 'Re-probe'}
          </button>
        </div>
        <div className="mt-2 space-y-1">
          <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Upstream: <span className="font-mono">{server?.upstream_url}</span>
          </div>
          <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Endpoint: <CopyableEndpoint slug={slug} />
          </div>
        </div>
      </div>

      <div className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold">Policy</h2>

        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="policy-preset">
            Start from a preset…
          </label>
          <select
            id="policy-preset"
            className="rounded-md px-3 py-2 text-sm w-full"
            value={selectedPresetId}
            onChange={(e) => applyPreset(e.target.value)}
          >
            <option value="">— choose a preset —</option>
            {POLICY_PRESETS.map((preset) => (
              <option key={preset.id} value={preset.id}>
                {preset.label}
              </option>
            ))}
          </select>
          {selectedPreset && (
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              {selectedPreset.description}
            </p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Mode</label>
          <select
            className="rounded-md px-3 py-2 text-sm"
            value={draft.mode}
            onChange={(e) => setMode(e.target.value as PolicyMode)}
          >
            <option value="passthrough">Passthrough — allow everything, just audit</option>
            <option value="allowlist">Allowlist — only listed tools pass</option>
            <option value="denylist">Denylist — all tools pass except listed</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="rate-limit">
            Rate limit
          </label>
          <input
            id="rate-limit"
            className="rounded-md px-3 py-2 text-sm font-mono w-40"
            placeholder="e.g. 5/minute"
            value={draft.rate_limit ?? ''}
            onChange={(e) => setRateLimit(e.target.value)}
          />
        </div>

        {isDirty && (
          <div className="space-y-2">
            {saveError && (
              <p className="text-sm" style={{ color: '#c0524b' }}>
                {saveError}
              </p>
            )}
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => savePolicy.mutate(draft)}
                className="btn-primary rounded-md px-4 py-2 text-sm font-medium disabled:opacity-60"
                disabled={savePolicy.isPending}
              >
                {savePolicy.isPending ? 'Saving…' : 'Save policy'}
              </button>
              <button
                type="button"
                onClick={() => setDraft(policy ?? null)}
                className="btn-secondary rounded-md px-4 py-2 text-sm font-medium"
              >
                Discard changes
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="px-4 py-3 border-b flex items-center justify-between gap-3" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold">Tools</h2>
            {toolsResponse?.fetched_at && (
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Updated {relativeTime(toolsResponse.fetched_at)}
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={() => refreshTools.mutate()}
            disabled={refreshTools.isPending}
            className="text-xs font-medium disabled:opacity-60"
            style={{ color: 'var(--accent)' }}
            title="Re-fetch the tool list from the upstream, bypassing the cache"
          >
            {refreshTools.isPending ? 'Refreshing…' : 'Refresh from upstream'}
          </button>
        </div>
        {toolsLoading && (
          <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            Loading tools…
          </p>
        )}
        {tools && tools.length === 0 && (
          <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            No tools found — the upstream may be unreachable, or hasn't been probed yet.
          </p>
        )}
        {tools && tools.length > 0 && (
          <ul>
            {tools.map((tool) => {
              const isAllowedInDraft =
                draft.mode === 'allowlist'
                  ? draft.allowed.includes(tool.name)
                  : draft.mode === 'denylist'
                    ? !draft.denied.includes(tool.name)
                    : true
              const canToggle = draft.mode !== 'passthrough'
              const rules = draft.param_rules[tool.name] ?? {}

              return (
                <li key={tool.name} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                  <div className="px-4 py-3 flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      <div className="font-mono text-sm font-medium">{tool.name}</div>
                      {tool.description && (
                        <div className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                          {tool.description}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <button
                        type="button"
                        onClick={() => setExpandedTool(expandedTool === tool.name ? null : tool.name)}
                        className="text-xs"
                        style={{ color: 'var(--accent)' }}
                      >
                        {Object.keys(rules).length > 0 ? `${Object.keys(rules).length} rule(s)` : 'add rule'}
                      </button>
                      <label className="inline-flex items-center gap-2 text-xs font-medium">
                        <input
                          type="checkbox"
                          checked={isAllowedInDraft}
                          disabled={!canToggle}
                          onChange={() => toggleTool(tool.name, isAllowedInDraft)}
                        />
                        {isAllowedInDraft ? 'Allowed' : 'Denied'}
                      </label>
                    </div>
                  </div>
                  {expandedTool === tool.name && (
                    <div className="px-4 pb-3">
                      <ParamRuleEditor
                        rules={rules}
                        onChange={(r) => setParamRules(tool.name, r)}
                      />
                    </div>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </div>
  )
}
