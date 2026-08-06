import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { configApi } from '../api/settings'
import { ApiError } from '../api/client'
import type { ConfigImportResponse } from '../api/types'

const KIND_COLOR: Record<string, string> = {
  create: 'var(--success)',
  update: 'var(--gold)',
  unchanged: 'var(--text-muted)',
}

export function ConfigurationCard() {
  const queryClient = useQueryClient()
  const [includeCredentials, setIncludeCredentials] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [yamlText, setYamlText] = useState<string | null>(null)
  const [preview, setPreview] = useState<ConfigImportResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function reset() {
    setFileName(null)
    setYamlText(null)
    setPreview(null)
    setError(null)
  }

  async function handleFile(file: File) {
    reset()
    const text = await file.text()
    setFileName(file.name)
    setYamlText(text)
    setBusy(true)
    try {
      // Always dry-run on select. The operator never gets a one-click destructive path:
      // seeing the diff is a prerequisite for the Apply button existing at all.
      setPreview(await configApi.import(text, false))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not read that file.')
    } finally {
      setBusy(false)
    }
  }

  async function handleApply() {
    if (!yamlText) return
    setBusy(true)
    setError(null)
    try {
      const result = await configApi.import(yamlText, true)
      setPreview(result)
      if (result.applied) {
        // Config just changed underneath every cached view — servers, policies and settings
        // are all potentially stale now.
        queryClient.invalidateQueries()
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Import failed.')
    } finally {
      setBusy(false)
    }
  }

  const changeCount = preview?.actions.filter((a) => a.kind !== 'unchanged').length ?? 0

  return (
    <div className="card p-5 space-y-4">
      <div>
        <h2 className="text-sm font-semibold">Configuration</h2>
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
          Servers, policies and gateway settings as a single reviewable YAML file — for diffing in
          git or moving to another instance. API keys are never exported. For disaster recovery,
          take a database backup instead.
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-3">
          <a href={configApi.exportUrl(includeCredentials)} download className="btn-secondary rounded-md px-3 py-1.5 text-xs font-medium">
            Export configuration
          </a>
          <label className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
            <input
              type="checkbox"
              checked={includeCredentials}
              onChange={(e) => setIncludeCredentials(e.target.checked)}
            />
            Include upstream credentials
          </label>
        </div>
        {includeCredentials && (
          <p className="text-xs" style={{ color: 'var(--danger)' }}>
            The exported file will contain plaintext credentials. Treat it as a secret — don't
            commit it to version control.
          </p>
        )}
      </div>

      <div className="space-y-2 pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
        <label className="block text-xs font-medium">Import configuration</label>
        <input
          type="file"
          accept=".yaml,.yml,text/yaml"
          className="text-xs"
          onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) handleFile(file)
          }}
        />
        {fileName && (
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {fileName}
            {busy && ' — checking…'}
          </p>
        )}

        {error && (
          <p className="text-xs" style={{ color: 'var(--danger)' }}>
            {error}
          </p>
        )}

        {preview && preview.errors.length > 0 && (
          <div className="text-xs space-y-1">
            <p style={{ color: 'var(--danger)' }}>
              This file was rejected — nothing was changed:
            </p>
            <ul className="list-disc pl-4" style={{ color: 'var(--danger)' }}>
              {preview.errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </div>
        )}

        {preview && preview.ok && (
          <div className="text-xs space-y-2">
            <ul className="space-y-0.5">
              {preview.actions.map((a) => (
                <li key={`${a.kind}-${a.target}`} style={{ color: KIND_COLOR[a.kind] }}>
                  {a.description}
                </li>
              ))}
            </ul>
            {preview.warnings.map((w) => (
              <p key={w} style={{ color: 'var(--text-muted)' }}>
                {w}
              </p>
            ))}

            {preview.applied ? (
              <p style={{ color: 'var(--success)' }}>Import applied.</p>
            ) : changeCount === 0 ? (
              <p style={{ color: 'var(--text-muted)' }}>
                Nothing to apply — this file matches the current configuration.
              </p>
            ) : (
              <div className="flex items-center gap-2">
                {/* Second, explicit click: the preview above is the first step, this is the
                    confirmation. Import overwrites live policy, so it must never be one action. */}
                <button
                  type="button"
                  onClick={handleApply}
                  disabled={busy}
                  className="btn-primary rounded-md px-3 py-1.5 text-xs font-medium disabled:opacity-60"
                >
                  {busy ? 'Applying…' : `Apply ${changeCount} change${changeCount === 1 ? '' : 's'}`}
                </button>
                <button type="button" onClick={reset} className="btn-secondary rounded-md px-3 py-1.5 text-xs font-medium">
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
