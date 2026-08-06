import { useState } from 'react'
import { useTestCall } from '../lib/useServers'
import { DecisionBadge } from './DecisionBadge'
import type { JsonSchema, JsonSchemaProperty } from '../api/types'

/** Scope guard (from the plan): render simple scalar fields only — string/number/boolean/enum,
 * with required marking. Anything else (nested objects, arrays, oneOf/anyOf, …) falls back to a
 * raw JSON textarea rather than growing into a general JSON Schema form engine. */
function isRenderable(schema: JsonSchema | null): boolean {
  if (!schema || schema.type !== 'object' || !schema.properties) return false
  return Object.values(schema.properties).every((p) => {
    if (p.enum) return true
    return p.type === 'string' || p.type === 'number' || p.type === 'integer' || p.type === 'boolean'
  })
}

function coerce(prop: JsonSchemaProperty, raw: string): unknown {
  if (prop.enum) return raw
  if (prop.type === 'boolean') return raw === 'true'
  if (prop.type === 'number' || prop.type === 'integer') {
    if (raw.trim() === '') return undefined
    const n = Number(raw)
    return Number.isNaN(n) ? raw : n
  }
  return raw
}

export function ToolTester({ slug, tool, schema }: { slug: string; tool: string; schema: JsonSchema | null }) {
  const testCall = useTestCall(slug)
  const renderable = isRenderable(schema)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [rawJson, setRawJson] = useState('{}')
  const [jsonError, setJsonError] = useState<string | null>(null)

  const properties = schema?.properties ?? {}
  const required = new Set(schema?.required ?? [])

  function run() {
    setJsonError(null)
    let args: Record<string, unknown>

    if (renderable) {
      args = {}
      for (const [name, prop] of Object.entries(properties)) {
        const raw = fields[name]
        // Omit untouched optional fields entirely rather than sending empty strings — the
        // upstream's own schema defaults should apply, and a spurious "" can itself trip a
        // param rule the operator is trying to test.
        if (raw === undefined || (raw === '' && !required.has(name))) continue
        const value = coerce(prop, raw)
        if (value !== undefined) args[name] = value
      }
    } else {
      try {
        const parsed = JSON.parse(rawJson)
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          setJsonError('Arguments must be a JSON object.')
          return
        }
        args = parsed as Record<string, unknown>
      } catch (e) {
        setJsonError(e instanceof Error ? e.message : 'Invalid JSON')
        return
      }
    }

    testCall.mutate({ tool, args })
  }

  const result = testCall.data

  return (
    <div className="mt-2 pl-4 border-l-2 space-y-2" style={{ borderColor: 'var(--border)' }}>
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Runs through the real policy pipeline as the logged-in admin. This tests <em>policy</em>,
        not API-key auth — a keyed gateway still requires a key for real clients.
      </p>

      {renderable ? (
        <div className="space-y-1.5">
          {Object.entries(properties).map(([name, prop]) => (
            <label key={name} className="flex items-center gap-2 text-xs">
              <span className="font-mono w-32 shrink-0">
                {name}
                {required.has(name) && <span style={{ color: 'var(--danger)' }}> *</span>}
              </span>
              {prop.enum ? (
                <select
                  className="rounded px-1.5 py-0.5 text-xs flex-1"
                  value={fields[name] ?? ''}
                  onChange={(e) => setFields((f) => ({ ...f, [name]: e.target.value }))}
                >
                  <option value="">—</option>
                  {prop.enum.map((opt) => (
                    <option key={String(opt)} value={String(opt)}>
                      {String(opt)}
                    </option>
                  ))}
                </select>
              ) : prop.type === 'boolean' ? (
                <select
                  className="rounded px-1.5 py-0.5 text-xs flex-1"
                  value={fields[name] ?? ''}
                  onChange={(e) => setFields((f) => ({ ...f, [name]: e.target.value }))}
                >
                  <option value="">—</option>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              ) : (
                <input
                  className="rounded px-1.5 py-0.5 text-xs flex-1 font-mono"
                  type={prop.type === 'number' || prop.type === 'integer' ? 'number' : 'text'}
                  placeholder={prop.description ?? prop.type ?? ''}
                  value={fields[name] ?? ''}
                  onChange={(e) => setFields((f) => ({ ...f, [name]: e.target.value }))}
                />
              )}
            </label>
          ))}
          {Object.keys(properties).length === 0 && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              This tool takes no arguments.
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-1">
          <label className="text-xs">Arguments (JSON)</label>
          <textarea
            className="w-full rounded px-1.5 py-1 text-xs font-mono"
            rows={3}
            value={rawJson}
            onChange={(e) => setRawJson(e.target.value)}
          />
          {jsonError && (
            <p className="text-xs" style={{ color: 'var(--danger)' }}>
              {jsonError}
            </p>
          )}
        </div>
      )}

      <button
        type="button"
        onClick={run}
        disabled={testCall.isPending}
        className="btn-secondary rounded px-2 py-1 text-xs disabled:opacity-60"
      >
        {testCall.isPending ? 'Running…' : 'Run test call'}
      </button>

      {testCall.isError && (
        <p className="text-xs" style={{ color: 'var(--danger)' }}>
          Test call failed to run.
        </p>
      )}

      {result && (
        <div className="text-xs space-y-1">
          <div className="flex items-center gap-2">
            <DecisionBadge decision={result.decision} />
            {result.rule && <span style={{ color: 'var(--text-muted)' }}>rule: {result.rule}</span>}
            {result.latency_ms !== null && (
              <span style={{ color: 'var(--text-muted)' }}>{result.latency_ms}ms</span>
            )}
          </div>
          {result.reason && <div style={{ color: 'var(--text-muted)' }}>{result.reason}</div>}
          {result.matched && (
            <div className="font-mono" style={{ color: 'var(--text-muted)' }}>
              matched: {result.matched}
            </div>
          )}
          {result.upstream_response && (
            <pre
              className="rounded px-2 py-1 overflow-x-auto"
              style={{ background: 'var(--code-bg)', border: '1px solid var(--border)' }}
            >
              {JSON.stringify(result.upstream_response, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}
