import { useState } from 'react'
import { DLP_DETECTORS } from '../api/types'
import type { DlpAction, DlpCustomPattern } from '../api/types'

const ACTIONS: DlpAction[] = ['allow', 'redact', 'block']

function ActionSelect({
  value,
  onChange,
}: {
  value: DlpAction
  onChange: (action: DlpAction) => void
}) {
  return (
    <select
      className="rounded px-2 py-1 text-xs"
      value={value}
      onChange={(e) => onChange(e.target.value as DlpAction)}
    >
      {ACTIONS.map((action) => (
        <option key={action} value={action}>
          {action}
        </option>
      ))}
    </select>
  )
}

/**
 * DLP section for the server detail page (enterprise #10). Every detector defaults to OFF —
 * "off" here means absent from `detectors`, not present with action='allow' (both behave
 * identically on the wire, but leaving unconfigured detectors out of the map keeps the saved
 * policy diffable and matches the backend's own "no dlp_detectors configured" regression
 * invariant). Toggling a detector on starts it at 'redact', the action the plan calls out as
 * the actual differentiator over a block-only rule.
 */
export function DlpEditor({
  detectors,
  customPatterns,
  onChange,
}: {
  detectors: Record<string, DlpAction>
  customPatterns: DlpCustomPattern[]
  onChange: (detectors: Record<string, DlpAction>, customPatterns: DlpCustomPattern[]) => void
}) {
  const [newPatternName, setNewPatternName] = useState('')
  const [newPatternRegex, setNewPatternRegex] = useState('')

  function toggleDetector(name: string, enabled: boolean) {
    const next = { ...detectors }
    if (enabled) {
      next[name] = 'redact'
    } else {
      delete next[name]
    }
    onChange(next, customPatterns)
  }

  function setDetectorAction(name: string, action: DlpAction) {
    onChange({ ...detectors, [name]: action }, customPatterns)
  }

  function addCustomPattern() {
    if (!newPatternName.trim() || !newPatternRegex.trim()) return
    onChange(detectors, [
      ...customPatterns,
      { name: newPatternName.trim(), pattern: newPatternRegex.trim(), action: 'block' },
    ])
    setNewPatternName('')
    setNewPatternRegex('')
  }

  function updateCustomPattern(index: number, patch: Partial<DlpCustomPattern>) {
    const next = customPatterns.map((p, i) => (i === index ? { ...p, ...patch } : p))
    onChange(detectors, next)
  }

  function removeCustomPattern(index: number) {
    onChange(
      detectors,
      customPatterns.filter((_, i) => i !== index),
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <p className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
          Scan tool call arguments for sensitive values before they reach the upstream. Every
          detector is off by default — enabling one only affects THIS server. "redact" replaces
          the matched span and lets the call proceed; "block" refuses the call outright.
        </p>
        <ul className="space-y-1.5">
          {DLP_DETECTORS.map(({ name, label }) => {
            const enabled = name in detectors
            return (
              <li key={name} className="flex items-center justify-between gap-3 text-xs">
                <label className="flex items-center gap-2 min-w-0">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => toggleDetector(name, e.target.checked)}
                  />
                  <span className="truncate">{label}</span>
                </label>
                {enabled && (
                  <ActionSelect
                    value={detectors[name]}
                    onChange={(action) => setDetectorAction(name, action)}
                  />
                )}
              </li>
            )
          })}
        </ul>
      </div>

      <div>
        <h3 className="text-xs font-semibold mb-1.5">Custom patterns</h3>
        {customPatterns.length > 0 && (
          <ul className="space-y-1.5 mb-2">
            {customPatterns.map((pattern, index) => (
              <li key={index} className="flex items-center gap-2 text-xs">
                <span className="font-mono font-medium shrink-0">{pattern.name}</span>
                <span
                  className="font-mono truncate flex-1"
                  style={{ color: 'var(--text-muted)' }}
                  title={pattern.pattern}
                >
                  {pattern.pattern}
                </span>
                <ActionSelect
                  value={pattern.action}
                  onChange={(action) => updateCustomPattern(index, { action })}
                />
                <button
                  type="button"
                  onClick={() => removeCustomPattern(index)}
                  style={{ color: 'var(--danger)' }}
                >
                  remove
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex items-center gap-2">
          <input
            className="rounded px-2 py-1 text-xs font-mono w-32"
            placeholder="name"
            value={newPatternName}
            onChange={(e) => setNewPatternName(e.target.value)}
          />
          <input
            className="rounded px-2 py-1 text-xs font-mono flex-1"
            placeholder="regex pattern"
            value={newPatternRegex}
            onChange={(e) => setNewPatternRegex(e.target.value)}
          />
          <button type="button" onClick={addCustomPattern} className="btn-secondary rounded px-2 py-1 text-xs">
            + pattern
          </button>
        </div>
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
          Operator-supplied patterns are matched with the same ReDoS-safe timeout as param rule
          block patterns — a pathological regex times out and fails closed (blocks) rather than
          hanging the request.
        </p>
      </div>
    </div>
  )
}
