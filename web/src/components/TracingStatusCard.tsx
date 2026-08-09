import { useTracingStatus } from '../lib/useSettings'

// Enterprise #9 (OpenTelemetry tracing). Deliberately read-only — tracing is an
// ACROPOLIS_OTEL_ENABLED environment-variable gate plus standard OTEL_EXPORTER_OTLP_* env vars
// (see docs/observability.md), not a UI-toggleable setting, so this card has no form controls
// and no save button, unlike ConfigurationCard/AlertsCard on this same page. It exists purely so
// an operator can confirm from the Settings page whether tracing is actually active, without
// needing shell access to check environment variables or grep startup logs.
export function TracingStatusCard() {
  const { data: status, isLoading } = useTracingStatus()

  if (isLoading || !status) return null

  const { enabled, active, sample_ratio: sampleRatio } = status

  let indicator: { label: string; color: string }
  if (active) {
    indicator = { label: 'Active', color: 'var(--success)' }
  } else if (enabled) {
    // Operator set ACROPOLIS_OTEL_ENABLED=true but the `otel` extra isn't installed — a real,
    // actionable misconfiguration, distinct from "tracing was never turned on."
    indicator = { label: 'Enabled, but not active', color: 'var(--danger)' }
  } else {
    indicator = { label: 'Disabled', color: 'var(--text-muted)' }
  }

  return (
    <div className="card p-5 space-y-3">
      <h2 className="text-sm font-semibold">Distributed tracing (OpenTelemetry)</h2>
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Configured via the <code>ACROPOLIS_OTEL_ENABLED</code> environment variable and standard{' '}
        <code>OTEL_EXPORTER_OTLP_*</code> variables, not from this page — see{' '}
        <code>docs/observability.md</code> for setup.
      </p>
      <div className="flex items-center gap-2 text-sm">
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{ background: indicator.color }}
          aria-hidden="true"
        />
        <span className="font-medium">{indicator.label}</span>
      </div>
      {active && (
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Sample ratio: {sampleRatio}
        </p>
      )}
      {enabled && !active && (
        <p className="text-xs" style={{ color: 'var(--danger)' }}>
          The <code>otel</code> optional dependency group is not installed on this instance —
          spans are not being exported. Install with <code>pip install acropolis[otel]</code> and
          restart.
        </p>
      )}
    </div>
  )
}
