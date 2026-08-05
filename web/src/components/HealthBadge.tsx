interface HealthBadgeProps {
  status: string
}

const DOT_COLOR: Record<string, string> = {
  healthy: 'var(--success)',
  unhealthy: 'var(--danger)',
  unknown: 'var(--text-muted)',
}

export function HealthBadge({ status }: HealthBadgeProps) {
  const color = DOT_COLOR[status] ?? DOT_COLOR.unknown
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color }}>
      <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {status}
    </span>
  )
}

export function ProtocolBadge({ protocol }: { protocol: string | null }) {
  if (!protocol) {
    return (
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        —
      </span>
    )
  }
  const isNewGen = protocol.startsWith('2026')
  return (
    <span
      className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium"
      style={{
        background: isNewGen
          ? 'color-mix(in srgb, var(--gold) 18%, transparent)'
          : 'color-mix(in srgb, var(--accent) 14%, transparent)',
        color: isNewGen ? 'var(--gold)' : 'var(--accent)',
      }}
    >
      {protocol}
    </span>
  )
}
