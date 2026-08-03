const COLORS: Record<string, string> = {
  ALLOWED: 'var(--color-teal-500)',
  BLOCKED: '#c0524b',
  PASSTHROUGH: 'var(--text-muted)',
  ERROR: 'var(--gold)',
}

export function DecisionBadge({ decision }: { decision: string }) {
  const color = COLORS[decision] ?? 'var(--text-muted)'
  return (
    <span
      className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium"
      style={{ background: `color-mix(in srgb, ${color} 16%, transparent)`, color }}
    >
      {decision}
    </span>
  )
}
