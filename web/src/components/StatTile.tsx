interface StatTileProps {
  label: string
  value: string | number
  accent?: 'default' | 'danger'
}

export function StatTile({ label, value, accent = 'default' }: StatTileProps) {
  return (
    <div className="card p-4">
      <div className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div
        className="text-2xl font-semibold mt-1"
        style={{ color: accent === 'danger' ? '#c0524b' : 'var(--text)' }}
      >
        {value}
      </div>
    </div>
  )
}
