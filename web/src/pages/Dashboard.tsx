import { Link } from 'react-router'
import { useStats } from '../lib/useStats'
import { StatTile } from '../components/StatTile'
import { HealthBadge, ProtocolBadge } from '../components/HealthBadge'

export function Dashboard() {
  const { data: stats, isLoading, isError } = useStats()

  if (isLoading) {
    return <p style={{ color: 'var(--text-muted)' }}>Loading…</p>
  }

  if (isError || !stats) {
    return <p style={{ color: 'var(--danger)' }}>Could not load stats.</p>
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Dashboard</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatTile label="Requests (24h)" value={stats.requests_24h} />
        <StatTile label="Blocked (24h)" value={stats.blocked_24h} accent={stats.blocked_24h > 0 ? 'danger' : 'default'} />
        <StatTile label="Allowed (24h)" value={stats.allowed_24h} />
        <StatTile
          label="Servers"
          value={`${stats.servers_healthy}/${stats.servers_total}`}
          accent={stats.servers_unhealthy > 0 ? 'danger' : 'default'}
        />
      </div>

      <div className="card">
        <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
          <h2 className="text-sm font-semibold">Server health</h2>
          <Link to="/servers" className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
            Manage servers →
          </Link>
        </div>
        {stats.server_health.length === 0 ? (
          <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            No servers registered yet.{' '}
            <Link to="/servers" style={{ color: 'var(--accent)' }}>
              Add one
            </Link>
            .
          </p>
        ) : (
          <ul>
            {stats.server_health.map((s) => (
              <li
                key={s.slug}
                className="px-4 py-3 flex items-center justify-between border-b last:border-b-0"
                style={{ borderColor: 'var(--border)' }}
              >
                <Link to={`/servers/${s.slug}`} className="font-medium text-sm hover:underline">
                  {s.slug}
                </Link>
                <div className="flex items-center gap-3">
                  <ProtocolBadge protocol={s.upstream_protocol} />
                  <HealthBadge status={s.health_status} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card">
        <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
          <h2 className="text-sm font-semibold">Recently blocked</h2>
          <Link to="/audit" className="text-xs font-medium" style={{ color: 'var(--accent)' }}>
            View audit log →
          </Link>
        </div>
        {stats.recent_blocked.length === 0 ? (
          <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            Nothing blocked recently.
          </p>
        ) : (
          <ul>
            {stats.recent_blocked.map((event) => (
              <li
                key={event.id}
                className="px-4 py-3 border-b last:border-b-0 text-sm"
                style={{ borderColor: 'var(--border)' }}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium">
                    {event.server_slug ?? 'aggregate'} · {event.tool ?? event.rpc_method}
                  </span>
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {new Date(event.ts).toLocaleTimeString()}
                  </span>
                </div>
                {event.reason && (
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    {event.reason}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
