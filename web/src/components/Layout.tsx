import { NavLink, Outlet } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { setupApi } from '../api/settings'
import { useCurrentUser } from '../lib/useUsers'
import { hasRole, type Role } from '../api/types'

const navItems: { to: string; label: string; end?: boolean; minRole?: Role }[] = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/servers', label: 'Servers' },
  { to: '/keys', label: 'API Keys', minRole: 'admin' },
  { to: '/usage', label: 'Usage' },
  { to: '/audit', label: 'Audit' },
  { to: '/users', label: 'Users', minRole: 'admin' },
  { to: '/settings', label: 'Settings' },
]

export function Layout() {
  const queryClient = useQueryClient()
  const { data: me } = useCurrentUser()
  const logout = useMutation({
    mutationFn: () => setupApi.logout(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['setup-status'] })
      window.location.href = '/'
    },
  })

  // Role-aware hiding is a COURTESY, not the enforcement boundary — every one of these routes'
  // mutating calls still gets a real 403 from the server if this check is ever wrong, bypassed,
  // or simply stale (see api/types.ts's hasRole). A viewer never sees "API Keys" or "Users" in
  // the nav; that's the whole of what this buys, and it's meant to buy exactly that much.
  const visibleNavItems = navItems.filter((item) => !item.minRole || hasRole(me?.role, item.minRole))

  return (
    <div className="flex min-h-screen">
      <aside
        className="w-56 shrink-0 border-r flex flex-col"
        style={{ borderColor: 'var(--border)', background: 'var(--bg-elevated)' }}
      >
        <div className="px-5 py-5 flex items-center gap-2">
          <span
            className="inline-flex h-7 w-7 items-center justify-center rounded-full text-sm font-bold"
            style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
          >
            A
          </span>
          <span className="font-semibold tracking-tight">Acropolis</span>
        </div>
        <nav className="flex-1 px-2 space-y-0.5">
          {visibleNavItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive ? 'nav-active' : 'nav-inactive'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t" style={{ borderColor: 'var(--border)' }}>
          {me && (
            <div className="px-3 pt-2 pb-1">
              <p className="text-sm font-medium truncate">{me.username ?? 'admin (legacy)'}</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {me.role}
                {me.auth_source === 'admin-token' && ' · break-glass token'}
                {me.auth_source === 'oidc' && ' · SSO'}
              </p>
            </div>
          )}
          <button
            type="button"
            onClick={() => logout.mutate()}
            className="w-full rounded-md px-3 py-2 text-sm font-medium text-left"
            style={{ color: 'var(--text-muted)' }}
          >
            Log out
          </button>
        </div>
      </aside>
      <main className="flex-1 min-w-0 p-8">
        <Outlet />
      </main>
    </div>
  )
}
