import { NavLink, Outlet } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { setupApi } from '../api/settings'

const navItems = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/servers', label: 'Servers' },
  { to: '/keys', label: 'API Keys' },
  { to: '/audit', label: 'Audit' },
  { to: '/settings', label: 'Settings' },
]

export function Layout() {
  const queryClient = useQueryClient()
  const logout = useMutation({
    mutationFn: () => setupApi.logout(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['setup-status'] })
      window.location.href = '/'
    },
  })

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
          {navItems.map((item) => (
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
        <div className="p-3">
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
