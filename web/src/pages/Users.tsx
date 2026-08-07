import { useState } from 'react'
import { Modal } from '../components/Modal'
import { ApiError } from '../api/client'
import type { Role } from '../api/types'
import { useCreateUser, useCurrentUser, useSetUserEnabled, useSetUserRole, useUsers } from '../lib/useUsers'

const ROLES: Role[] = ['viewer', 'operator', 'admin']

function CreateUserModal({ onClose }: { onClose: () => void }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [error, setError] = useState<string | null>(null)
  const create = useCreateUser()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    create.mutate(
      { username, password, role, email: email || undefined },
      {
        onSuccess: () => onClose(),
        onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong'),
      },
    )
  }

  return (
    <Modal title="Invite user" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="user-username">
            Username
          </label>
          <input
            id="user-username"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            required
          />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="user-email">
            Email (optional)
          </label>
          <input
            id="user-email"
            type="email"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="user-password">
            Temporary password
          </label>
          <input
            id="user-password"
            type="password"
            autoComplete="new-password"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={8}
            required
          />
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            At least 8 characters. The new user should change this after signing in.
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="user-role">
            Role
          </label>
          <select
            id="user-role"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
        {error && (
          <p className="text-sm" style={{ color: 'var(--danger)' }}>
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary rounded-md px-4 py-2 text-sm font-medium">
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary rounded-md px-4 py-2 text-sm font-medium disabled:opacity-60"
            disabled={create.isPending}
          >
            {create.isPending ? 'Creating…' : 'Create user'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function Users() {
  const { data: users, isLoading, isError } = useUsers()
  const { data: me } = useCurrentUser()
  const setRole = useSetUserRole()
  const setEnabled = useSetUserEnabled()
  const [showCreate, setShowCreate] = useState(false)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Users</h1>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="btn-primary rounded-md px-4 py-2 text-sm font-medium"
        >
          Invite user
        </button>
      </div>

      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        Roles are enforced by the server on every request — this page is for administering who has
        access, not the only thing standing between a role and what it can do.
      </p>

      {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}
      {isError && <p style={{ color: 'var(--danger)' }}>Could not load users.</p>}

      {users && users.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: 'var(--border)' }}>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Username
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Email
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Auth
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Role
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Last login
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const isSelf = me?.user_id === user.id
                return (
                  <tr key={user.id} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                    <td className="px-4 py-3 font-medium">
                      {user.username}
                      {isSelf && (
                        <span className="ml-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                          (you)
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {user.email ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {user.auth_source}
                    </td>
                    <td className="px-4 py-3">
                      <select
                        className="rounded-md px-2 py-1 text-xs"
                        value={user.role}
                        disabled={setRole.isPending}
                        onChange={(e) => setRole.mutate({ id: user.id, role: e.target.value as Role })}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        disabled={isSelf}
                        title={isSelf ? "You can't disable your own account" : undefined}
                        onClick={() => setEnabled.mutate({ id: user.id, enabled: !user.enabled })}
                        className="text-xs font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                        style={{ color: user.enabled ? 'var(--success)' : 'var(--text-muted)' }}
                      >
                        {user.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}
