import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { setupApi } from '../api/settings'
import { ApiError } from '../api/client'
import { useOidcStatus } from '../lib/useUsers'

export function Login() {
  const queryClient = useQueryClient()
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const { data: oidcStatus } = useOidcStatus()

  const login = useMutation({
    mutationFn: () => setupApi.login(password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['session'] })
      window.location.href = '/'
    },
    onError: (err) => {
      setError(err instanceof ApiError ? 'Incorrect password' : 'Something went wrong')
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    login.mutate()
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="card w-full max-w-sm p-8">
        <div className="flex items-center gap-2 mb-6">
          <span
            className="inline-flex h-8 w-8 items-center justify-center rounded-full text-base font-bold"
            style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
          >
            A
          </span>
          <h1 className="text-lg font-semibold">Sign in to Acropolis</h1>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" htmlFor="password">
              Admin password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              autoFocus
              className="w-full rounded-md px-3 py-2 text-sm"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && (
            <p className="text-sm" style={{ color: 'var(--danger)' }}>
              {error}
            </p>
          )}
          <button
            type="submit"
            className="btn-primary w-full rounded-md py-2 text-sm font-medium disabled:opacity-60"
            disabled={login.isPending}
          >
            {login.isPending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        {oidcStatus?.enabled && oidcStatus.login_url && (
          <>
            <div className="flex items-center gap-3 my-4">
              <div className="flex-1 border-t" style={{ borderColor: 'var(--border)' }} />
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                or
              </span>
              <div className="flex-1 border-t" style={{ borderColor: 'var(--border)' }} />
            </div>
            {/* A plain navigation, not a fetch — /auth/oidc/login issues a 302 to the IdP's
                authorization endpoint, which only makes sense as a real browser navigation. */}
            <a
              href={oidcStatus.login_url}
              className="btn-secondary w-full rounded-md py-2 text-sm font-medium flex items-center justify-center"
            >
              Sign in with SSO
            </a>
          </>
        )}
      </div>
    </div>
  )
}
