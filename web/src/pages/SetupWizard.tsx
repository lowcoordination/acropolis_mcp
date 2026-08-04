import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { setupApi } from '../api/settings'
import { ApiError } from '../api/client'

export function SetupWizard() {
  const queryClient = useQueryClient()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [authMode, setAuthMode] = useState<'open' | 'keyed'>('keyed')
  const [error, setError] = useState<string | null>(null)

  const setup = useMutation({
    mutationFn: () => setupApi.complete(password, authMode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['setup-status'] })
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : 'Something went wrong')
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match')
      return
    }
    setup.mutate()
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="card w-full max-w-md p-8">
        <div className="flex items-center gap-2 mb-1">
          <span
            className="inline-flex h-8 w-8 items-center justify-center rounded-full text-base font-bold"
            style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
          >
            A
          </span>
          <h1 className="text-lg font-semibold">Welcome to Acropolis</h1>
        </div>
        <p className="text-sm mb-6" style={{ color: 'var(--text-muted)' }}>
          Set an admin password to finish setting up your gateway.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" htmlFor="password">
              Admin password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="new-password"
              className="w-full rounded-md px-3 py-2 text-sm"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1" htmlFor="confirm">
              Confirm password
            </label>
            <input
              id="confirm"
              type="password"
              autoComplete="new-password"
              className="w-full rounded-md px-3 py-2 text-sm"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1" htmlFor="auth-mode">
              Data-plane authentication
            </label>
            <select
              id="auth-mode"
              className="w-full rounded-md px-3 py-2 text-sm"
              value={authMode}
              onChange={(e) => setAuthMode(e.target.value as 'open' | 'keyed')}
            >
              <option value="keyed">Keyed — require an API key on /mcp/* (recommended)</option>
              <option value="open">Open — no key required (trusted LAN only)</option>
            </select>
          </div>

          {error && (
            <p className="text-sm" style={{ color: '#c0524b' }}>
              {error}
            </p>
          )}

          <button
            type="submit"
            className="btn-primary w-full rounded-md py-2 text-sm font-medium disabled:opacity-60"
            disabled={setup.isPending}
          >
            {setup.isPending ? 'Setting up…' : 'Finish setup'}
          </button>
        </form>
      </div>
    </div>
  )
}
