import { useState } from 'react'
import { Link } from 'react-router'
import { useCreateServer, useServers } from '../lib/useServers'
import { HealthBadge, ProtocolBadge } from '../components/HealthBadge'
import { Modal } from '../components/Modal'
import { ApiError } from '../api/client'

function slugify(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

function AddServerModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [upstreamUrl, setUpstreamUrl] = useState('')
  const [error, setError] = useState<string | null>(null)
  const create = useCreateServer()

  function handleNameChange(value: string) {
    setName(value)
    if (!slugTouched) setSlug(slugify(value))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    create.mutate(
      { slug, name, upstream_url: upstreamUrl },
      {
        onSuccess: onClose,
        onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong'),
      },
    )
  }

  return (
    <Modal title="Add server" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="name">
            Name
          </label>
          <input
            id="name"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={name}
            onChange={(e) => handleNameChange(e.target.value)}
            placeholder="Filesystem"
            required
          />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="slug">
            Slug
          </label>
          <input
            id="slug"
            className="w-full rounded-md px-3 py-2 text-sm font-mono"
            value={slug}
            onChange={(e) => {
              setSlugTouched(true)
              setSlug(slugify(e.target.value))
            }}
            placeholder="filesystem"
            pattern="[a-z0-9-]+"
            required
          />
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            Used in the endpoint URL: /mcp/{slug || '{slug}'}
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="upstream_url">
            Upstream URL
          </label>
          <input
            id="upstream_url"
            className="w-full rounded-md px-3 py-2 text-sm font-mono"
            value={upstreamUrl}
            onChange={(e) => setUpstreamUrl(e.target.value)}
            placeholder="http://localhost:8010/mcp"
            required
          />
        </div>
        {error && (
          <p className="text-sm" style={{ color: '#c0524b' }}>
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
            {create.isPending ? 'Adding…' : 'Add server'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function Servers() {
  const { data: servers, isLoading, isError } = useServers()
  const [showAdd, setShowAdd] = useState(false)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Servers</h1>
        <button
          type="button"
          onClick={() => setShowAdd(true)}
          className="btn-primary rounded-md px-4 py-2 text-sm font-medium"
        >
          Add server
        </button>
      </div>

      {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}
      {isError && <p style={{ color: '#c0524b' }}>Could not load servers.</p>}

      {servers && servers.length === 0 && (
        <div className="card p-8 text-center">
          <p style={{ color: 'var(--text-muted)' }}>No servers registered yet.</p>
        </div>
      )}

      {servers && servers.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: 'var(--border)' }}>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Slug
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Upstream
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Protocol
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Health
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Enabled
                </th>
              </tr>
            </thead>
            <tbody>
              {servers.map((server) => (
                <tr key={server.slug} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                  <td className="px-4 py-3">
                    <Link to={`/servers/${server.slug}`} className="font-medium hover:underline">
                      {server.slug}
                    </Link>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    {server.upstream_url}
                  </td>
                  <td className="px-4 py-3">
                    <ProtocolBadge protocol={server.upstream_protocol} />
                  </td>
                  <td className="px-4 py-3">
                    <HealthBadge status={server.health_status} />
                  </td>
                  <td className="px-4 py-3">{server.enabled ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && <AddServerModal onClose={() => setShowAdd(false)} />}
    </div>
  )
}
