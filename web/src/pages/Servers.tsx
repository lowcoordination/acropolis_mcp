import { useState } from 'react'
import { Link } from 'react-router'
import { useCreateServer, useServers } from '../lib/useServers'
import { useSettings } from '../lib/useSettings'
import { useActiveProject } from '../lib/ProjectContext'
import { useProjects } from '../lib/useProjects'
import { HealthBadge, ProtocolBadge } from '../components/HealthBadge'
import { CredentialBadge } from '../components/CredentialBadge'
import { Modal } from '../components/Modal'
import { ApiError } from '../api/client'

function slugify(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

// Enterprise #5: a bare heuristic for "does this look like a vault:// reference" purely to
// adjust the placeholder/hint text as the operator types — NOT validation (the backend is the
// real authority on the shape; archon/secrets/openbao.py's parse_vault_ref is the actual parser).
function looksLikeReference(value: string): boolean {
  return value.startsWith('vault://') || value.startsWith('enc:v1:')
}

function AddServerModal({ onClose, defaultProjectSlug }: { onClose: () => void; defaultProjectSlug?: string }) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [upstreamUrl, setUpstreamUrl] = useState('')
  const [upstreamAuthHeader, setUpstreamAuthHeader] = useState('')
  const [projectSlug, setProjectSlug] = useState(defaultProjectSlug ?? 'default')
  const [error, setError] = useState<string | null>(null)
  const create = useCreateServer()
  const { data: settings } = useSettings()
  const { data: projects } = useProjects()

  function handleNameChange(value: string) {
    setName(value)
    if (!slugTouched) setSlug(slugify(value))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    create.mutate(
      {
        slug,
        name,
        upstream_url: upstreamUrl,
        project_slug: projectSlug,
        ...(upstreamAuthHeader ? { upstream_auth_header: upstreamAuthHeader } : {}),
      },
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
        {projects && projects.length > 1 && (
          <div>
            <label className="block text-sm font-medium mb-1" htmlFor="project">
              Project
            </label>
            <select
              id="project"
              className="w-full rounded-md px-3 py-2 text-sm"
              value={projectSlug}
              onChange={(e) => setProjectSlug(e.target.value)}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.slug}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>
        )}
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
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="upstream_auth_header">
            Upstream credential <span style={{ color: 'var(--text-muted)' }}>(optional)</span>
          </label>
          <input
            id="upstream_auth_header"
            className="w-full rounded-md px-3 py-2 text-sm font-mono"
            value={upstreamAuthHeader}
            onChange={(e) => setUpstreamAuthHeader(e.target.value)}
            placeholder={
              settings?.secret_provider === 'openbao'
                ? 'vault://secret/acropolis/<slug>#token'
                : 'Bearer sk-... (or vault://mount/path#key)'
            }
            autoComplete="off"
          />
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            {settings?.secret_provider === 'openbao' ? (
              <>
                Active provider: <span className="font-mono">openbao</span> — paste a{' '}
                <span className="font-mono">vault://mount/path#key</span> reference to a secret you've
                already written to Vault/OpenBao. A literal value is stored as-is, unresolved.
              </>
            ) : settings?.secret_provider === 'encrypted' ? (
              <>
                Active provider: <span className="font-mono">encrypted</span> — a literal Authorization
                header value is encrypted at rest automatically. A{' '}
                <span className="font-mono">vault://</span> reference is stored as-is.
              </>
            ) : (
              <>
                Sent as the <span className="font-mono">Authorization</span> header on requests to this
                server's upstream. Never shown again after saving.
              </>
            )}
            {upstreamAuthHeader && looksLikeReference(upstreamAuthHeader) && (
              <>
                {' '}
                This looks like a secret reference, not a literal credential — it will be exported and
                displayed as configuration, not treated as a secret.
              </>
            )}
          </p>
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
            {create.isPending ? 'Adding…' : 'Add server'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function Servers() {
  const { activeProjectId } = useActiveProject()
  const { data: projects } = useProjects()
  const { data: servers, isLoading, isError } = useServers(activeProjectId)
  const [showAdd, setShowAdd] = useState(false)
  const showProjectColumn = !!projects && projects.length > 1
  const activeProject = projects?.find((p) => p.id === activeProjectId)

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
      {isError && <p style={{ color: 'var(--danger)' }}>Could not load servers.</p>}

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
                {showProjectColumn && (
                  <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                    Project
                  </th>
                )}
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
                  Credential
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
                  {showProjectColumn && (
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {server.project_slug ?? '—'}
                    </td>
                  )}
                  <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    {server.upstream_url}
                  </td>
                  <td className="px-4 py-3">
                    <ProtocolBadge protocol={server.upstream_protocol} />
                  </td>
                  <td className="px-4 py-3">
                    <HealthBadge status={server.health_status} />
                    {server.health_status === 'unhealthy' && server.health_reason && (
                      <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }} title={server.health_reason}>
                        {server.health_reason.length > 40
                          ? `${server.health_reason.slice(0, 40)}…`
                          : server.health_reason}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <CredentialBadge
                      hasCredential={server.has_upstream_auth_header}
                      isReference={server.upstream_auth_header_is_reference}
                    />
                  </td>
                  <td className="px-4 py-3">{server.enabled ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && (
        <AddServerModal onClose={() => setShowAdd(false)} defaultProjectSlug={activeProject?.slug} />
      )}
    </div>
  )
}
