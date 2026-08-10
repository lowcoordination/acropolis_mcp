import { useState } from 'react'
import { Modal } from '../components/Modal'
import { ApiError } from '../api/client'
import type { ProjectResponse, ProjectRole } from '../api/types'
import {
  useCreateProject,
  useDeleteProject,
  useProjectMembers,
  useProjects,
  useRemoveProjectMember,
  useUpsertProjectMember,
} from '../lib/useProjects'
import { useUsers } from '../lib/useUsers'

const PROJECT_ROLES: ProjectRole[] = ['viewer', 'poweruser', 'admin']

function CreateProjectModal({ onClose }: { onClose: () => void }) {
  const [slug, setSlug] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const create = useCreateProject()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    create.mutate(
      { slug, name },
      {
        onSuccess: () => onClose(),
        onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong'),
      },
    )
  }

  return (
    <Modal title="New project" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="project-slug">
            Slug
          </label>
          <input
            id="project-slug"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            placeholder="team-payments"
            pattern="[a-z0-9-]+"
            autoFocus
            required
          />
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            Lowercase letters, numbers, and hyphens only. Cannot be changed later.
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="project-name">
            Display name
          </label>
          <input
            id="project-name"
            className="w-full rounded-md px-3 py-2 text-sm"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
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
            {create.isPending ? 'Creating…' : 'Create project'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function MembersModal({ project, onClose }: { project: ProjectResponse; onClose: () => void }) {
  const { data: members, isLoading } = useProjectMembers(project.id)
  const { data: users } = useUsers()
  const upsert = useUpsertProjectMember(project.id)
  const remove = useRemoveProjectMember(project.id)
  const [addUserId, setAddUserId] = useState<number | ''>('')
  const [addRole, setAddRole] = useState<ProjectRole>('viewer')
  const [error, setError] = useState<string | null>(null)

  const memberUserIds = new Set(members?.map((m) => m.user_id))
  // GET /users is admin-only globally — a project admin who isn't a global admin/user-manager
  // won't have this list; fall back to typing a user id directly in that case rather than
  // hiding membership management entirely.
  const addableUsers = (users ?? []).filter((u) => !memberUserIds.has(u.id))

  function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (addUserId === '') return
    upsert.mutate(
      { userId: addUserId, role: addRole },
      { onError: (err) => setError(err instanceof ApiError ? err.message : 'Something went wrong') },
    )
  }

  return (
    <Modal title={`Members of ${project.name}`} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          Project role is independent of a user's global role — see docs/projects.md. A global
          admin can always administer this project even with no row here.
        </p>

        {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}

        {members && members.length > 0 && (
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left" style={{ borderColor: 'var(--border)' }}>
                  <th className="px-3 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                    User
                  </th>
                  <th className="px-3 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                    Project role
                  </th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.user_id} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                    <td className="px-3 py-2 font-medium">{m.username}</td>
                    <td className="px-3 py-2">
                      <select
                        className="rounded-md px-2 py-1 text-xs"
                        value={m.role}
                        disabled={upsert.isPending}
                        onChange={(e) =>
                          upsert.mutate({ userId: m.user_id, role: e.target.value as ProjectRole })
                        }
                      >
                        {PROJECT_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => remove.mutate(m.user_id)}
                        disabled={remove.isPending}
                        className="text-xs font-medium"
                        style={{ color: 'var(--danger)' }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {members && members.length === 0 && (
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            No explicit members yet — only global admins can access this project (via the
            superset), until someone is added below.
          </p>
        )}

        <form onSubmit={handleAdd} className="flex items-end gap-2 border-t pt-4" style={{ borderColor: 'var(--border)' }}>
          <div className="flex-1">
            <label className="block text-xs font-medium mb-1" htmlFor="add-member-user">
              Add member
            </label>
            {addableUsers.length > 0 ? (
              <select
                id="add-member-user"
                className="w-full rounded-md px-2 py-1.5 text-sm"
                value={addUserId}
                onChange={(e) => setAddUserId(e.target.value ? Number(e.target.value) : '')}
              >
                <option value="">Select a user…</option>
                {addableUsers.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id="add-member-user"
                type="number"
                className="w-full rounded-md px-2 py-1.5 text-sm"
                placeholder="User id"
                value={addUserId}
                onChange={(e) => setAddUserId(e.target.value ? Number(e.target.value) : '')}
              />
            )}
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" htmlFor="add-member-role">
              Role
            </label>
            <select
              id="add-member-role"
              className="rounded-md px-2 py-1.5 text-sm"
              value={addRole}
              onChange={(e) => setAddRole(e.target.value as ProjectRole)}
            >
              {PROJECT_ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            disabled={addUserId === '' || upsert.isPending}
            className="btn-primary rounded-md px-3 py-1.5 text-sm font-medium disabled:opacity-60"
          >
            Add
          </button>
        </form>
        {error && (
          <p className="text-sm" style={{ color: 'var(--danger)' }}>
            {error}
          </p>
        )}
      </div>
    </Modal>
  )
}

export function Projects() {
  const { data: projects, isLoading, isError } = useProjects()
  const deleteProject = useDeleteProject()
  const [showCreate, setShowCreate] = useState(false)
  const [membersFor, setMembersFor] = useState<ProjectResponse | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Projects</h1>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="btn-primary rounded-md px-4 py-2 text-sm font-medium"
        >
          New project
        </button>
      </div>

      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        Projects scope servers, keys, and their audit/usage history. Creating and deleting a
        project is instance-wide (global-admin) authority; who can administer WITHIN a project is
        set via that project's members. This is visibility scoping, not tenant isolation — see
        docs/projects.md.
      </p>

      {isLoading && <p style={{ color: 'var(--text-muted)' }}>Loading…</p>}
      {isError && <p style={{ color: 'var(--danger)' }}>Could not load projects.</p>}
      {deleteError && <p style={{ color: 'var(--danger)' }}>{deleteError}</p>}

      {projects && projects.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: 'var(--border)' }}>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Slug
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Name
                </th>
                <th className="px-4 py-2 font-medium" style={{ color: 'var(--text-muted)' }}>
                  Created
                </th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                  <td className="px-4 py-3 font-mono text-xs">{project.slug}</td>
                  <td className="px-4 py-3 font-medium">{project.name}</td>
                  <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {new Date(project.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right space-x-3">
                    <button
                      type="button"
                      onClick={() => setMembersFor(project)}
                      className="text-xs font-medium"
                      style={{ color: 'var(--accent)' }}
                    >
                      Members
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDeleteError(null)
                        deleteProject.mutate(project.slug, {
                          onError: (err) =>
                            setDeleteError(err instanceof ApiError ? err.message : 'Could not delete project'),
                        })
                      }}
                      disabled={deleteProject.isPending}
                      className="text-xs font-medium"
                      style={{ color: 'var(--danger)' }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && <CreateProjectModal onClose={() => setShowCreate(false)} />}
      {membersFor && <MembersModal project={membersFor} onClose={() => setMembersFor(null)} />}
    </div>
  )
}
