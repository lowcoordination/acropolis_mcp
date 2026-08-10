import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useProjects } from './useProjects'

// The frontend's project switcher — 'all' means no project filter (the instance-wide view every
// list/get route defaults to when no project_id is supplied, matching pre-feature behavior
// exactly). A specific project id scopes servers/keys/audit/usage pages via each page's own
// project_id query param. This is a UI convenience, never a security boundary: every backend
// route enforces its own require_project_role/require_role regardless of what's selected here —
// switching to a project the caller has no access to just means every list comes back empty or
// 403s on write, the same way it would from a direct API call.
const STORAGE_KEY = 'acropolis.activeProjectId'

interface ProjectContextValue {
  activeProjectId: number | null // null = "All projects"
  setActiveProjectId: (id: number | null) => void
}

const ProjectContext = createContext<ProjectContextValue | null>(null)

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { data: projects } = useProjects()
  const [activeProjectId, setActiveProjectIdState] = useState<number | null>(() => {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    return stored ? Number(stored) : null
  })

  // If the persisted project id no longer exists (deleted, or this browser's storage predates
  // that project ever existing), fall back to "All projects" rather than silently filtering
  // every page down to zero rows with no explanation.
  useEffect(() => {
    if (activeProjectId != null && projects && !projects.some((p) => p.id === activeProjectId)) {
      setActiveProjectIdState(null)
      window.localStorage.removeItem(STORAGE_KEY)
    }
  }, [activeProjectId, projects])

  const setActiveProjectId = (id: number | null) => {
    setActiveProjectIdState(id)
    if (id == null) {
      window.localStorage.removeItem(STORAGE_KEY)
    } else {
      window.localStorage.setItem(STORAGE_KEY, String(id))
    }
  }

  const value = useMemo(() => ({ activeProjectId, setActiveProjectId }), [activeProjectId])

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>
}

export function useActiveProject() {
  const ctx = useContext(ProjectContext)
  if (!ctx) throw new Error('useActiveProject must be used within a ProjectProvider')
  return ctx
}
