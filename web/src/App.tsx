import { Navigate, Route, Routes } from 'react-router'
import { useSetupStatus } from './lib/useSetupStatus'
import { ProjectProvider } from './lib/ProjectContext'
import { SetupWizard } from './pages/SetupWizard'
import { Login } from './pages/Login'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Servers } from './pages/Servers'
import { ServerDetail } from './pages/ServerDetail'
import { Keys } from './pages/Keys'
import { Usage } from './pages/Usage'
import { Audit } from './pages/Audit'
import { Proposals } from './pages/Proposals'
import { Settings } from './pages/Settings'
import { Users } from './pages/Users'
import { Projects } from './pages/Projects'

function App() {
  const { data: setupStatus, isLoading, isError } = useSetupStatus()

  if (isLoading) {
    return <div className="min-h-screen flex items-center justify-center">Loading…</div>
  }

  if (isError) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Could not reach the Acropolis backend.
      </div>
    )
  }

  if (!setupStatus?.setup_complete) {
    return <SetupWizard />
  }

  return (
    <Routes>
      {/* A 401 anywhere behind Layout is handled globally by the API client (see
          api/client.ts), which redirects to /login — this route just needs to exist. */}
      <Route path="/login" element={<Login />} />
      <Route
        element={
          // Enterprise #4: ProjectProvider wraps everything behind Layout (not the whole app) —
          // it depends on GET /projects, which itself requires an authenticated session; wrapping
          // /login too would just mean an always-empty, always-loading provider on that route.
          <ProjectProvider>
            <Layout />
          </ProjectProvider>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="servers" element={<Servers />} />
        <Route path="servers/:slug" element={<ServerDetail />} />
        <Route path="keys" element={<Keys />} />
        <Route path="usage" element={<Usage />} />
        <Route path="audit" element={<Audit />} />
        <Route path="approvals" element={<Proposals />} />
        <Route path="settings" element={<Settings />} />
        {/* No client-side role gate on this route itself — Users renders an empty/error state
            for a non-admin (GET /users 403s), and every mutation in it 403s server-side
            regardless. The NAV LINK is what's hidden per-role (see Layout.tsx); a viewer who
            navigates here directly by URL sees a clean "could not load" rather than a fake
            404, which is honest about the route existing and matches 02-rbac.md's "403, not
            404" principle at the API layer this page is built on. */}
        <Route path="users" element={<Users />} />
        {/* Same "no client-side gate, server enforces it" discipline as Users above — project
            CRUD is global-admin-only server-side (POST/DELETE /projects), and a non-admin still
            sees the list (GET /projects is viewer+) with create/delete controls that 403 if
            somehow reached. */}
        <Route path="projects" element={<Projects />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default App
