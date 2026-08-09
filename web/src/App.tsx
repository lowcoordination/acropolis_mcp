import { Navigate, Route, Routes } from 'react-router'
import { useSetupStatus } from './lib/useSetupStatus'
import { SetupWizard } from './pages/SetupWizard'
import { Login } from './pages/Login'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Servers } from './pages/Servers'
import { ServerDetail } from './pages/ServerDetail'
import { Keys } from './pages/Keys'
import { Usage } from './pages/Usage'
import { Audit } from './pages/Audit'
import { Settings } from './pages/Settings'
import { Users } from './pages/Users'

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
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="servers" element={<Servers />} />
        <Route path="servers/:slug" element={<ServerDetail />} />
        <Route path="keys" element={<Keys />} />
        <Route path="usage" element={<Usage />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
        {/* No client-side role gate on this route itself — Users renders an empty/error state
            for a non-admin (GET /users 403s), and every mutation in it 403s server-side
            regardless. The NAV LINK is what's hidden per-role (see Layout.tsx); a viewer who
            navigates here directly by URL sees a clean "could not load" rather than a fake
            404, which is honest about the route existing and matches 02-rbac.md's "403, not
            404" principle at the API layer this page is built on. */}
        <Route path="users" element={<Users />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default App
