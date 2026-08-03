import { Navigate, Route, Routes } from 'react-router'
import { useSetupStatus } from './lib/useSetupStatus'
import { SetupWizard } from './pages/SetupWizard'
import { Login } from './pages/Login'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Servers } from './pages/Servers'
import { ServerDetail } from './pages/ServerDetail'
import { Keys } from './pages/Keys'
import { Audit } from './pages/Audit'
import { Settings } from './pages/Settings'

function App() {
  const { data: setupStatus, isLoading, isError } = useSetupStatus()

  if (isLoading) {
    return <div className="min-h-screen flex items-center justify-center">Loading…</div>
  }

  if (isError) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        Could not reach the Argus backend.
      </div>
    )
  }

  if (!setupStatus?.setup_complete) {
    return <SetupWizard />
  }

  return (
    <Routes>
      {/* A 401 anywhere behind Layout means the session expired — the query layer surfaces
          that as an error boundary per-page rather than a global redirect for now; the login
          route itself is always reachable directly. */}
      <Route path="/login" element={<Login />} />
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="servers" element={<Servers />} />
        <Route path="servers/:slug" element={<ServerDetail />} />
        <Route path="keys" element={<Keys />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default App
