import { useEffect, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import apiClient from './lib/api'
import SetupWizard from './components/auth/SetupWizard'
import LoginForm from './components/auth/LoginForm'
import ProtectedRoute from './components/auth/ProtectedRoute'
import Dashboard from './pages/Dashboard'
import Authorities from './pages/Authorities'
import Certificates from './pages/Certificates'

function AppRoutes() {
  const [setupComplete, setSetupComplete] = useState<boolean | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['setup-status'],
    queryFn: () => apiClient.getSetupStatus(),
    retry: 1,
  })

  useEffect(() => {
    if (data) {
      setSetupComplete(data.setup_complete)
    }
  }, [data])

  if (isLoading || setupComplete === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  if (!setupComplete) {
    return <SetupWizard />
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginForm />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/authorities" element={<Authorities />} />
        <Route path="/certificates" element={<Certificates />} />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default AppRoutes
