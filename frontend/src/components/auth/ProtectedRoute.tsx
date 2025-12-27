import { useEffect, useState } from 'react'
import { Navigate, Outlet } from 'react-router-dom'

export default function ProtectedRoute() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('auth_token')
    setIsAuthenticated(!!token)
  }, [])

  if (isAuthenticated === null) {
    return <div>Loading...</div>
  }

  return isAuthenticated ? <Outlet /> : <Navigate to="/login" replace />
}
