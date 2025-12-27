import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, FileKey, AlertTriangle, TrendingUp, Activity } from 'lucide-react'
import SidebarLayout from '@/components/layout/SidebarLayout'
import apiClient from '@/lib/api'

export default function Dashboard() {
  const { data: authorities } = useQuery({
    queryKey: ['authorities'],
    queryFn: () => apiClient.listAuthorities(),
  })

  const { data: certificates } = useQuery({
    queryKey: ['certificates'],
    queryFn: () => apiClient.listCertificates(),
  })

  // Calculate statistics
  const totalCAs = authorities?.length || 0
  const totalCerts = certificates?.length || 0
  const validCerts = certificates?.filter((cert: any) => cert.status === 'valid').length || 0
  const expiringCerts = certificates?.filter((cert: any) => cert.status === 'expiring_soon').length || 0

  return (
    <SidebarLayout>
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
      </div>
      
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* Total Certificate Authorities */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Certificate Authorities
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalCAs}</div>
            <p className="text-xs text-muted-foreground">
              Total Root & Intermediate CAs
            </p>
          </CardContent>
        </Card>

        {/* Total Certificates */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Certificates
            </CardTitle>
            <FileKey className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalCerts}</div>
            <p className="text-xs text-muted-foreground">
              Active SSL/TLS certificates
            </p>
          </CardContent>
        </Card>

        {/* Valid Certificates */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Valid Certificates
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{validCerts}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              Healthy status
            </p>
          </CardContent>
        </Card>

        {/* Expiring Soon */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Expiring Soon
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{expiringCerts}</div>
            <p className="text-xs text-muted-foreground">
              {expiringCerts > 0 ? 'Needs attention' : 'All certificates healthy'}
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Recent Activity */}
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>
              Latest certificate operations and changes
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {certificates && certificates.length > 0 ? (
                certificates.slice(0, 5).map((cert: any) => (
                  <div key={cert.id} className="flex items-center">
                    <FileKey className="mr-2 h-4 w-4 text-muted-foreground" />
                    <div className="flex-1 space-y-1">
                      <p className="text-sm font-medium leading-none">
                        {cert.common_name}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        Expires: {new Date(cert.not_after).toLocaleDateString()}
                      </p>
                    </div>
                    <div className={`text-xs font-medium ${
                      cert.status === 'valid' ? 'text-green-600' : 
                      cert.status === 'expiring_soon' ? 'text-yellow-600' : 
                      'text-red-600'
                    }`}>
                      {cert.status === 'valid' ? 'Valid' : 
                       cert.status === 'expiring_soon' ? 'Expiring Soon' : 
                       'Expired'}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-muted-foreground">
                  No certificates yet. Create your first certificate to get started.
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Certificate Authorities Overview */}
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Certificate Authorities</CardTitle>
            <CardDescription>
              Your PKI infrastructure
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {authorities && authorities.length > 0 ? (
                authorities.slice(0, 3).map((ca: any) => (
                  <div key={ca.id} className="flex items-center">
                    <Shield className="mr-2 h-4 w-4 text-muted-foreground" />
                    <div className="flex-1 space-y-1">
                      <p className="text-sm font-medium leading-none">
                        {ca.friendly_name}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {ca.common_name}
                      </p>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-muted-foreground">
                  No CAs configured. Create a Root CA to get started.
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </SidebarLayout>
  )
}
