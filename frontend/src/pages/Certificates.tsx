import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { useToast } from '@/hooks/use-toast'
import { Plus, Download, Trash2, RefreshCw, Copy, Package } from 'lucide-react'
import SidebarLayout from '@/components/layout/SidebarLayout'
import apiClient from '@/lib/api'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

export default function Certificates() {
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [isDeleteOpen, setIsDeleteOpen] = useState(false)
  const [isRenewOpen, setIsRenewOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [renewTarget, setRenewTarget] = useState<any>(null)
  const [renewValidityDays, setRenewValidityDays] = useState('365')
  const [authorityId, setAuthorityId] = useState('')
  const [commonName, setCommonName] = useState('')
  const [organization, setOrganization] = useState('')
  const [organizationUnit, setOrganizationUnit] = useState('')
  const [country, setCountry] = useState('')
  const [province, setProvince] = useState('')
  const [locality, setLocality] = useState('')
  const [sans, setSans] = useState('')
  const [algorithm, setAlgorithm] = useState('rsa')
  const [rsaBits, setRsaBits] = useState('4096')
  const [ecCurve, setEcCurve] = useState('P384')
  const [validityDays, setValidityDays] = useState('365')
  const [isServerAuth, setIsServerAuth] = useState(true)
  const [isClientAuth, setIsClientAuth] = useState(false)
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const { data: certificates, isLoading } = useQuery({
    queryKey: ['certificates'],
    queryFn: () => apiClient.listCertificates(),
  })

  const { data: authorities } = useQuery({
    queryKey: ['authorities'],
    queryFn: () => apiClient.listAuthorities(),
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => apiClient.createCertificate(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      setIsCreateOpen(false)
      resetForm()
      toast({
        title: "Success",
        description: "Certificate created successfully",
      })
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to create certificate",
        variant: "destructive",
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteCertificate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      setIsDeleteOpen(false)
      setDeleteTarget(null)
      toast({
        title: "Success",
        description: "Certificate deleted successfully",
      })
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to delete certificate",
        variant: "destructive",
      })
    },
  })

  const renewMutation = useMutation({
    mutationFn: (data: any) => apiClient.createCertificate(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      setIsRenewOpen(false)
      setRenewTarget(null)
      toast({
        title: "Success",
        description: "Certificate renewed successfully",
      })
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to renew certificate",
        variant: "destructive",
      })
    },
  })

  const resetForm = () => {
    setAuthorityId('')
    setCommonName('')
    setOrganization('')
    setOrganizationUnit('')
    setCountry('')
    setProvince('')
    setLocality('')
    setSans('')
    setAlgorithm('rsa')
    setRsaBits('4096')
    setEcCurve('P384')
    setValidityDays('365')
    setIsServerAuth(true)
    setIsClientAuth(false)
  }

  const handleCreate = () => {
    const sansList = sans.split(',').map(s => s.trim()).filter(s => s)
    createMutation.mutate({
      authority_id: authorityId,
      common_name: commonName,
      organization,
      organization_unit: organizationUnit,
      country,
      province,
      locality,
      sans: sansList,
      algorithm,
      rsa_bits: parseInt(rsaBits),
      ec_curve: ecCurve,
      validity_days: parseInt(validityDays),
      is_server_auth: isServerAuth,
      is_client_auth: isClientAuth,
    })
  }

  const handleExport = async (id: string, format: string) => {
    try {
      const response = await apiClient.exportCertificate(id, format, 'password123')
      
      // Extract filename from Content-Disposition header
      let filename = `certificate.${format === 'pkcs12' ? 'pfx' : 'pem'}`
      const contentDisposition = response.headers['content-disposition']
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename=(.+)/)
        if (filenameMatch && filenameMatch[1]) {
          filename = filenameMatch[1].replace(/['"]/g, '') // Remove quotes if present
        }
      }
      
      const blob = response.data
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      toast({
        title: "Success",
        description: `Certificate exported as ${format.toUpperCase()}`,
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to export certificate",
        variant: "destructive",
      })
    }
  }

  const handleBulkExport = async (caName: string, certificates: any[], format: string) => {
    try {
      // Dynamic import of JSZip
      const JSZip = (await import('jszip')).default
      const zip = new JSZip()
      
      // Export each certificate and add to ZIP
      for (const cert of certificates) {
        try {
          const response = await apiClient.exportCertificate(cert.id, format, 'password123')
          
          // Extract filename from Content-Disposition header or generate one
          let filename = `${cert.common_name}.${format === 'pkcs12' ? 'pfx' : 'pem'}`
          const contentDisposition = response.headers['content-disposition']
          if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename=(.+)/)
            if (filenameMatch && filenameMatch[1]) {
              filename = filenameMatch[1].replace(/['"]/g, '')
            }
          }
          
          // Add file to ZIP
          zip.file(filename, response.data)
        } catch (error) {
          console.error(`Failed to export certificate ${cert.common_name}:`, error)
          // Continue with other certificates
        }
      }
      
      // Generate ZIP file
      const blob = await zip.generateAsync({ type: 'blob' })
      
      // Sanitize CA name for filename (remove special characters)
      const sanitizedCaName = caName.replace(/[^a-zA-Z0-9-_]/g, '_')
      const zipFilename = `${sanitizedCaName}-certificates-${format}.zip`
      
      // Download ZIP file
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = zipFilename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      
      toast({
        title: "Success",
        description: `Exported ${certificates.length} certificate${certificates.length === 1 ? '' : 's'} as ${format.toUpperCase()}`,
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: "Failed to export certificates",
        variant: "destructive",
      })
    }
  }

  const openDeleteDialog = (cert: any) => {
    setDeleteTarget(cert)
    setIsDeleteOpen(true)
  }

  const openRenewDialog = (cert: any) => {
    setRenewTarget(cert)
    setRenewValidityDays('365') // Default to 1 year
    setIsRenewOpen(true)
  }

  const openCloneDialog = (cert: any) => {
    // Pre-fill all form fields from certificate data
    setAuthorityId(cert.authority_id)
    setCommonName('') // User must provide new CN
    setOrganization(cert.organization || '')
    setOrganizationUnit(cert.organization_unit || '')
    setCountry(cert.country || '')
    setProvince(cert.province || '')
    setLocality(cert.locality || '')
    setSans(cert.sans ? cert.sans.join(', ') : '')
    setAlgorithm(cert.algorithm || 'rsa')
    setRsaBits(cert.key_size ? cert.key_size.toString() : '4096')
    setEcCurve(cert.ec_curve || 'P384')
    setValidityDays(cert.validity_days ? cert.validity_days.toString() : '365')
    setIsServerAuth(cert.is_server_auth !== undefined ? cert.is_server_auth : true)
    setIsClientAuth(cert.is_client_auth !== undefined ? cert.is_client_auth : false)
    setIsCreateOpen(true)
  }

  const handleDelete = () => {
    if (deleteTarget) {
      deleteMutation.mutate(deleteTarget.id)
    }
  }

  const handleRenew = () => {
    if (!renewTarget) return

    // Parse the certificate details and create a new one with the same parameters
    // Extract organization details from the certificate (these might not be in the response)
    // For now, we'll use what we have
    renewMutation.mutate({
      authority_id: renewTarget.authority_id,
      common_name: renewTarget.common_name,
      sans: renewTarget.sans || [],
      validity_days: parseInt(renewValidityDays),
      is_server_auth: true, // Default assumption
      is_client_auth: false, // Default assumption
      algorithm: 'rsa', // Default
      rsa_bits: 4096, // Default
    })
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'valid':
        return <Badge className="bg-green-500">Valid</Badge>
      case 'expiring_soon':
        return <Badge className="bg-yellow-500">Expiring Soon</Badge>
      case 'expired':
        return <Badge variant="destructive">Expired</Badge>
      case 'revoked':
        return <Badge variant="destructive">Revoked</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  // Group certificates by CA
  const groupCertificatesByCA = () => {
    if (!certificates || !authorities) return []

    // Create a map of authority_id to authority name
    const authorityMap = new Map(
      authorities.map((auth: any) => [auth.id, auth.friendly_name])
    )

    // Group certificates by authority_id
    const groups = new Map<string, { caName: string; certificates: any[] }>()
    
    certificates.forEach((cert: any) => {
      const caName = authorityMap.get(cert.authority_id) || cert.issuer_name || 'Unknown CA'
      
      if (!groups.has(cert.authority_id)) {
        groups.set(cert.authority_id, {
          caName,
          certificates: []
        })
      }
      
      groups.get(cert.authority_id)!.certificates.push(cert)
    })

    // Sort certificates within each group by common name
    groups.forEach(group => {
      group.certificates.sort((a: any, b: any) => 
        (a.common_name || '').localeCompare(b.common_name || '', undefined, { sensitivity: 'base' })
      )
    })

    // Convert to array and sort groups by CA name
    return Array.from(groups.entries())
      .map(([authorityId, group]) => ({
        authorityId,
        caName: group.caName,
        certificates: group.certificates
      }))
      .sort((a, b) => a.caName.localeCompare(b.caName, undefined, { sensitivity: 'base' }))
  }

  const groupedCertificates = groupCertificatesByCA()

  return (
    <SidebarLayout>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Certificates</h1>
        <Button onClick={() => setIsCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Certificate
        </Button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : certificates?.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          No certificates found. Create one to get started.
        </div>
      ) : (
        <div className="space-y-6">
          {groupedCertificates.map((group, index) => (
            <div key={group.authorityId}>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <h2 className="text-lg font-semibold">{group.caName}</h2>
                    <Badge variant="secondary">
                      {group.certificates.length} {group.certificates.length === 1 ? 'certificate' : 'certificates'}
                    </Badge>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm">
                        <Package className="h-4 w-4 mr-2" />
                        Export All
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem onClick={() => handleBulkExport(group.caName, group.certificates, 'pem')}>
                        Export All as PEM
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleBulkExport(group.caName, group.certificates, 'pkcs12')}>
                        Export All as PFX
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
                
                <div className="grid gap-3">
                  {group.certificates.map((cert: any) => (
                    <Card key={cert.id} className="overflow-hidden">
                      <CardHeader className="py-3">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <div className="flex items-center gap-3">
                              <CardTitle className="text-sm">{cert.common_name}</CardTitle>
                              {getStatusBadge(cert.status)}
                            </div>
                            <CardDescription className="mt-2">
                              <div className="space-y-1 text-xs">
                                <div><strong>Valid Until:</strong> {new Date(cert.not_after).toLocaleDateString()}</div>
                                {cert.sans && cert.sans.length > 0 && (
                                  <div><strong>SANs:</strong> {cert.sans.join(', ')}</div>
                                )}
                              </div>
                            </CardDescription>
                          </div>
                          <div className="flex gap-2">
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="outline" size="sm">
                                  <Download className="h-4 w-4 mr-2" />
                                  Export
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent>
                                <DropdownMenuItem onClick={() => handleExport(cert.id, 'pem')}>
                                  Export as PEM
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => handleExport(cert.id, 'pkcs12')}>
                                  Export as PFX
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openRenewDialog(cert)}
                              title="Renew certificate with new expiration"
                            >
                              <RefreshCw className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openCloneDialog(cert)}
                              title="Clone certificate with same settings"
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => openDeleteDialog(cert)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                    </Card>
                  ))}
                </div>
              </div>
              {index < groupedCertificates.length - 1 && <Separator className="my-6" />}
            </div>
          ))}
        </div>
      )}

      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Certificate</DialogTitle>
            <DialogDescription>
              Create a new certificate signed by a Certificate Authority
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="authority">Certificate Authority *</Label>
              <Select value={authorityId} onValueChange={setAuthorityId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a CA" />
                </SelectTrigger>
                <SelectContent>
                  {authorities?.map((auth: any) => (
                    <SelectItem key={auth.id} value={auth.id}>
                      {auth.friendly_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="common_name">Common Name *</Label>
                <Input
                  id="common_name"
                  placeholder="example.com"
                  value={commonName}
                  onChange={(e) => setCommonName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="organization">Organization</Label>
                <Input
                  id="organization"
                  placeholder="My Company"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="organization_unit">Organization Unit</Label>
                <Input
                  id="organization_unit"
                  placeholder="IT Department"
                  value={organizationUnit}
                  onChange={(e) => setOrganizationUnit(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="country">Country (2-letter code)</Label>
                <Input
                  id="country"
                  placeholder="US"
                  maxLength={2}
                  value={country}
                  onChange={(e) => setCountry(e.target.value.toUpperCase())}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="province">State/Province</Label>
                <Input
                  id="province"
                  placeholder="California"
                  value={province}
                  onChange={(e) => setProvince(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="locality">City/Locality</Label>
                <Input
                  id="locality"
                  placeholder="San Francisco"
                  value={locality}
                  onChange={(e) => setLocality(e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sans">Subject Alternative Names (comma-separated)</Label>
              <Input
                id="sans"
                placeholder="www.example.com, *.example.com, 192.168.1.1"
                value={sans}
                onChange={(e) => setSans(e.target.value)}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="algorithm">Key Algorithm</Label>
                <Select value={algorithm} onValueChange={setAlgorithm}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="rsa">RSA</SelectItem>
                    <SelectItem value="ecdsa">ECDSA (Elliptic Curve)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              {algorithm === 'rsa' ? (
                <div className="space-y-2">
                  <Label htmlFor="rsa_bits">RSA Key Size</Label>
                  <Select value={rsaBits} onValueChange={setRsaBits}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="2048">2048 bits</SelectItem>
                      <SelectItem value="3072">3072 bits</SelectItem>
                      <SelectItem value="4096">4096 bits</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="ec_curve">EC Curve</Label>
                  <Select value={ecCurve} onValueChange={setEcCurve}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="P256">P-256 (secp256r1)</SelectItem>
                      <SelectItem value="P384">P-384 (secp384r1)</SelectItem>
                      <SelectItem value="P521">P-521 (secp521r1)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="validity_days">Validity Period</Label>
              <Select value={validityDays} onValueChange={setValidityDays}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30">30 days</SelectItem>
                  <SelectItem value="90">90 days (3 months)</SelectItem>
                  <SelectItem value="180">180 days (6 months)</SelectItem>
                  <SelectItem value="365">365 days (1 year)</SelectItem>
                  <SelectItem value="730">730 days (2 years)</SelectItem>
                  <SelectItem value="825">825 days (~27 months)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Certificate Usage</Label>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="server_auth"
                    checked={isServerAuth}
                    onChange={(e) => setIsServerAuth(e.target.checked)}
                    className="h-4 w-4"
                  />
                  <Label htmlFor="server_auth" className="font-normal cursor-pointer">
                    Server Authentication (TLS/SSL)
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="client_auth"
                    checked={isClientAuth}
                    onChange={(e) => setIsClientAuth(e.target.checked)}
                    className="h-4 w-4"
                  />
                  <Label htmlFor="client_auth" className="font-normal cursor-pointer">
                    Client Authentication
                  </Label>
                </div>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button 
              onClick={handleCreate}
              disabled={!authorityId || !commonName || createMutation.isPending}
            >
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isRenewOpen} onOpenChange={setIsRenewOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Renew Certificate</DialogTitle>
            <DialogDescription>
              Create a new certificate with the same details but a new expiration date
            </DialogDescription>
          </DialogHeader>
          {renewTarget && (
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <p className="text-sm">
                  <strong>Common Name:</strong> {renewTarget.common_name}
                </p>
                {renewTarget.sans && renewTarget.sans.length > 0 && (
                  <p className="text-sm">
                    <strong>SANs:</strong> {renewTarget.sans.join(', ')}
                  </p>
                )}
                <p className="text-sm">
                  <strong>Issuer:</strong> {renewTarget.issuer_name}
                </p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="renew_validity">Validity Period</Label>
                <Select value={renewValidityDays} onValueChange={setRenewValidityDays}>
                  <SelectTrigger id="renew_validity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="30">30 days</SelectItem>
                    <SelectItem value="90">90 days (3 months)</SelectItem>
                    <SelectItem value="180">180 days (6 months)</SelectItem>
                    <SelectItem value="365">365 days (1 year)</SelectItem>
                    <SelectItem value="730">730 days (2 years)</SelectItem>
                    <SelectItem value="825">825 days (~27 months)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <p className="text-sm text-muted-foreground">
                Note: The original certificate will remain valid until its expiration date. 
                You may want to revoke or delete the old certificate after verifying the new one.
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsRenewOpen(false)}>
              Cancel
            </Button>
            <Button 
              onClick={handleRenew}
              disabled={renewMutation.isPending}
            >
              {renewMutation.isPending ? "Renewing..." : "Renew Certificate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Certificate</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this certificate?
            </DialogDescription>
          </DialogHeader>
          {deleteTarget && (
            <div className="py-4">
              <p className="text-sm">
                <strong>Common Name:</strong> {deleteTarget.common_name}
              </p>
              <p className="text-sm">
                <strong>Serial Number:</strong> {deleteTarget.serial_number}
              </p>
              <p className="text-sm text-red-500 mt-4">
                Warning: This action cannot be undone.
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDeleteOpen(false)}>
              Cancel
            </Button>
            <Button 
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </SidebarLayout>
  )
}
