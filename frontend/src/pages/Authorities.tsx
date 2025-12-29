import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useToast } from '@/hooks/use-toast'
import { Plus, Trash2, Download, Upload, FileText, FolderOpen } from 'lucide-react'
import SidebarLayout from '@/components/layout/SidebarLayout'
import apiClient from '@/lib/api'

export default function Authorities() {
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [isImportOpen, setIsImportOpen] = useState(false)
  const [isImportFromFileOpen, setIsImportFromFileOpen] = useState(false)
  const [isDeleteOpen, setIsDeleteOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)
  const [friendlyName, setFriendlyName] = useState('')
  const [commonName, setCommonName] = useState('')
  const [organization, setOrganization] = useState('')
  const [organizationUnit, setOrganizationUnit] = useState('')
  const [country, setCountry] = useState('')
  const [province, setProvince] = useState('')
  const [locality, setLocality] = useState('')
  const [algorithm, setAlgorithm] = useState('rsa')
  const [rsaBits, setRsaBits] = useState('4096')
  const [ecCurve, setEcCurve] = useState('P384')
  const [validityYears, setValidityYears] = useState('10')
  const [importFriendlyName, setImportFriendlyName] = useState('')
  const [importCertificatePEM, setImportCertificatePEM] = useState('')
  const [importPrivateKeyPEM, setImportPrivateKeyPEM] = useState('')
  const [importPassword, setImportPassword] = useState('')
  const [importFileType, setImportFileType] = useState<'pem_single' | 'pem_separate'>('pem_single')
  const [selectedCertFile, setSelectedCertFile] = useState<File | null>(null)
  const [selectedKeyFile, setSelectedKeyFile] = useState<File | null>(null)
  const [selectedPemFile, setSelectedPemFile] = useState<File | null>(null)
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const { data: authorities, isLoading } = useQuery({
    queryKey: ['authorities'],
    queryFn: () => apiClient.listAuthorities(),
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => apiClient.createRootCA(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['authorities'] })
      setIsCreateOpen(false)
      resetForm()
      toast({
        title: "Success",
        description: "Root CA created successfully",
      })
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to create CA",
        variant: "destructive",
      })
    },
  })

  const importMutation = useMutation({
    mutationFn: (data: any) => apiClient.importCA(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['authorities'] })
      setIsImportOpen(false)
      resetImportForm()
      toast({
        title: "Success",
        description: "CA imported successfully",
      })
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to import CA",
        variant: "destructive",
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteAuthority(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['authorities'] })
      setIsDeleteOpen(false)
      setDeleteTarget(null)
      toast({
        title: "Success",
        description: "Certificate Authority deleted successfully",
      })
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to delete CA",
        variant: "destructive",
      })
    },
  })

  const resetForm = () => {
    setFriendlyName('')
    setCommonName('')
    setOrganization('')
    setOrganizationUnit('')
    setCountry('')
    setProvince('')
    setLocality('')
    setAlgorithm('rsa')
    setRsaBits('4096')
    setEcCurve('P384')
    setValidityYears('10')
  }

  const resetImportForm = () => {
    setImportFriendlyName('')
    setImportCertificatePEM('')
    setImportPrivateKeyPEM('')
    setImportPassword('')
  }

  const resetFileImportForm = () => {
    setImportFriendlyName('')
    setImportPassword('')
    setImportFileType('pem_single')
    setSelectedCertFile(null)
    setSelectedKeyFile(null)
    setSelectedPemFile(null)
  }

  const readFileAsText = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = (e) => resolve(e.target?.result as string)
      reader.onerror = reject
      reader.readAsText(file)
    })
  }

  const parsePemFile = (content: string) => {
    // Extract certificate and private key from single PEM file
    const certMatch = content.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)
    const keyMatch = content.match(/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/)
    return { cert: certMatch?.[0] || '', key: keyMatch?.[0] || '' }
  }

  const handleCreate = () => {
    const validityDays = parseInt(validityYears) * 365
    createMutation.mutate({
      friendly_name: friendlyName,
      common_name: commonName,
      organization,
      organization_unit: organizationUnit,
      country,
      province,
      locality,
      algorithm,
      rsa_bits: algorithm === 'rsa' ? parseInt(rsaBits) : 0,
      ec_curve: algorithm === 'ecdsa' ? ecCurve : '',
      validity_days: validityDays,
    })
  }

  const handleImport = () => {
    importMutation.mutate({
      friendly_name: importFriendlyName,
      certificate_pem: importCertificatePEM,
      private_key_pem: importPrivateKeyPEM,
      password: importPassword,
    })
  }

  const handleFileImport = async () => {
    try {
      let certPem = ''
      let keyPem = ''

      if (importFileType === 'pem_single' && selectedPemFile) {
        const content = await readFileAsText(selectedPemFile)
        const parsed = parsePemFile(content)
        certPem = parsed.cert
        keyPem = parsed.key
        
        if (!certPem || !keyPem) {
          toast({
            title: "Error",
            description: "Could not find both certificate and private key in the file",
            variant: "destructive",
          })
          return
        }
      } else if (importFileType === 'pem_separate') {
        if (!selectedCertFile || !selectedKeyFile) {
          toast({
            title: "Error",
            description: "Please select both certificate and private key files",
            variant: "destructive",
          })
          return
        }
        certPem = await readFileAsText(selectedCertFile)
        keyPem = await readFileAsText(selectedKeyFile)
      }

      importMutation.mutate({
        friendly_name: importFriendlyName,
        certificate_pem: certPem,
        private_key_pem: keyPem,
        password: importPassword,
      })

      setIsImportFromFileOpen(false)
      resetFileImportForm()
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to read file",
        variant: "destructive",
      })
    }
  }

  const handleDelete = () => {
    if (deleteTarget) {
      deleteMutation.mutate(deleteTarget.id)
    }
  }

  const handleExportAuthority = async (authority: any, format: string, certOnly: boolean = false) => {
    try {
      // For now, use empty password. Could add password dialog later
      const blob = await apiClient.exportAuthority(authority.id, format, '', false, certOnly)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const extension = format === 'pkcs12' ? 'pfx' : format
      const suffix = certOnly ? '_cert' : '_CA'
      a.download = `${authority.friendly_name.replace(/\s/g, '_')}${suffix}.${extension}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      const exportType = certOnly ? 'certificate only' : 'CA with private key'
      toast({
        title: "Success",
        description: `CA exported as ${format.toUpperCase()} (${exportType})`,
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Failed to export CA",
        variant: "destructive",
      })
    }
  }

  const openDeleteDialog = (authority: any) => {
    setDeleteTarget(authority)
    setIsDeleteOpen(true)
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'valid':
        return <Badge className="bg-green-500">Valid</Badge>
      case 'expiring_soon':
        return <Badge className="bg-yellow-500">Expiring Soon</Badge>
      case 'expired':
        return <Badge variant="destructive">Expired</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  return (
    <SidebarLayout>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Certificate Authorities</h1>
        <div className="flex gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">
                <Upload className="h-4 w-4 mr-2" />
                Import CA
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => setIsImportOpen(true)}>
                <FileText className="h-4 w-4 mr-2" />
                Import from Text
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setIsImportFromFileOpen(true)}>
                <FolderOpen className="h-4 w-4 mr-2" />
                Import from File
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" onClick={() => setIsCreateOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Create Root CA
          </Button>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <div className="grid gap-4">
          {authorities?.slice().sort((a: any, b: any) => 
            (a.friendly_name || '').localeCompare(b.friendly_name || '', undefined, { sensitivity: 'base' })
          ).map((authority: any) => (
            <Card key={authority.id} className="overflow-hidden">
              <CardHeader className="py-3">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <CardTitle className="text-sm">{authority.friendly_name}</CardTitle>
                      {getStatusBadge(authority.status)}
                    </div>
                    <CardDescription className="mt-2">
                      <div className="space-y-1 text-xs">
                        <div><strong>CN:</strong> {authority.common_name}</div>
                        <div><strong>Valid Until:</strong> {new Date(authority.not_after).toLocaleDateString()}</div>
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
                        <DropdownMenuLabel>CA with Private Key</DropdownMenuLabel>
                        <DropdownMenuItem onClick={() => handleExportAuthority(authority, 'pem', false)}>
                          Export as PEM
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleExportAuthority(authority, 'pkcs12', false)}>
                          Export as PFX
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuLabel>Certificate Only</DropdownMenuLabel>
                        <DropdownMenuItem onClick={() => handleExportAuthority(authority, 'pem', true)}>
                          Export as PEM (cert only)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => openDeleteDialog(authority)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
            </Card>
          ))}
          {authorities?.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              No Certificate Authorities found. Create one to get started.
            </div>
          )}
        </div>
      )}

      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Root CA</DialogTitle>
            <DialogDescription>
              Create a new self-signed Root Certificate Authority
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="friendly_name">Friendly Name *</Label>
              <Input
                id="friendly_name"
                placeholder="My Root CA"
                value={friendlyName}
                onChange={(e) => setFriendlyName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="common_name">Common Name (CN) *</Label>
              <Input
                id="common_name"
                placeholder="My Organization Root CA"
                value={commonName}
                onChange={(e) => setCommonName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="organization">Organization</Label>
              <Input
                id="organization"
                placeholder="My Organization"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="organization_unit">Organization Unit</Label>
              <Input
                id="organization_unit"
                placeholder="IT Department"
                value={organizationUnit}
                onChange={(e) => setOrganizationUnit(e.target.value)}
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="space-y-2">
                <Label htmlFor="country">Country</Label>
                <Input
                  id="country"
                  placeholder="US"
                  maxLength={2}
                  value={country}
                  onChange={(e) => setCountry(e.target.value.toUpperCase())}
                />
              </div>
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
            <div className="border-t pt-4">
              <h4 className="text-sm font-semibold mb-3">Key Configuration</h4>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="algorithm">Algorithm</Label>
                  <Select value={algorithm} onValueChange={setAlgorithm}>
                    <SelectTrigger id="algorithm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="rsa">RSA</SelectItem>
                      <SelectItem value="ecdsa">ECDSA</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {algorithm === 'rsa' && (
                  <div className="space-y-2">
                    <Label htmlFor="rsa_bits">RSA Key Size</Label>
                    <Select value={rsaBits} onValueChange={setRsaBits}>
                      <SelectTrigger id="rsa_bits">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2048">2048 bits</SelectItem>
                        <SelectItem value="3072">3072 bits</SelectItem>
                        <SelectItem value="4096">4096 bits (Recommended)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
                {algorithm === 'ecdsa' && (
                  <div className="space-y-2">
                    <Label htmlFor="ec_curve">EC Curve</Label>
                    <Select value={ecCurve} onValueChange={setEcCurve}>
                      <SelectTrigger id="ec_curve">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="P256">P-256 (256-bit)</SelectItem>
                        <SelectItem value="P384">P-384 (384-bit, Recommended)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="validity">Validity Period</Label>
                  <Select value={validityYears} onValueChange={setValidityYears}>
                    <SelectTrigger id="validity">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 year</SelectItem>
                      <SelectItem value="2">2 years</SelectItem>
                      <SelectItem value="5">5 years</SelectItem>
                      <SelectItem value="10">10 years (Recommended)</SelectItem>
                      <SelectItem value="20">20 years</SelectItem>
                      <SelectItem value="30">30 years</SelectItem>
                    </SelectContent>
                  </Select>
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
              disabled={!friendlyName || !commonName || createMutation.isPending}
            >
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isImportOpen} onOpenChange={setIsImportOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Import Certificate Authority</DialogTitle>
            <DialogDescription>
              Import an existing CA certificate and private key
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="import_friendly_name">Friendly Name *</Label>
              <Input
                id="import_friendly_name"
                placeholder="Imported CA"
                value={importFriendlyName}
                onChange={(e) => setImportFriendlyName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="import_certificate_pem">Certificate (PEM format) *</Label>
              <textarea
                id="import_certificate_pem"
                className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                value={importCertificatePEM}
                onChange={(e) => setImportCertificatePEM(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Paste the PEM-encoded certificate
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="import_private_key_pem">Private Key (PEM format) *</Label>
              <textarea
                id="import_private_key_pem"
                className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                value={importPrivateKeyPEM}
                onChange={(e) => setImportPrivateKeyPEM(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Paste the PEM-encoded private key
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="import_password">Password (if encrypted)</Label>
              <Input
                id="import_password"
                type="password"
                placeholder="Optional password for encrypted private key"
                value={importPassword}
                onChange={(e) => setImportPassword(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Leave empty if the private key is not encrypted
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsImportOpen(false)}>
              Cancel
            </Button>
            <Button 
              onClick={handleImport}
              disabled={!importFriendlyName || !importCertificatePEM || !importPrivateKeyPEM || importMutation.isPending}
            >
              {importMutation.isPending ? "Importing..." : "Import"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isImportFromFileOpen} onOpenChange={setIsImportFromFileOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Import CA from File</DialogTitle>
            <DialogDescription>
              Import an existing CA certificate and private key from file(s)
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="file_import_friendly_name">Friendly Name *</Label>
              <Input
                id="file_import_friendly_name"
                placeholder="Imported CA"
                value={importFriendlyName}
                onChange={(e) => setImportFriendlyName(e.target.value)}
              />
            </div>
            
            <div className="space-y-2">
              <Label>File Format *</Label>
              <Select value={importFileType} onValueChange={(value: any) => setImportFileType(value)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="pem_single">Single PEM file (certificate + key)</SelectItem>
                  <SelectItem value="pem_separate">Separate PEM files</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {importFileType === 'pem_single' && (
              <div className="space-y-2">
                <Label htmlFor="pem_file">PEM File *</Label>
                <div className="flex gap-2 items-center">
                  <Input
                    id="pem_file"
                    type="file"
                    accept=".pem,.crt,.cer,.key"
                    onChange={(e) => setSelectedPemFile(e.target.files?.[0] || null)}
                    className="cursor-pointer"
                  />
                </div>
                {selectedPemFile && (
                  <p className="text-xs text-muted-foreground">
                    Selected: {selectedPemFile.name}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  File should contain both the certificate and private key
                </p>
              </div>
            )}

            {importFileType === 'pem_separate' && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="cert_file">Certificate File *</Label>
                  <div className="flex gap-2 items-center">
                    <Input
                      id="cert_file"
                      type="file"
                      accept=".pem,.crt,.cer"
                      onChange={(e) => setSelectedCertFile(e.target.files?.[0] || null)}
                      className="cursor-pointer"
                    />
                  </div>
                  {selectedCertFile && (
                    <p className="text-xs text-muted-foreground">
                      Selected: {selectedCertFile.name}
                    </p>
                  )}
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="key_file">Private Key File *</Label>
                  <div className="flex gap-2 items-center">
                    <Input
                      id="key_file"
                      type="file"
                      accept=".pem,.key"
                      onChange={(e) => setSelectedKeyFile(e.target.files?.[0] || null)}
                      className="cursor-pointer"
                    />
                  </div>
                  {selectedKeyFile && (
                    <p className="text-xs text-muted-foreground">
                      Selected: {selectedKeyFile.name}
                    </p>
                  )}
                </div>
              </>
            )}

            <div className="space-y-2">
              <Label htmlFor="file_import_password">Password (if encrypted)</Label>
              <Input
                id="file_import_password"
                type="password"
                placeholder="Optional password for encrypted private key"
                value={importPassword}
                onChange={(e) => setImportPassword(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Leave empty if the private key is not encrypted
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsImportFromFileOpen(false)}>
              Cancel
            </Button>
            <Button 
              onClick={handleFileImport}
              disabled={
                !importFriendlyName || 
                (importFileType === 'pem_single' && !selectedPemFile) ||
                (importFileType === 'pem_separate' && (!selectedCertFile || !selectedKeyFile)) ||
                importMutation.isPending
              }
            >
              {importMutation.isPending ? "Importing..." : "Import"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Certificate Authority</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this Certificate Authority?
            </DialogDescription>
          </DialogHeader>
          {deleteTarget && (
            <div className="py-4">
              <p className="text-sm">
                <strong>Friendly Name:</strong> {deleteTarget.friendly_name}
              </p>
              <p className="text-sm">
                <strong>Common Name:</strong> {deleteTarget.common_name}
              </p>
              <p className="text-sm text-red-500 mt-4">
                Warning: This action cannot be undone. All certificates issued by this CA may become invalid.
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
