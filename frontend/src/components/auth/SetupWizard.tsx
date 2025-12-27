import { useState } from 'react'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import apiClient from '@/lib/api'

export default function SetupWizard() {
  const [step, setStep] = useState(1)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [masterKey, setMasterKey] = useState('')
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  const handleSubmit = async () => {
    if (password !== confirmPassword) {
      toast({
        title: "Error",
        description: "Passwords do not match",
        variant: "destructive",
      })
      return
    }

    if (password.length < 8) {
      toast({
        title: "Error",
        description: "Password must be at least 8 characters",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const result = await apiClient.performSetup(username, password)
      setMasterKey(result.master_key)
      localStorage.setItem('auth_token', result.token)
      setStep(2)
      toast({
        title: "Success",
        description: "Setup completed successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Setup failed",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const handleComplete = () => {
    // Reload the page to refetch setup status
    window.location.href = '/dashboard'
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0a0a0a] p-4">
      <Card className="w-full max-w-lg">
        {step === 1 && (
          <>
            <CardHeader>
              <CardTitle>Welcome to Open Certificate Manager</CardTitle>
              <CardDescription>
                Let's set up your admin account to get started
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  placeholder="admin"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={loading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="At least 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">Confirm Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={loading}
                />
              </div>
            </CardContent>
            <CardFooter>
              <Button 
                onClick={handleSubmit} 
                disabled={loading || !username || !password || !confirmPassword}
                className="w-full"
              >
                {loading ? "Setting up..." : "Complete Setup"}
              </Button>
            </CardFooter>
          </>
        )}

        {step === 2 && (
          <>
            <CardHeader>
              <CardTitle>Important: Save Your Master Key</CardTitle>
              <CardDescription>
                This key encrypts all private keys in the database. Store it securely!
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-md">
                <p className="text-sm font-medium text-yellow-800 mb-2">⚠️ Warning</p>
                <p className="text-sm text-yellow-700">
                  If you lose this key, you will not be able to decrypt your certificates.
                  Copy it now and store it in a secure location.
                </p>
              </div>
              <div className="space-y-2">
                <Label>Master Key</Label>
                <Input
                  value={masterKey}
                  readOnly
                  className="font-mono text-xs"
                  onFocus={(e) => e.target.select()}
                />
              </div>
              <Button
                variant="outline"
                className="w-full"
                onClick={() => {
                  navigator.clipboard.writeText(masterKey)
                  toast({
                    title: "Copied!",
                    description: "Master key copied to clipboard",
                  })
                }}
              >
                Copy to Clipboard
              </Button>
            </CardContent>
            <CardFooter>
              <Button onClick={handleComplete} className="w-full">
                I've Saved My Master Key - Continue
              </Button>
            </CardFooter>
          </>
        )}
      </Card>
    </div>
  )
}
