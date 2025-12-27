import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import { Shield } from 'lucide-react'
import apiClient from '@/lib/api'
import encryptionBg from '@/assets/encryption.png'

export default function LoginForm() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    setLoading(true)
    try {
      const result = await apiClient.login(username, password)
      localStorage.setItem('auth_token', result.token)
      toast({
        title: "Success",
        description: "Logged in successfully",
      })
      navigate('/dashboard')
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.response?.data?.error || "Login failed",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-2">
      {/* Left side - Testimonial/Branding */}
      <div className="relative hidden lg:flex flex-col justify-between bg-muted p-10 text-white dark:border-r">
        <div 
          className="absolute inset-0 bg-cover bg-center bg-no-repeat" 
          style={{ backgroundImage: `url(${encryptionBg})` }}
        />
        <div className="absolute inset-0 bg-black/85" />
        <div className="relative z-20 flex items-center text-2xl font-medium">
          <Shield className="mr-3 h-10 w-10" />
          Open Certificate Manager
        </div>
      </div>

      {/* Right side - Login Form */}
      <div className="flex items-center justify-center p-8">
        <div className="mx-auto flex w-full flex-col justify-center space-y-6 sm:w-[350px]">
          <div className="flex flex-col space-y-2 text-center">
            <h1 className="text-2xl font-semibold tracking-tight">
              Sign in to your account
            </h1>
            <p className="text-sm text-muted-foreground">
              Enter your credentials below to access your certificates
            </p>
          </div>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                required
              />
            </div>
            <Button 
              type="submit" 
              disabled={loading || !username || !password}
              className="w-full"
            >
              {loading ? "Signing in..." : "Sign In"}
            </Button>
          </form>
          <p className="px-8 text-center text-sm text-muted-foreground">
            Secure certificate management for your organization
          </p>
        </div>
      </div>
    </div>
  )
}
