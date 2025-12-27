import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Shield, LayoutDashboard, FileKey, LogOut, User } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'

interface SidebarLayoutProps {
  children: React.ReactNode
}

export default function SidebarLayout({ children }: SidebarLayoutProps) {
  const location = useLocation()
  const navigate = useNavigate()

  const handleLogout = () => {
    localStorage.removeItem('auth_token')
    navigate('/login')
  }

  const navItems = [
    {
      title: 'Dashboard',
      href: '/dashboard',
      icon: LayoutDashboard,
    },
    {
      title: 'Certificate Authorities',
      href: '/authorities',
      icon: Shield,
    },
    {
      title: 'Certificates',
      href: '/certificates',
      icon: FileKey,
    },
  ]

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <div className="hidden border-r bg-muted/40 md:block md:w-[220px] lg:w-[280px]">
        <div className="flex h-full max-h-screen flex-col gap-2">
          {/* Logo/Brand */}
          <div className="flex h-14 items-center border-b px-4 lg:h-[60px] lg:px-6">
            <Link to="/dashboard" className="flex items-center gap-2 font-semibold">
              <Shield className="h-6 w-6" />
              <span className="text-lg">OCM</span>
            </Link>
          </div>

          {/* Navigation */}
          <div className="flex-1 overflow-auto py-2">
            <nav className="grid items-start px-2 text-sm font-medium lg:px-4">
              {navItems.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.href
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    className={cn(
                      "flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary",
                      isActive && "bg-muted text-primary"
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    {item.title}
                  </Link>
                )
              })}
            </nav>
          </div>

          <Separator />

          {/* User Section */}
          <div className="mt-auto p-4">
            <div className="flex items-center gap-3 rounded-lg bg-muted px-3 py-2">
              <Avatar className="h-8 w-8">
                <AvatarFallback>
                  <User className="h-4 w-4" />
                </AvatarFallback>
              </Avatar>
              <div className="flex-1 overflow-hidden">
                <p className="text-sm font-medium leading-none">Admin</p>
                <p className="text-xs text-muted-foreground">Administrator</p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="mt-2 w-full justify-start"
              onClick={handleLogout}
            >
              <LogOut className="mr-2 h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex flex-1 flex-col">
        {/* Header */}
        <header className="flex h-14 items-center gap-4 border-b bg-muted/40 px-4 lg:h-[60px] lg:px-6">
          <div className="w-full flex-1">
            <h1 className="text-lg font-semibold">Open Certificate Manager</h1>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            onClick={handleLogout}
          >
            <LogOut className="h-5 w-5" />
          </Button>
        </header>

        {/* Page Content */}
        <main className="flex flex-1 flex-col gap-4 p-4 lg:gap-6 lg:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
