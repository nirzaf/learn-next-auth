'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet';
import { Badge } from '@/components/ui/badge';
import { ThemeToggle } from '@/components/theme-toggle';
import { useAuth } from '@/contexts/auth-context';
import { useProgress } from '@/contexts/progress-context';
import { 
  Menu, 
  BookOpen, 
  Code2, 
  Shield, 
  Users,
  LogIn,
  LogOut,
  User,
  Trophy,
  Target,
  Play
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navigation = [
  {
    name: 'Getting Started',
    href: '/getting-started',
    icon: BookOpen,
    description: 'Authentication fundamentals'
  },
  {
    name: 'JWT Auth',
    href: '/jwt-auth',
    icon: Shield,
    description: 'JSON Web Token authentication'
  },
  {
    name: 'Session Auth',
    href: '/session-auth',
    icon: Users,
    description: 'Server-side session management'
  },
  {
    name: 'OAuth',
    href: '/oauth-auth',
    icon: Shield,
    description: 'Third-party authentication'
  },
  {
    name: 'Protected Routes',
    href: '/protected-routes',
    icon: Shield,
    description: 'Route guards and middleware'
  },
  {
    name: 'Advanced Security',
    href: '/advanced-security',
    icon: Target,
    description: 'Security best practices'
  },
  {
    name: 'Examples',
    href: '/examples',
    icon: Code2,
    description: 'Code examples and tutorials'
  },
  {
    name: 'Playground',
    href: '/playground',
    icon: Play,
    description: 'Interactive code editor'
  }
];

export function Navigation() {
  const [isOpen, setIsOpen] = useState(false);
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { getTotalProgress, achievements } = useProgress();

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto px-4">
        <div className="flex h-16 items-center justify-between">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 font-bold text-xl">
              <Shield className="h-6 w-6 text-primary" />
              <span className="hidden sm:inline">Auth Learn</span>
            </Link>
            
            <nav className="hidden lg:flex items-center gap-1">
              {navigation.slice(0, 6).map((item) => (
                <Button
                  key={item.name}
                  variant={pathname === item.href ? 'secondary' : 'ghost'}
                  className={cn(
                    'gap-2 text-sm',
                    pathname === item.href && 'bg-primary/10 text-primary'
                  )}
                  asChild
                >
                  <Link href={item.href}>
                    <item.icon className="h-4 w-4" />
                    <span className="hidden xl:inline">{item.name}</span>
                  </Link>
                </Button>
              ))}
            </nav>
          </div>

          <div className="flex items-center gap-4">
            {user && (
              <div className="hidden md:flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <Trophy className="h-4 w-4 text-yellow-500" />
                  <Badge variant="secondary">{achievements.length}</Badge>
                </div>
                <div className="flex items-center gap-2">
                  <Target className="h-4 w-4 text-primary" />
                  <Badge variant="outline">{getTotalProgress()}%</Badge>
                </div>
              </div>
            )}
            
            <ThemeToggle />
            
            {user ? (
              <div className="flex items-center gap-2">
                <Button variant="ghost" className="gap-2" asChild>
                  <Link href="/dashboard">
                    <User className="h-4 w-4" />
                    <span className="hidden sm:inline">{user.name}</span>
                  </Link>
                </Button>
                <Button variant="outline" onClick={logout} className="gap-2">
                  <LogOut className="h-4 w-4" />
                  <span className="hidden sm:inline">Logout</span>
                </Button>
              </div>
            ) : (
              <Button asChild className="gap-2">
                <Link href="/login">
                  <LogIn className="h-4 w-4" />
                  Login
                </Link>
              </Button>
            )}

            <Sheet open={isOpen} onOpenChange={setIsOpen}>
              <SheetTrigger asChild className="lg:hidden">
                <Button variant="ghost" size="sm">
                  <Menu className="h-5 w-5" />
                  <span className="sr-only">Toggle navigation menu</span>
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="w-[300px]">
                <div className="flex flex-col gap-4 mt-6">
                  {user && (
                    <div className="p-4 border rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <User className="h-4 w-4" />
                        <span className="font-medium">{user.name}</span>
                      </div>
                      <div className="flex items-center justify-between text-sm text-muted-foreground">
                        <span>Progress: {getTotalProgress()}%</span>
                        <span>Achievements: {achievements.length}</span>
                      </div>
                    </div>
                  )}
                  
                  <nav className="flex flex-col gap-2">
                    {navigation.map((item) => (
                      <Button
                        key={item.name}
                        variant={pathname === item.href ? 'secondary' : 'ghost'}
                        className="justify-start gap-3 h-auto p-3"
                        asChild
                        onClick={() => setIsOpen(false)}
                      >
                        <Link href={item.href}>
                          <item.icon className="h-4 w-4" />
                          <div className="text-left">
                            <div className="font-medium">{item.name}</div>
                            <div className="text-xs text-muted-foreground">
                              {item.description}
                            </div>
                          </div>
                        </Link>
                      </Button>
                    ))}
                  </nav>
                  
                  {user && (
                    <Button asChild className="mt-4">
                      <Link href="/dashboard" onClick={() => setIsOpen(false)}>
                        <Trophy className="mr-2 h-4 w-4" />
                        Dashboard
                      </Link>
                    </Button>
                  )}
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </header>
  );
}