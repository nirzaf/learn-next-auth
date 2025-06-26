'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, 
  Lock, 
  Key, 
  CheckCircle, 
  AlertTriangle,
  Code2,
  Server,
  Globe,
  Users
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import { useAuth } from '@/contexts/auth-context';

export default function ProtectedRoutes() {
  const { user } = useAuth();
  const [selectedExample, setSelectedExample] = useState('middleware');

  const middlewareCode = `// middleware.js (Next.js 12.2+)
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';

export function middleware(request) {
  // Define protected paths
  const protectedPaths = ['/dashboard', '/profile', '/admin'];
  const isProtectedPath = protectedPaths.some(path => 
    request.nextUrl.pathname.startsWith(path)
  );

  if (isProtectedPath) {
    // Check for JWT token in cookies or Authorization header
    const token = request.cookies.get('jwt-token')?.value || 
                  request.headers.get('authorization')?.replace('Bearer ', '');

    if (!token) {
      // Redirect to login if no token
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('from', request.nextUrl.pathname);
      return NextResponse.redirect(loginUrl);
    }

    try {
      // Verify token
      jwt.verify(token, process.env.JWT_SECRET);
      
      // Token is valid, continue to the protected page
      return NextResponse.next();
    } catch (error) {
      // Token is invalid, redirect to login
      const loginUrl = new URL('/login', request.url);
      return NextResponse.redirect(loginUrl);
    }
  }

  // Not a protected path, continue normally
  return NextResponse.next();
}

// Configure which paths the middleware runs on
export const config = {
  matcher: [
    '/dashboard/:path*',
    '/profile/:path*',
    '/admin/:path*'
  ]
};`;

  const serverSideCode = `// app/dashboard/page.tsx
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';

async function verifyAuth() {
  const cookieStore = cookies();
  const token = cookieStore.get('jwt-token')?.value;

  if (!token) {
    return null;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded;
  } catch (error) {
    return null;
  }
}

export default async function Dashboard() {
  const user = await verifyAuth();

  if (!user) {
    redirect('/login');
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
      <div className="bg-white p-6 rounded-lg shadow">
        <h2 className="text-xl font-semibold mb-4">Welcome, {user.email}!</h2>
        <p className="text-gray-600">
          This is a protected page that requires authentication.
        </p>
      </div>
    </div>
  );
}`;

  const clientSideCode = `// components/ProtectedRoute.tsx
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/auth-context';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading) {
      if (!user) {
        // User is not authenticated, redirect to login
        router.push('/login');
        return;
      }

      if (requiredRole && user.role !== requiredRole) {
        // User doesn't have required role, redirect to unauthorized page
        router.push('/unauthorized');
        return;
      }
    }
  }, [user, loading, requiredRole, router]);

  // Show loading while checking authentication
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Don't render children if user is not authenticated or doesn't have required role
  if (!user || (requiredRole && user.role !== requiredRole)) {
    return null;
  }

  return <>{children}</>;
}

// Usage in a page component:
// export default function AdminPage() {
//   return (
//     <ProtectedRoute requiredRole="admin">
//       <div>Admin content here</div>
//     </ProtectedRoute>
//   );
// }`;

  const roleBasedCode = `// lib/auth.js
export const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  MODERATOR: 'moderator'
};

export const PERMISSIONS = {
  READ_USERS: 'read:users',
  WRITE_USERS: 'write:users',
  DELETE_USERS: 'delete:users',
  MANAGE_CONTENT: 'manage:content'
};

export const rolePermissions = {
  [ROLES.ADMIN]: [
    PERMISSIONS.READ_USERS,
    PERMISSIONS.WRITE_USERS,
    PERMISSIONS.DELETE_USERS,
    PERMISSIONS.MANAGE_CONTENT
  ],
  [ROLES.MODERATOR]: [
    PERMISSIONS.READ_USERS,
    PERMISSIONS.MANAGE_CONTENT
  ],
  [ROLES.USER]: [
    PERMISSIONS.READ_USERS
  ]
};

export function hasPermission(userRole, requiredPermission) {
  const permissions = rolePermissions[userRole] || [];
  return permissions.includes(requiredPermission);
}

// Higher-order component for permission-based access
export function withPermission(Component, requiredPermission) {
  return function PermissionWrapper(props) {
    const { user } = useAuth();
    
    if (!user || !hasPermission(user.role, requiredPermission)) {
      return <div>Access denied. Insufficient permissions.</div>;
    }
    
    return <Component {...props} />;
  };
}`;

  const protectionMethods = [
    {
      title: 'Middleware Protection',
      description: 'Edge-level route protection using Next.js middleware',
      icon: Globe,
      pros: ['Runs at the edge', 'Fast execution', 'Blocks requests early'],
      cons: ['Limited to simple logic', 'No access to React context']
    },
    {
      title: 'Server-Side Protection',
      description: 'Server-side authentication checks in page components',
      icon: Server,
      pros: ['Full server capabilities', 'SEO friendly', 'Secure by default'],
      cons: ['Slower than middleware', 'Requires server round-trip']
    },
    {
      title: 'Client-Side Protection',
      description: 'React component-based route protection',
      icon: Users,
      pros: ['Rich user experience', 'Access to React state', 'Flexible UI'],
      cons: ['Not secure alone', 'Requires loading states', 'SEO limitations']
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">Route Protection</Badge>
          <h1 className="text-4xl font-bold mb-4">Protected Routes & Authorization</h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Learn how to implement route guards, middleware protection, and role-based access control in Next.js applications.
          </p>
        </div>

        {/* Current User Status */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              Current Authentication Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            {user ? (
              <Alert>
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Authenticated:</strong> Logged in as {user.name} ({user.email}) with role: {user.role || 'user'}
                </AlertDescription>
              </Alert>
            ) : (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Not Authenticated:</strong> You would be redirected to login when accessing protected routes
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        {/* Protection Methods Overview */}
        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6">Route Protection Methods</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {protectionMethods.map((method, index) => (
              <Card key={index} className="h-full">
                <CardHeader>
                  <div className="flex items-center gap-3 mb-2">
                    <method.icon className="h-6 w-6 text-primary" />
                    <CardTitle className="text-lg">{method.title}</CardTitle>
                  </div>
                  <CardDescription>{method.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-semibold text-green-600 mb-2">✅ Pros:</h5>
                      <ul className="text-sm space-y-1">
                        {method.pros.map((pro, i) => (
                          <li key={i} className="flex items-center gap-2">
                            <div className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                            {pro}
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-semibold text-amber-600 mb-2">⚠️ Cons:</h5>
                      <ul className="text-sm space-y-1">
                        {method.cons.map((con, i) => (
                          <li key={i} className="flex items-center gap-2">
                            <div className="w-1.5 h-1.5 bg-amber-500 rounded-full" />
                            {con}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Implementation Examples */}
        <Tabs value={selectedExample} onValueChange={setSelectedExample} className="mb-8">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="middleware">Middleware</TabsTrigger>
            <TabsTrigger value="server-side">Server-Side</TabsTrigger>
            <TabsTrigger value="client-side">Client-Side</TabsTrigger>
            <TabsTrigger value="role-based">Role-Based</TabsTrigger>
          </TabsList>
          
          <TabsContent value="middleware">
            <Card>
              <CardHeader>
                <CardTitle>Next.js Middleware Protection</CardTitle>
                <CardDescription>
                  Protect routes at the edge using Next.js middleware for optimal performance
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={middlewareCode}
                  language="javascript"
                  filename="middleware.js"
                  description="Edge middleware that runs before pages are rendered to check authentication"
                />
                <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-950/20 rounded-lg">
                  <h4 className="font-semibold text-blue-800 dark:text-blue-400 mb-2">Key Benefits:</h4>
                  <ul className="text-sm text-blue-700 dark:text-blue-300 space-y-1">
                    <li>• Runs at the edge for maximum performance</li>
                    <li>• Blocks unauthorized requests before they reach your pages</li>
                    <li>• Automatic redirects with return URL preservation</li>
                    <li>• Works with both cookies and Authorization headers</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="server-side">
            <Card>
              <CardHeader>
                <CardTitle>Server-Side Route Protection</CardTitle>
                <CardDescription>
                  Implement authentication checks in server components and page functions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={serverSideCode}
                  language="javascript"
                  filename="app/dashboard/page.tsx"
                  description="Server component with authentication verification using Next.js App Router"
                />
                <div className="mt-4 p-4 bg-green-50 dark:bg-green-950/20 rounded-lg">
                  <h4 className="font-semibold text-green-800 dark:text-green-400 mb-2">Advantages:</h4>
                  <ul className="text-sm text-green-700 dark:text-green-300 space-y-1">
                    <li>• SEO-friendly - protected content never reaches the client</li>
                    <li>• Secure by default - no client-side authentication bypass</li>
                    <li>• Full server capabilities for complex authentication logic</li>
                    <li>• Works perfectly with Next.js App Router</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="client-side">
            <Card>
              <CardHeader>
                <CardTitle>Client-Side Route Protection</CardTitle>
                <CardDescription>
                  Create reusable React components for protecting routes on the client side
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={clientSideCode}
                  language="javascript"
                  filename="components/ProtectedRoute.tsx"
                  description="Reusable React component for client-side route protection with role-based access"
                />
                <div className="mt-4 p-4 bg-purple-50 dark:bg-purple-950/20 rounded-lg">
                  <h4 className="font-semibold text-purple-800 dark:text-purple-400 mb-2">Use Cases:</h4>
                  <ul className="text-sm text-purple-700 dark:text-purple-300 space-y-1">
                    <li>• Rich user interfaces with loading states</li>
                    <li>• Dynamic content based on user permissions</li>
                    <li>• Gradual access control within single pages</li>
                    <li>• Integration with React state management</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="role-based">
            <Card>
              <CardHeader>
                <CardTitle>Role-Based Access Control (RBAC)</CardTitle>
                <CardDescription>
                  Implement sophisticated permission systems with roles and granular permissions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={roleBasedCode}
                  language="javascript"
                  filename="lib/auth.js"
                  description="Complete RBAC system with roles, permissions, and higher-order components"
                />
                <div className="mt-4 p-4 bg-amber-50 dark:bg-amber-950/20 rounded-lg">
                  <h4 className="font-semibold text-amber-800 dark:text-amber-400 mb-2">RBAC Benefits:</h4>
                  <ul className="text-sm text-amber-700 dark:text-amber-300 space-y-1">
                    <li>• Scalable permission management</li>
                    <li>• Fine-grained access control</li>
                    <li>• Easy role assignment and modification</li>
                    <li>• Separation of concerns between authentication and authorization</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Security Best Practices */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-red-500" />
              Security Best Practices
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-semibold text-green-600">✅ Do:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Always validate authentication on the server
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use HTTPS in production environments
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Implement proper session timeout
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use secure, httpOnly cookies for tokens
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Implement rate limiting on auth endpoints
                  </li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h4 className="font-semibold text-red-600">❌ Don't:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Rely solely on client-side protection
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Store sensitive data in localStorage
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Expose user roles/permissions in URLs
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Trust client-side role/permission checks
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Forget to handle edge cases and errors
                  </li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Practice Exercise */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code2 className="h-5 w-5 text-blue-500" />
              Practice Exercise
            </CardTitle>
            <CardDescription>
              Test your understanding of route protection concepts
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Challenge: Multi-Level Protection</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Create a page that requires both authentication and admin role. Implement three layers of protection:
                  middleware for basic auth, server-side for role checking, and client-side for UI enhancement.
                </p>
                <Button variant="outline">
                  <Key className="mr-2 h-4 w-4" />
                  View Solution
                </Button>
              </div>
              
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Quiz: Security Scenarios</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Test your knowledge of security vulnerabilities and how to prevent them in route protection.
                </p>
                <Button variant="outline">
                  <CheckCircle className="mr-2 h-4 w-4" />
                  Take Quiz
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}