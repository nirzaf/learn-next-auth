'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Play, 
  Save, 
  Download, 
  Upload,
  Code2, 
  Terminal,
  CheckCircle,
  AlertTriangle,
  Lightbulb,
  BookOpen
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import { useAuth } from '@/contexts/auth-context';
import { useProgress } from '@/contexts/progress-context';

// Use the PlaygroundProject type from progress context

interface Template {
  title: string;
  description: string;
  code: string;
}

type TemplateKey = 'jwt-login' | 'session-middleware' | 'oauth-setup' | 'protected-component';

export default function Playground() {
  const { user } = useAuth();
  const { savePlaygroundCode, getSavedCode } = useProgress();
  const [selectedTemplate, setSelectedTemplate] = useState<TemplateKey>('jwt-login');
  const [code, setCode] = useState('');
  const [output, setOutput] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [savedProjects, setSavedProjects] = useState<any[]>([]);

  const templates: Record<TemplateKey, Template> = {
    'jwt-login': {
      title: 'JWT Login API',
      description: 'Complete JWT authentication endpoint',
      code: `// pages/api/auth/login.js
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { email, password } = req.body;

  try {
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    // Mock user lookup (replace with database query)
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.hashedPassword);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
}

async function findUserByEmail(email) {
  // Mock implementation - replace with actual database query
  const mockUsers = [
    {
      id: '1',
      email: 'student@university.edu',
      hashedPassword: await bcrypt.hash('password123', 12),
      name: 'John Doe',
      role: 'student'
    }
  ];
  
  return mockUsers.find(user => user.email === email);
}`
    },
    'session-middleware': {
      title: 'Session Middleware',
      description: 'Next.js middleware for session protection',
      code: `// middleware.js
import { NextResponse } from 'next/server';
import { getSession } from '@/lib/session';

export async function middleware(request) {
  // Define protected paths
  const protectedPaths = ['/dashboard', '/profile', '/admin'];
  const isProtectedPath = protectedPaths.some(path => 
    request.nextUrl.pathname.startsWith(path)
  );

  if (isProtectedPath) {
    try {
      const session = await getSession(request);
      
      if (!session) {
        // Redirect to login if no session
        const loginUrl = new URL('/login', request.url);
        loginUrl.searchParams.set('from', request.nextUrl.pathname);
        return NextResponse.redirect(loginUrl);
      }

      // Check if session is expired
      if (session.exp && Date.now() >= session.exp * 1000) {
        const loginUrl = new URL('/login', request.url);
        return NextResponse.redirect(loginUrl);
      }

      // Session is valid, continue
      return NextResponse.next();
      
    } catch (error) {
      console.error('Middleware error:', error);
      const loginUrl = new URL('/login', request.url);
      return NextResponse.redirect(loginUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/profile/:path*',
    '/admin/:path*'
  ]
};`
    },
    'oauth-setup': {
      title: 'OAuth Configuration',
      description: 'NextAuth.js OAuth provider setup',
      code: `// pages/api/auth/[...nextauth].js
import NextAuth from 'next-auth'
import GoogleProvider from 'next-auth/providers/google'
import GitHubProvider from 'next-auth/providers/github'

export default NextAuth({
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    GitHubProvider({
      clientId: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
    })
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      // Persist the OAuth access_token to the token right after signin
      if (account) {
        token.accessToken = account.access_token
        token.provider = account.provider
      }
      return token
    },
    async session({ session, token }) {
      // Send properties to the client
      session.accessToken = token.accessToken
      session.provider = token.provider
      return session
    },
    async signIn({ user, account, profile }) {
      // Custom sign-in logic
      console.log('User signing in:', user.email);
      
      // You can add custom validation here
      // Return true to allow sign in, false to deny
      return true;
    },
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith("/")) return \`\${baseUrl}\${url}\`
      // Allows callback URLs on the same origin
      else if (new URL(url).origin === baseUrl) return url
      return baseUrl
    }
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  jwt: {
    maxAge: 30 * 24 * 60 * 60, // 30 days
  }
})`
    },
    'protected-component': {
      title: 'Protected React Component',
      description: 'Higher-order component for route protection',
      code: `// components/ProtectedRoute.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/auth-context';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
  fallback?: React.ReactNode;
}

export function ProtectedRoute({ 
  children, 
  requiredRole, 
  fallback 
}: ProtectedRouteProps) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [isAuthorized, setIsAuthorized] = useState(false);

  useEffect(() => {
    if (!loading) {
      if (!user) {
        router.push('/login');
        return;
      }

      if (requiredRole && user.role !== requiredRole) {
        router.push('/unauthorized');
        return;
      }

      setIsAuthorized(true);
    }
  }, [user, loading, requiredRole, router]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!isAuthorized) {
    return fallback || null;
  }

  return <>{children}</>;
}

// Usage example:
export function AdminPage() {
  return (
    <ProtectedRoute requiredRole="admin">
      <div className="p-8">
        <h1 className="text-2xl font-bold">Admin Dashboard</h1>
        <p>This content is only visible to admin users.</p>
      </div>
    </ProtectedRoute>
  );
}

// Higher-order component version
export function withAuth<T extends object>(
  Component: React.ComponentType<T>,
  requiredRole?: string
) {
  return function AuthenticatedComponent(props: T) {
    return (
      <ProtectedRoute requiredRole={requiredRole}>
        <Component {...props} />
      </ProtectedRoute>
    );
  };
}`
    }
  };

  useEffect(() => {
    if (selectedTemplate && templates[selectedTemplate]) {
      setCode(templates[selectedTemplate].code);
    }
  }, [selectedTemplate]);

  useEffect(() => {
    if (user) {
      const saved = getSavedCode();
      setSavedProjects(saved);
    }
  }, [user, getSavedCode]);

  const runCode = async () => {
    setIsRunning(true);
    setOutput('Running code...\n');
    
    // Simulate code execution
    setTimeout(() => {
      try {
        // Mock output based on template
        let mockOutput = '';
        
        if (selectedTemplate === 'jwt-login') {
          mockOutput = `✅ JWT Login API Analysis:
- Input validation: ✓
- Password hashing: ✓ (bcrypt)
- JWT token creation: ✓
- Error handling: ✓
- Security headers: ⚠️ Consider adding rate limiting

Mock Response:
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "1",
    "email": "student@university.edu",
    "name": "John Doe",
    "role": "student"
  }
}`;
        } else if (selectedTemplate === 'session-middleware') {
          mockOutput = `✅ Middleware Analysis:
- Path protection: ✓
- Session validation: ✓
- Redirect logic: ✓
- Error handling: ✓

Protected paths: /dashboard, /profile, /admin
Redirect URL: /login?from=/dashboard`;
        } else {
          mockOutput = `✅ Code executed successfully!
No syntax errors found.
Security best practices: ✓
Performance optimizations: ✓`;
        }
        
        setOutput(mockOutput);
      } catch (error) {
        setOutput(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
      setIsRunning(false);
    }, 2000);
  };

  const saveCode = () => {
    if (!user) return;
    
    const projectName = `${templates[selectedTemplate]?.title || 'Untitled'} - ${new Date().toLocaleDateString()}`;
    savePlaygroundCode(projectName, code, selectedTemplate);
    setSavedProjects(getSavedCode());
  };

  const loadSavedProject = (project: any) => {
    setCode(project.code);
    setSelectedTemplate(project.template as TemplateKey);
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
        <Navigation />
        <div className="container mx-auto px-4 py-8 text-center">
          <h1 className="text-2xl font-bold mb-4">Please log in to access the playground</h1>
          <Button asChild>
            <Link href="/login">Login</Link>
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-7xl">
        <div className="mb-8">
          <Badge className="mb-4">Interactive Playground</Badge>
          <h1 className="text-4xl font-bold mb-4">Code Playground</h1>
          <p className="text-xl text-muted-foreground">
            Practice authentication concepts with live code examples and instant feedback.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Templates</CardTitle>
                <CardDescription>Choose a starting template</CardDescription>
              </CardHeader>
              <CardContent>
                <Select value={selectedTemplate} onValueChange={(value) => setSelectedTemplate(value as TemplateKey)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select template" />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(templates).map(([key, template]) => (
                      <SelectItem key={key} value={key}>
                        {template.title}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                
                {selectedTemplate && (
                  <div className="mt-4 p-3 bg-muted rounded-lg">
                    <h4 className="font-semibold text-sm mb-1">
                      {templates[selectedTemplate].title}
                    </h4>
                    <p className="text-xs text-muted-foreground">
                      {templates[selectedTemplate].description}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Saved Projects</CardTitle>
                <CardDescription>Your saved code snippets</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {savedProjects.length > 0 ? (
                    savedProjects.map((project, index) => (
                      <Button
                        key={index}
                        variant="outline"
                        className="w-full justify-start text-left h-auto p-3"
                        onClick={() => loadSavedProject(project)}
                      >
                        <div>
                          <div className="font-medium text-sm">{project.name}</div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(project.savedAt).toLocaleDateString()}
                          </div>
                        </div>
                      </Button>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground">No saved projects yet</p>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Lightbulb className="h-4 w-4" />
                  Tips
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm">
                  <p>• Use Ctrl+S to save your code</p>
                  <p>• Click Run to test your implementation</p>
                  <p>• Check the output for security analysis</p>
                  <p>• Experiment with different approaches</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <Tabs defaultValue="editor" className="space-y-6">
              <TabsList>
                <TabsTrigger value="editor">Code Editor</TabsTrigger>
                <TabsTrigger value="output">Output</TabsTrigger>
                <TabsTrigger value="docs">Documentation</TabsTrigger>
              </TabsList>
              
              <TabsContent value="editor">
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle>Code Editor</CardTitle>
                        <CardDescription>
                          Write and test your authentication code
                        </CardDescription>
                      </div>
                      <div className="flex gap-2">
                        <Button variant="outline" onClick={saveCode}>
                          <Save className="mr-2 h-4 w-4" />
                          Save
                        </Button>
                        <Button onClick={runCode} disabled={isRunning}>
                          <Play className="mr-2 h-4 w-4" />
                          {isRunning ? 'Running...' : 'Run'}
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <Textarea
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      className="min-h-[500px] font-mono text-sm"
                      placeholder="Write your authentication code here..."
                    />
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="output">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Terminal className="h-5 w-5" />
                      Output Console
                    </CardTitle>
                    <CardDescription>
                      Code execution results and security analysis
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="bg-black text-green-400 p-4 rounded-lg font-mono text-sm min-h-[400px] whitespace-pre-wrap">
                      {output || 'Click "Run" to execute your code and see the output here...'}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
              
              <TabsContent value="docs">
                <div className="space-y-6">
                  <Card>
                    <CardHeader>
                      <CardTitle>Quick Reference</CardTitle>
                      <CardDescription>
                        Common authentication patterns and best practices
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-semibold mb-2">JWT Best Practices</h4>
                          <ul className="text-sm space-y-1 text-muted-foreground">
                            <li>• Use strong secrets (256-bit minimum)</li>
                            <li>• Set appropriate expiration times</li>
                            <li>• Include necessary claims only</li>
                            <li>• Validate tokens on every request</li>
                          </ul>
                        </div>
                        <div>
                          <h4 className="font-semibold mb-2">Session Security</h4>
                          <ul className="text-sm space-y-1 text-muted-foreground">
                            <li>• Use httpOnly cookies</li>
                            <li>• Set secure flag in production</li>
                            <li>• Implement session timeout</li>
                            <li>• Regenerate session IDs</li>
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Common Patterns</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CodeBlock
                        code={`// Password hashing with bcrypt
const bcrypt = require('bcryptjs');
const saltRounds = 12;

// Hash password
const hashedPassword = await bcrypt.hash(password, saltRounds);

// Verify password
const isValid = await bcrypt.compare(password, hashedPassword);`}
                        language="javascript"
                        title="Password Hashing"
                      />
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </main>
    </div>
  );
}