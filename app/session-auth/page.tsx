'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { 
  Cookie, 
  Server, 
  Database, 
  CheckCircle, 
  AlertTriangle,
  Play,
  Code2,
  Lock,
  Clock
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import { useToast } from '@/hooks/use-toast';

export default function SessionAuth() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [sessionData, setSessionData] = useState('');
  const { toast } = useToast();

  const sessionBasics = `// What are Sessions?
// Sessions are server-side storage mechanisms that maintain user state
// across multiple HTTP requests. Unlike JWT tokens, session data is stored
// on the server, and only a session ID is sent to the client.

// Session Flow:
// 1. User logs in with credentials
// 2. Server creates a session and stores user data
// 3. Server sends session ID to client (usually in a cookie)
// 4. Client includes session ID in subsequent requests
// 5. Server uses session ID to retrieve user data

// Session vs JWT Comparison:
// Sessions: Server-side storage, more secure, requires server state
// JWT: Client-side storage, stateless, self-contained tokens`;

  const sessionSetupCode = `// lib/session.js
import { cookies } from 'next/headers';
import { SignJWT, jwtVerify } from 'jose';

const secretKey = process.env.SESSION_SECRET;
const encodedKey = new TextEncoder().encode(secretKey);

export async function createSession(userId, userData) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  
  const session = await new SignJWT({ userId, ...userData })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(encodedKey);

  cookies().set('session', session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: expiresAt,
    sameSite: 'lax',
    path: '/'
  });

  return session;
}

export async function getSession() {
  const cookieStore = cookies();
  const session = cookieStore.get('session')?.value;

  if (!session) return null;

  try {
    const { payload } = await jwtVerify(session, encodedKey);
    return payload;
  } catch (error) {
    console.error('Session verification failed:', error);
    return null;
  }
}

export async function deleteSession() {
  cookies().delete('session');
}

export async function updateSession() {
  const session = await getSession();
  if (!session) return null;

  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  
  const newSession = await new SignJWT(session)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(encodedKey);

  cookies().set('session', newSession, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: expiresAt,
    sameSite: 'lax',
    path: '/'
  });

  return newSession;
}`;

  const loginApiCode = `// app/api/auth/login/route.js
import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { createSession } from '@/lib/session';

export async function POST(request) {
  try {
    const { email, password } = await request.json();

    // Validate input
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Find user in database (mock implementation)
    const user = await findUserByEmail(email);
    if (!user) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.hashedPassword);
    if (!isValidPassword) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Create session
    await createSession(user.id, {
      email: user.email,
      name: user.name,
      role: user.role
    });

    return NextResponse.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// Mock user finder (replace with actual database query)
async function findUserByEmail(email) {
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
}`;

  const logoutApiCode = `// app/api/auth/logout/route.js
import { NextResponse } from 'next/server';
import { deleteSession } from '@/lib/session';

export async function POST() {
  try {
    await deleteSession();
    
    return NextResponse.json({
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}`;

  const protectedPageCode = `// app/dashboard/page.tsx
import { redirect } from 'next/navigation';
import { getSession } from '@/lib/session';

export default async function Dashboard() {
  const session = await getSession();

  if (!session) {
    redirect('/login');
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4">Welcome Back!</h2>
            <p className="text-gray-600 mb-2">
              <strong>Name:</strong> {session.name}
            </p>
            <p className="text-gray-600 mb-2">
              <strong>Email:</strong> {session.email}
            </p>
            <p className="text-gray-600">
              <strong>Role:</strong> {session.role}
            </p>
          </div>
          
          <div className="bg-blue-50 p-6 rounded-lg">
            <h3 className="text-lg font-semibold mb-3 text-blue-800">
              Session Information
            </h3>
            <p className="text-blue-700 text-sm">
              Your session is securely stored on the server and will expire 
              automatically after 7 days of inactivity.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}`;

  const clientHookCode = `// hooks/useSession.js
'use client';

import { useState, useEffect } from 'react';

export function useSession() {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSession();
  }, []);

  const fetchSession = async () => {
    try {
      const response = await fetch('/api/auth/session');
      if (response.ok) {
        const data = await response.json();
        setSession(data.session);
      } else {
        setSession(null);
      }
    } catch (error) {
      console.error('Session fetch error:', error);
      setSession(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      setLoading(true);
      
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.ok) {
        setSession(data.user);
        return { success: true, user: data.user };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      return { success: false, error: 'Network error' };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setSession(null);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  return { session, login, logout, loading, refetch: fetchSession };
}`;

  const handleDemoLogin = async () => {
    if (!email || !password) {
      toast({
        title: "Error",
        description: "Please enter email and password",
        variant: "destructive"
      });
      return;
    }

    // Mock session creation for demo
    const mockSessionData = {
      userId: '1',
      email: email,
      name: 'Demo User',
      role: 'student',
      createdAt: new Date().toISOString()
    };

    setSessionData(JSON.stringify(mockSessionData, null, 2));
    toast({
      title: "Success!",
      description: "Session created (demo mode)",
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">Session Authentication</Badge>
          <h1 className="text-4xl font-bold mb-4">Session-Based Authentication</h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Learn how to implement traditional server-side session management for secure, stateful authentication in Next.js.
          </p>
        </div>

        {/* Session Overview */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Cookie className="h-5 w-5 text-primary" />
              How Session Authentication Works
            </CardTitle>
            <CardDescription>
              Understanding the server-side session management approach
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              <div className="text-center">
                <div className="w-12 h-12 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Server className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Server Storage</h4>
                <p className="text-sm text-muted-foreground">Session data is stored securely on the server</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-green-100 text-green-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Cookie className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Session ID</h4>
                <p className="text-sm text-muted-foreground">Only a session identifier is sent to the client</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-purple-100 text-purple-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Database className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">State Management</h4>
                <p className="text-sm text-muted-foreground">Server maintains user state across requests</p>
              </div>
            </div>
            
            <CodeBlock
              code={sessionBasics}
              language="javascript"
              title="Session Authentication Concepts"
              description="Understanding how sessions work compared to stateless authentication"
            />
          </CardContent>
        </Card>

        {/* Interactive Demo */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Play className="h-5 w-5 text-green-500" />
              Interactive Session Demo
            </CardTitle>
            <CardDescription>
              See how session data is created and managed
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input 
                    id="email"
                    type="email" 
                    placeholder="student@university.edu"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input 
                    id="password"
                    type="password" 
                    placeholder="password123"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
                <Button onClick={handleDemoLogin} className="w-full">
                  <Cookie className="mr-2 h-4 w-4" />
                  Create Session
                </Button>
              </div>
              
              <div className="space-y-4">
                <Label>Session Data (Server-Side):</Label>
                <div className="p-3 bg-muted rounded-lg min-h-24 text-sm font-mono">
                  <pre>{sessionData || 'Session data will appear here after login...'}</pre>
                </div>
                {sessionData && (
                  <Alert>
                    <CheckCircle className="h-4 w-4" />
                    <AlertDescription>
                      Session created! In a real application, this data would be stored securely on the server.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Implementation Tabs */}
        <Tabs defaultValue="setup" className="mb-8">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="setup">Session Setup</TabsTrigger>
            <TabsTrigger value="login">Login API</TabsTrigger>
            <TabsTrigger value="logout">Logout API</TabsTrigger>
            <TabsTrigger value="protected">Protected Pages</TabsTrigger>
            <TabsTrigger value="client">Client Hook</TabsTrigger>
          </TabsList>
          
          <TabsContent value="setup">
            <Card>
              <CardHeader>
                <CardTitle>Session Management Setup</CardTitle>
                <CardDescription>
                  Core session utilities for creating, reading, and managing sessions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={sessionSetupCode}
                  language="javascript"
                  filename="lib/session.js"
                  description="Complete session management utilities using Next.js cookies and JWT for session tokens"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="login">
            <Card>
              <CardHeader>
                <CardTitle>Login API Route</CardTitle>
                <CardDescription>
                  Server-side authentication endpoint that creates sessions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={loginApiCode}
                  language="javascript"
                  filename="app/api/auth/login/route.js"
                  description="Login API route that validates credentials and creates secure sessions"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="logout">
            <Card>
              <CardHeader>
                <CardTitle>Logout API Route</CardTitle>
                <CardDescription>
                  Clean session termination and cookie cleanup
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={logoutApiCode}
                  language="javascript"
                  filename="app/api/auth/logout/route.js"
                  description="Simple logout endpoint that securely deletes the session cookie"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="protected">
            <Card>
              <CardHeader>
                <CardTitle>Protected Page Implementation</CardTitle>
                <CardDescription>
                  Server-side session verification in page components
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={protectedPageCode}
                  language="javascript"
                  filename="app/dashboard/page.tsx"
                  description="Protected page that checks session on the server before rendering"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="client">
            <Card>
              <CardHeader>
                <CardTitle>Client-Side Session Hook</CardTitle>
                <CardDescription>
                  React hook for managing session state on the client
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={clientHookCode}
                  language="javascript"
                  filename="hooks/useSession.js"
                  description="Custom React hook for session management with login, logout, and state synchronization"
                />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Session vs JWT Comparison */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Session vs JWT Comparison</CardTitle>
            <CardDescription>
              Understanding when to use each authentication method
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-semibold text-blue-600">🍪 Session-Based Auth</h4>
                <div className="space-y-3">
                  <div>
                    <h5 className="font-medium text-green-600">✅ Advantages:</h5>
                    <ul className="text-sm space-y-1 mt-1">
                      <li>• Server controls session lifecycle</li>
                      <li>• Can revoke sessions instantly</li>
                      <li>• No sensitive data in client storage</li>
                      <li>• Smaller cookie size</li>
                      <li>• Better for sensitive applications</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium text-red-600">❌ Disadvantages:</h5>
                    <ul className="text-sm space-y-1 mt-1">
                      <li>• Requires server-side storage</li>
                      <li>• Harder to scale horizontally</li>
                      <li>• Server state management complexity</li>
                      <li>• Not suitable for stateless APIs</li>
                    </ul>
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <h4 className="font-semibold text-purple-600">🔑 JWT-Based Auth</h4>
                <div className="space-y-3">
                  <div>
                    <h5 className="font-medium text-green-600">✅ Advantages:</h5>
                    <ul className="text-sm space-y-1 mt-1">
                      <li>• Stateless and scalable</li>
                      <li>• Self-contained tokens</li>
                      <li>• Works across domains</li>
                      <li>• No server-side storage needed</li>
                      <li>• Great for APIs and microservices</li>
                    </ul>
                  </div>
                  <div>
                    <h5 className="font-medium text-red-600">❌ Disadvantages:</h5>
                    <ul className="text-sm space-y-1 mt-1">
                      <li>• Cannot revoke tokens easily</li>
                      <li>• Larger token size</li>
                      <li>• Token expiration management</li>
                      <li>• Potential security risks if mishandled</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Security Considerations */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-red-500" />
              Session Security Best Practices
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-semibold text-green-600">✅ Do:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use httpOnly cookies for session IDs
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Set secure flag in production (HTTPS)
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Implement session timeout
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Regenerate session IDs after login
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use SameSite cookie attribute
                  </li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h4 className="font-semibold text-red-600">❌ Don't:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Store session data in client-side storage
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Use predictable session IDs
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Forget to clean up expired sessions
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Allow concurrent sessions without limits
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Expose session data in URLs or logs
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
              Test your understanding of session-based authentication
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Challenge: Session Store Implementation</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Implement a Redis-based session store for production use. Include session cleanup, 
                  concurrent session limits, and session data encryption.
                </p>
                <Button variant="outline">
                  <Clock className="mr-2 h-4 w-4" />
                  View Solution
                </Button>
              </div>
              
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Quiz: Session Security</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Test your knowledge of session security vulnerabilities and mitigation strategies.
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