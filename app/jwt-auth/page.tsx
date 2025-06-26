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
  Key, 
  Shield, 
  Clock, 
  CheckCircle, 
  AlertTriangle,
  Play,
  Code2,
  Database,
  Lock
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import { useToast } from '@/hooks/use-toast';

export default function JWTAuth() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const { toast } = useToast();

  const jwtBasics = `// What is a JWT (JSON Web Token)?
// A JWT consists of three parts separated by dots:
// Header.Payload.Signature

// Example JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

// Decoded Header:
{
  "alg": "HS256",  // Algorithm used for signing
  "typ": "JWT"     // Token type
}

// Decoded Payload:
{
  "sub": "1234567890",        // Subject (user ID)
  "name": "John Doe",         // User data
  "iat": 1516239022,          // Issued at time
  "exp": 1516325422           // Expiration time
}

// Signature is created by:
// HMACSHA256(
//   base64UrlEncode(header) + "." +
//   base64UrlEncode(payload),
//   secret
// )`;

  const loginApiCode = `// pages/api/auth/login.js
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { email, password } = req.body;

  try {
    // 1. Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    // 2. Find user in database (mock implementation)
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 3. Verify password
    const isValidPassword = await bcrypt.compare(password, user.hashedPassword);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 4. Create JWT token
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: '7d',
        issuer: 'your-app-name',
        audience: 'your-app-users'
      }
    );

    // 5. Return token and user data
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

// Helper function to find user by email
async function findUserByEmail(email) {
  // In a real app, this would query your database
  // Example with Prisma ORM:
  // return await prisma.user.findUnique({ where: { email } });
  
  // Mock user for demonstration
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

  const clientSideCode = `// hooks/useAuth.js
import { useState, useEffect } from 'react';

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing token on mount
    const token = localStorage.getItem('jwt-token');
    if (token) {
      // Verify token and get user data
      verifyToken(token);
    } else {
      setLoading(false);
    }
  }, []);

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
        // Store token in localStorage
        localStorage.setItem('jwt-token', data.token);
        setUser(data.user);
        return { success: true, user: data.user };
      } else {
        return { success: false, error: data.message };
      }
    } catch (error) {
      return { success: false, error: 'Network error' };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('jwt-token');
    setUser(null);
  };

  const verifyToken = async (token) => {
    try {
      const response = await fetch('/api/auth/verify', {
        headers: {
          'Authorization': \`Bearer \${token}\`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
      } else {
        // Token is invalid, remove it
        localStorage.removeItem('jwt-token');
      }
    } catch (error) {
      localStorage.removeItem('jwt-token');
    } finally {
      setLoading(false);
    }
  };

  return { user, login, logout, loading };
}`;

  const protectedApiCode = `// pages/api/protected/profile.js
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  try {
    // 1. Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // 2. Verify and decode token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3. Get user data based on token
    const user = await getUserById(decoded.userId);
    if (!user) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    // 4. Return protected data
    res.status(200).json({
      message: 'Profile data retrieved successfully',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    
    console.error('Protected route error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
}

// Middleware function to protect routes
export function withAuth(handler) {
  return async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authentication required' });
      }

      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Add user data to request object
      req.user = decoded;
      
      // Call the original handler
      return handler(req, res);
      
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  };
}

// Usage example:
// export default withAuth(handler);`;

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

  const handleDemoLogin = async () => {
    if (!email || !password) {
      toast({
        title: "Error",
        description: "Please enter email and password",
        variant: "destructive"
      });
      return;
    }

    // Mock JWT creation for demo
    const mockPayload = {
      userId: '1',
      email: email,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
    };

    // Create a mock token (in real app, this would come from your API)
    const mockToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${btoa(JSON.stringify(mockPayload))}.mock-signature`;
    
    setToken(mockToken);
    toast({
      title: "Success!",
      description: "JWT token generated (demo mode)",
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">JWT Authentication</Badge>
          <h1 className="text-4xl font-bold mb-4">JSON Web Token Authentication</h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Learn how to implement stateless authentication using JWT tokens in Next.js applications.
          </p>
        </div>

        {/* JWT Overview */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5 text-primary" />
              What are JWT Tokens?
            </CardTitle>
            <CardDescription>
              JSON Web Tokens are a compact, URL-safe means of representing claims securely between two parties.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              <div className="text-center">
                <div className="w-12 h-12 bg-red-100 text-red-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Shield className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Header</h4>
                <p className="text-sm text-muted-foreground">Contains token type and signing algorithm</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Database className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Payload</h4>
                <p className="text-sm text-muted-foreground">Contains user data and claims</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-green-100 text-green-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Lock className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Signature</h4>
                <p className="text-sm text-muted-foreground">Ensures token hasn't been tampered with</p>
              </div>
            </div>
            
            <CodeBlock
              code={jwtBasics}
              language="javascript"
              title="JWT Structure Explained"
              description="Understanding the three parts of a JWT token"
            />
          </CardContent>
        </Card>

        {/* Interactive Demo */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Play className="h-5 w-5 text-green-500" />
              Interactive JWT Demo
            </CardTitle>
            <CardDescription>
              Try the authentication flow to see how JWT tokens work
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
                  <Key className="mr-2 h-4 w-4" />
                  Generate JWT Token
                </Button>
              </div>
              
              <div className="space-y-4">
                <Label>Generated JWT Token:</Label>
                <div className="p-3 bg-muted rounded-lg min-h-24 text-sm font-mono break-all">
                  {token || 'Token will appear here after login...'}
                </div>
                {token && (
                  <Alert>
                    <CheckCircle className="h-4 w-4" />
                    <AlertDescription>
                      Token generated successfully! In a real application, this would be securely stored and used for API requests.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Implementation Tabs */}
        <Tabs defaultValue="login" className="mb-8">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="login">Login API</TabsTrigger>
            <TabsTrigger value="client">Client Side</TabsTrigger>
            <TabsTrigger value="protected">Protected Routes</TabsTrigger>
            <TabsTrigger value="middleware">Middleware</TabsTrigger>
          </TabsList>
          
          <TabsContent value="login">
            <Card>
              <CardHeader>
                <CardTitle>Login API Implementation</CardTitle>
                <CardDescription>
                  Server-side authentication endpoint that validates credentials and returns a JWT token
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={loginApiCode}
                  language="javascript"
                  filename="pages/api/auth/login.js"
                  description="Complete login API route with error handling and security best practices"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="client">
            <Card>
              <CardHeader>
                <CardTitle>Client-Side Implementation</CardTitle>
                <CardDescription>
                  React hook for managing authentication state and JWT tokens
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={clientSideCode}
                  language="javascript"
                  filename="hooks/useAuth.js"
                  description="Custom React hook that handles login, logout, and token management"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="protected">
            <Card>
              <CardHeader>
                <CardTitle>Protected API Routes</CardTitle>
                <CardDescription>
                  How to verify JWT tokens and protect API endpoints
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={protectedApiCode}
                  language="javascript"
                  filename="pages/api/protected/profile.js"
                  description="Example of a protected API route with JWT verification and middleware pattern"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="middleware">
            <Card>
              <CardHeader>
                <CardTitle>Next.js Middleware</CardTitle>
                <CardDescription>
                  Protect pages at the edge using Next.js middleware
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={middlewareCode}
                  language="javascript"
                  filename="middleware.js"
                  description="Edge middleware that runs before pages are rendered to check authentication"
                />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Security Considerations */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
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
                    Use strong, random JWT secrets
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Set appropriate expiration times
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Store tokens securely (httpOnly cookies)
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Validate tokens on every request
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use HTTPS in production
                  </li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h4 className="font-semibold text-red-600">❌ Don't:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Store sensitive data in JWT payload
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Use weak or default secrets
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Store tokens in localStorage (XSS risk)
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Ignore token expiration
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Trust client-side token validation only
                  </li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Quiz/Practice */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code2 className="h-5 w-5 text-blue-500" />
              Practice Exercise
            </CardTitle>
            <CardDescription>
              Test your understanding of JWT authentication
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Challenge: Implement Token Refresh</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Modify the login API to return both an access token (15 minutes) and a refresh token (7 days). 
                  Implement automatic token refresh when the access token expires.
                </p>
                <Button variant="outline">
                  <Clock className="mr-2 h-4 w-4" />
                  View Solution
                </Button>
              </div>
              
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Quiz: JWT Security</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Test your knowledge of JWT security best practices and common vulnerabilities.
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