'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { 
  BookOpen, 
  CheckCircle, 
  Clock, 
  AlertTriangle,
  Lightbulb,
  Target,
  Users,
  Shield,
  Key,
  Database
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import Link from 'next/link';

export default function GettingStarted() {
  const concepts = [
    {
      title: 'Authentication',
      description: 'Verifying the identity of a user (who are you?)',
      icon: Users,
      examples: ['Username/password login', 'Biometric verification', 'Multi-factor authentication']
    },
    {
      title: 'Authorization',
      description: 'Determining what an authenticated user can do (what can you do?)',
      icon: Shield,
      examples: ['Role-based access control', 'Permission systems', 'Resource-level permissions']
    },
    {
      title: 'Session Management',
      description: 'Maintaining user state across requests',
      icon: Key,
      examples: ['HTTP cookies', 'JWT tokens', 'Server-side sessions']
    },
    {
      title: 'Data Security',
      description: 'Protecting sensitive information',
      icon: Database,
      examples: ['Password hashing', 'Data encryption', 'Secure transmission']
    }
  ];

  const setupCode = `// package.json dependencies for authentication
{
  "dependencies": {
    "next": "^13.5.0",
    "react": "^18.2.0",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "next-auth": "^4.23.0"
  }
}`;

  const basicAuthFlow = `// Basic authentication flow in Next.js
// pages/api/auth/login.js
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { email, password } = req.body;

  // 1. Validate user credentials (check database)
  const user = await findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.hashedPassword)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // 2. Create JWT token
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  // 3. Send token to client
  res.status(200).json({
    message: 'Login successful',
    token,
    user: { id: user.id, email: user.email, name: user.name }
  });
}`;

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">Getting Started</Badge>
          <h1 className="text-4xl font-bold mb-4">Authentication Fundamentals</h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Learn the core concepts and terminology you need to understand before implementing authentication in Next.js.
          </p>
        </div>

        {/* Learning Objectives */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5 text-primary" />
              Learning Objectives
            </CardTitle>
            <CardDescription>
              By the end of this module, you will understand:
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-start gap-3">
                <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Core Authentication Concepts</h4>
                  <p className="text-sm text-muted-foreground">Authentication vs Authorization vs Session Management</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Next.js Authentication Features</h4>
                  <p className="text-sm text-muted-foreground">API routes, middleware, and SSR capabilities</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Security Best Practices</h4>
                  <p className="text-sm text-muted-foreground">Password hashing, token management, and secure storage</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Implementation Strategies</h4>
                  <p className="text-sm text-muted-foreground">When to use different authentication methods</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Core Concepts */}
        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6">Core Concepts</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {concepts.map((concept, index) => (
              <Card key={index} className="h-full">
                <CardHeader>
                  <div className="flex items-center gap-3 mb-2">
                    <concept.icon className="h-6 w-6 text-primary" />
                    <CardTitle className="text-lg">{concept.title}</CardTitle>
                  </div>
                  <CardDescription>{concept.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <h5 className="font-semibold mb-2 text-sm">Examples:</h5>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    {concept.examples.map((example, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <div className="w-1.5 h-1.5 bg-primary rounded-full" />
                        {example}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Why Next.js for Authentication */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lightbulb className="h-5 w-5 text-yellow-500" />
              Why Next.js for Authentication?
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <div className="w-6 h-6 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-sm font-bold">1</div>
                <div>
                  <h4 className="font-semibold">Full-Stack Capabilities</h4>
                  <p className="text-sm text-muted-foreground">API routes allow you to handle authentication logic server-side within the same codebase</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-6 h-6 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-sm font-bold">2</div>
                <div>
                  <h4 className="font-semibold">Server-Side Rendering (SSR)</h4>
                  <p className="text-sm text-muted-foreground">Check authentication status before rendering pages, improving security and user experience</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-6 h-6 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-sm font-bold">3</div>
                <div>
                  <h4 className="font-semibold">Middleware Support</h4>
                  <p className="text-sm text-muted-foreground">Protect routes and handle authentication logic at the edge</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-6 h-6 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-sm font-bold">4</div>
                <div>
                  <h4 className="font-semibold">Built-in Security Features</h4>
                  <p className="text-sm text-muted-foreground">CSRF protection, secure headers, and automatic HTTPS in production</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Project Setup */}
        <div className="mb-8">
          <h2 className="text-2xl font-bold mb-6">Project Setup</h2>
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Required Dependencies</CardTitle>
              <CardDescription>
                Common packages used for authentication in Next.js applications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock
                code={setupCode}
                language="json"
                filename="package.json"
                description="Essential dependencies for implementing authentication features"
              />
            </CardContent>
          </Card>
        </div>

        {/* Basic Authentication Flow */}
        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6">Basic Authentication Flow</h2>
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Login API Route Example</CardTitle>
              <CardDescription>
                A simple example showing the basic authentication flow in Next.js
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock
                code={basicAuthFlow}
                language="javascript"
                filename="pages/api/auth/login.js"
                description="This example shows the three key steps: validate credentials, create token, and send response"
              />
            </CardContent>
          </Card>

          <Card className="border-amber-200 bg-amber-50 dark:bg-amber-950/20 dark:border-amber-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-amber-800 dark:text-amber-400">
                <AlertTriangle className="h-5 w-5" />
                Important Security Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="text-amber-800 dark:text-amber-400">
              <ul className="space-y-2 text-sm">
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-amber-600 rounded-full mt-2" />
                  <span><strong>Never store plain text passwords</strong> - Always hash passwords using bcrypt or similar</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-amber-600 rounded-full mt-2" />
                  <span><strong>Use environment variables</strong> - Keep JWT secrets and API keys in .env files</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-amber-600 rounded-full mt-2" />
                  <span><strong>Validate all inputs</strong> - Never trust data from the client</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-amber-600 rounded-full mt-2" />
                  <span><strong>Use HTTPS</strong> - Always encrypt data in transit</span>
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Progress & Next Steps */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-500" />
              Ready for Implementation!
            </CardTitle>
            <CardDescription>
              You now understand the fundamentals. Let's start implementing!
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-6">
              <div className="flex justify-between text-sm mb-2">
                <span>Module Progress</span>
                <span>100%</span>
              </div>
              <Progress value={100} />
            </div>
            
            <div className="flex flex-col sm:flex-row gap-4">
              <Button className="flex-1" asChild>
                <Link href="/jwt-auth">
                  <BookOpen className="mr-2 h-4 w-4" />
                  Start with JWT Authentication
                </Link>
              </Button>
              <Button variant="outline" className="flex-1" asChild>
                <Link href="/examples">
                  <Clock className="mr-2 h-4 w-4" />
                  Browse All Examples
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}