'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Code2, 
  Play, 
  Download,
  GitBranch,
  Clock,
  Star,
  Key,
  Shield,
  Users,
  Lock,
  Database,
  Smartphone
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import Link from 'next/link';

export default function Examples() {
  const examples = [
    {
      title: 'Simple JWT Login',
      description: 'Basic JWT authentication with login and protected routes',
      category: 'JWT',
      difficulty: 'Beginner',
      duration: '15 min',
      rating: 4.9,
      icon: Key,
      link: '/jwt-auth',
      tags: ['JWT', 'Login', 'API Routes']
    },
    {
      title: 'Session-Based Auth',
      description: 'Traditional server-side session management',
      category: 'Sessions',
      difficulty: 'Beginner',
      duration: '20 min',
      rating: 4.7,
      icon: Lock,
      link: '/session-auth',
      tags: ['Sessions', 'Cookies', 'Server-side']
    },
    {
      title: 'OAuth with Google',
      description: 'Third-party authentication using Google OAuth',
      category: 'OAuth',
      difficulty: 'Intermediate',
      duration: '30 min',
      rating: 4.8,
      icon: Users,
      link: '/oauth-auth',
      tags: ['OAuth', 'Google', 'Third-party']
    },
    {
      title: 'Protected Routes',
      description: 'Route guards and middleware implementation',
      category: 'Security',
      difficulty: 'Intermediate',
      duration: '25 min',
      rating: 4.6,
      icon: Shield,
      link: '/protected-routes',
      tags: ['Middleware', 'Guards', 'Security']
    },
    {
      title: 'Role-Based Access',
      description: 'User roles and permission-based authorization',
      category: 'Authorization',
      difficulty: 'Advanced',
      duration: '40 min',
      rating: 4.9,
      icon: Database,
      link: '#',
      tags: ['RBAC', 'Permissions', 'Authorization']
    },
    {
      title: 'Mobile App Auth',
      description: 'Authentication for React Native applications',
      category: 'Mobile',
      difficulty: 'Advanced',
      duration: '45 min',
      rating: 4.5,
      icon: Smartphone,
      link: '#',
      tags: ['React Native', 'Mobile', 'Cross-platform']
    }
  ];

  const quickStartCode = `// Quick Start - Basic Authentication Setup
npx create-next-app my-auth-app
cd my-auth-app
npm install jsonwebtoken bcryptjs

// Create your first API route
// pages/api/auth/login.js
export default async function handler(req, res) {
  // Your authentication logic here
}`;

  const projectStructure = `my-auth-app/
├── pages/
│   ├── api/
│   │   └── auth/
│   │       ├── login.js
│   │       ├── register.js
│   │       └── verify.js
│   ├── login.js
│   ├── dashboard.js
│   └── _app.js
├── components/
│   ├── AuthProvider.js
│   └── ProtectedRoute.js
├── hooks/
│   └── useAuth.js
├── middleware.js
└── .env.local`;

  const categories = ['All', 'JWT', 'Sessions', 'OAuth', 'Security', 'Authorization', 'Mobile'];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">Code Examples</Badge>
          <h1 className="text-4xl font-bold mb-4">Authentication Examples</h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Explore real-world authentication implementations with complete, runnable code examples.
          </p>
        </div>

        {/* Quick Start */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Play className="h-5 w-5 text-green-500" />
              Quick Start Guide
            </CardTitle>
            <CardDescription>
              Get up and running with authentication in Next.js in under 5 minutes
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="setup">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="setup">Project Setup</TabsTrigger>
                <TabsTrigger value="structure">File Structure</TabsTrigger>
              </TabsList>
              
              <TabsContent value="setup">
                <CodeBlock
                  code={quickStartCode}
                  language="bash"
                  title="Get Started in Minutes"
                  description="Basic setup commands to create your first authenticated Next.js app"
                />
              </TabsContent>
              
              <TabsContent value="structure">
                <CodeBlock
                  code={projectStructure}
                  language="text"
                  title="Recommended Project Structure"
                  description="Organize your authentication code for maintainability and scalability"
                />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Category Filter */}
        <div className="flex flex-wrap gap-2 mb-8 justify-center">
          {categories.map((category) => (
            <Button
              key={category}
              variant={category === 'All' ? 'default' : 'outline'}
              size="sm"
            >
              {category}
            </Button>
          ))}
        </div>

        {/* Examples Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
          {examples.map((example, index) => (
            <Card key={index} className="group hover:shadow-lg transition-all duration-300 border-2 hover:border-primary/20">
              <CardHeader>
                <div className="flex items-center justify-between mb-2">
                  <div className="w-10 h-10 bg-primary/10 text-primary rounded-lg flex items-center justify-center">
                    <example.icon className="h-5 w-5 group-hover:scale-110 transition-transform" />
                  </div>
                  <Badge variant={example.difficulty === 'Beginner' ? 'default' : example.difficulty === 'Intermediate' ? 'secondary' : 'destructive'}>
                    {example.difficulty}
                  </Badge>
                </div>
                <CardTitle className="text-lg">{example.title}</CardTitle>
                <CardDescription>{example.description}</CardDescription>
              </CardHeader>
              
              <CardContent>
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-1">
                    {example.tags.map((tag, i) => (
                      <Badge key={i} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                  
                  <div className="flex items-center justify-between text-sm text-muted-foreground">
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {example.duration}
                      </div>
                      <div className="flex items-center gap-1">
                        <Star className="h-3 w-3 fill-current text-yellow-500" />
                        {example.rating}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex gap-2">
                    <Button className="flex-1" asChild>
                      <Link href={example.link}>
                        <Code2 className="mr-2 h-4 w-4" />
                        View Tutorial
                      </Link>
                    </Button>
                    <Button variant="outline" size="sm">
                      <Download className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Community Examples */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitBranch className="h-5 w-5 text-blue-500" />
              Community Examples
            </CardTitle>
            <CardDescription>
              Real-world authentication implementations shared by the community
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 border rounded-lg">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 bg-gradient-to-br from-purple-400 to-purple-600 rounded-full flex items-center justify-center text-white text-sm font-bold">
                    JD
                  </div>
                  <div>
                    <h4 className="font-semibold">E-commerce Auth System</h4>
                    <p className="text-sm text-muted-foreground">By John Doe</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">
                  Complete authentication system with user profiles, order history, and admin panel.
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm">
                    <Code2 className="mr-1 h-3 w-3" />
                    View Code
                  </Button>
                  <Button variant="outline" size="sm">
                    <Play className="mr-1 h-3 w-3" />
                    Live Demo
                  </Button>
                </div>
              </div>
              
              <div className="p-4 border rounded-lg">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 bg-gradient-to-br from-green-400 to-green-600 rounded-full flex items-center justify-center text-white text-sm font-bold">
                    SM
                  </div>
                  <div>
                    <h4 className="font-semibold">Multi-tenant SaaS Auth</h4>
                    <p className="text-sm text-muted-foreground">By Sarah Miller</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">
                  Advanced authentication with organization management and team permissions.
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm">
                    <Code2 className="mr-1 h-3 w-3" />
                    View Code
                  </Button>
                  <Button variant="outline" size="sm">
                    <Play className="mr-1 h-3 w-3" />
                    Live Demo
                  </Button>
                </div>
              </div>
            </div>
            
            <div className="mt-6 text-center">
              <Button variant="outline">
                <GitBranch className="mr-2 h-4 w-4" />
                Submit Your Example
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Learning Resources */}
        <Card>
          <CardHeader>
            <CardTitle>Additional Learning Resources</CardTitle>
            <CardDescription>
              Enhance your authentication knowledge with these curated resources
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4">
                <div className="w-12 h-12 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Code2 className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Interactive Playground</h4>
                <p className="text-sm text-muted-foreground mb-3">
                  Test authentication concepts in a safe environment
                </p>
                <Button variant="outline" size="sm">
                  Try Playground
                </Button>
              </div>
              
              <div className="text-center p-4">
                <div className="w-12 h-12 bg-green-100 text-green-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Shield className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Security Checklist</h4>
                <p className="text-sm text-muted-foreground mb-3">
                  Ensure your authentication is production-ready
                </p>
                <Button variant="outline" size="sm">
                  View Checklist
                </Button>
              </div>
              
              <div className="text-center p-4">
                <div className="w-12 h-12 bg-purple-100 text-purple-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Star className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Best Practices Guide</h4>
                <p className="text-sm text-muted-foreground mb-3">
                  Learn industry-standard authentication patterns
                </p>
                <Button variant="outline" size="sm">
                  Read Guide
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}