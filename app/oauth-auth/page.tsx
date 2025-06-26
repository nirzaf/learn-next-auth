'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Users, 
  Shield, 
  Key, 
  CheckCircle, 
  AlertTriangle,
  Play,
  Code2,
  ExternalLink,
  Github,
  Chrome,
  Facebook
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import { useToast } from '@/hooks/use-toast';

export default function OAuthAuth() {
  const [selectedProvider, setSelectedProvider] = useState('google');
  const { toast } = useToast();

  const oauthBasics = `// What is OAuth 2.0?
// OAuth 2.0 is an authorization framework that enables applications to obtain
// limited access to user accounts on an HTTP service. It works by delegating
// user authentication to the service that hosts the user account.

// OAuth Flow (Authorization Code Flow):
// 1. User clicks "Login with Google"
// 2. App redirects user to Google's authorization server
// 3. User authenticates with Google and grants permissions
// 4. Google redirects back to app with authorization code
// 5. App exchanges code for access token (server-to-server)
// 6. App uses access token to fetch user information
// 7. App creates local session/account for the user

// Key Benefits:
// - Users don't share passwords with your app
// - Leverages existing user accounts (Google, GitHub, etc.)
// - Reduced friction in sign-up process
// - Built-in security from OAuth providers`;

  const nextAuthSetup = `// Installation and basic setup
npm install next-auth

// pages/api/auth/[...nextauth].js
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
      // Persist the OAuth access_token and or the user id to the token right after signin
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
    async signIn({ user, account, profile, email, credentials }) {
      // You can add custom logic here
      // Return true to allow sign in, false to deny
      return true
    }
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  }
})`;

  const googleSetupCode = `// Setting up Google OAuth

// 1. Go to Google Cloud Console (console.cloud.google.com)
// 2. Create a new project or select existing one
// 3. Enable Google+ API
// 4. Go to Credentials → Create Credentials → OAuth 2.0 Client IDs
// 5. Set authorized redirect URIs:
//    - http://localhost:3000/api/auth/callback/google (development)
//    - https://yourdomain.com/api/auth/callback/google (production)

// .env.local
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your_nextauth_secret_here

// components/GoogleSignIn.jsx
import { signIn, signOut, useSession } from 'next-auth/react'

export default function GoogleSignIn() {
  const { data: session, status } = useSession()

  if (status === "loading") return <p>Loading...</p>

  if (session) {
    return (
      <div className="text-center">
        <img 
          src={session.user.image} 
          alt="Profile" 
          className="w-16 h-16 rounded-full mx-auto mb-4"
        />
        <p className="mb-2">Signed in as {session.user.email}</p>
        <button 
          onClick={() => signOut()}
          className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
        >
          Sign out
        </button>
      </div>
    )
  }

  return (
    <div className="text-center">
      <button 
        onClick={() => signIn('google')}
        className="bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 flex items-center gap-2 mx-auto"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24">
          {/* Google icon SVG path */}
        </svg>
        Sign in with Google
      </button>
    </div>
  )
}`;

  const githubSetupCode = `// Setting up GitHub OAuth

// 1. Go to GitHub Settings → Developer settings → OAuth Apps
// 2. Click "New OAuth App"
// 3. Fill in application details:
//    - Application name: Your App Name
//    - Homepage URL: http://localhost:3000 (or your domain)
//    - Authorization callback URL: http://localhost:3000/api/auth/callback/github
// 4. Copy Client ID and generate Client Secret

// .env.local (add to existing file)
GITHUB_ID=your_github_client_id
GITHUB_SECRET=your_github_client_secret

// components/GitHubSignIn.jsx
import { signIn, signOut, useSession } from 'next-auth/react'
import { Github } from 'lucide-react'

export default function GitHubSignIn() {
  const { data: session } = useSession()

  if (session) {
    return (
      <div className="border rounded-lg p-4">
        <div className="flex items-center gap-3 mb-3">
          <img 
            src={session.user.image} 
            alt="Avatar" 
            className="w-10 h-10 rounded-full"
          />
          <div>
            <p className="font-semibold">{session.user.name}</p>
            <p className="text-sm text-gray-600">{session.user.email}</p>
          </div>
        </div>
        <button 
          onClick={() => signOut()}
          className="w-full bg-gray-800 text-white py-2 rounded hover:bg-gray-900"
        >
          Sign out
        </button>
      </div>
    )
  }

  return (
    <button 
      onClick={() => signIn('github')}
      className="w-full bg-gray-800 text-white py-3 px-4 rounded-lg hover:bg-gray-900 flex items-center justify-center gap-2"
    >
      <Github className="w-5 h-5" />
      Continue with GitHub
    </button>
  )
}`;

  const customProviderCode = `// Creating a custom OAuth provider
// pages/api/auth/[...nextauth].js

import NextAuth from 'next-auth'

export default NextAuth({
  providers: [
    {
      id: "university-sso",
      name: "University SSO",
      type: "oauth",
      authorization: {
        url: "https://sso.university.edu/oauth/authorize",
        params: {
          scope: "openid email profile",
          grant_type: "authorization_code",
        }
      },
      token: "https://sso.university.edu/oauth/token",
      userinfo: "https://sso.university.edu/oauth/userinfo",
      clientId: process.env.UNIVERSITY_CLIENT_ID,
      clientSecret: process.env.UNIVERSITY_CLIENT_SECRET,
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          image: profile.picture,
          // Map custom fields
          studentId: profile.student_id,
          department: profile.department
        }
      },
    }
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      if (account && profile) {
        token.studentId = profile.student_id
        token.department = profile.department
      }
      return token
    },
    async session({ session, token }) {
      session.user.studentId = token.studentId
      session.user.department = token.department
      return session
    }
  }
})`;

  const protectedPageCode = `// pages/dashboard.js - Protected page with OAuth
import { useSession, getSession } from 'next-auth/react'
import { useRouter } from 'next/router'
import { useEffect } from 'react'

export default function Dashboard() {
  const { data: session, status } = useSession()
  const router = useRouter()

  useEffect(() => {
    if (status === 'loading') return // Still loading

    if (!session) {
      router.push('/auth/signin')
      return
    }
  }, [session, status, router])

  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  if (!session) {
    return null // Will redirect
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <div className="flex items-center gap-4 mb-4">
            <img 
              src={session.user.image} 
              alt="Profile" 
              className="w-16 h-16 rounded-full"
            />
            <div>
              <h1 className="text-2xl font-bold">Welcome, {session.user.name}!</h1>
              <p className="text-gray-600">Signed in via {session.provider}</p>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-50 p-4 rounded">
              <h3 className="font-semibold mb-2">Account Information</h3>
              <p><strong>Email:</strong> {session.user.email}</p>
              <p><strong>Provider:</strong> {session.provider}</p>
              {session.user.studentId && (
                <p><strong>Student ID:</strong> {session.user.studentId}</p>
              )}
            </div>
            
            <div className="bg-blue-50 p-4 rounded">
              <h3 className="font-semibold mb-2 text-blue-800">OAuth Benefits</h3>
              <ul className="text-sm text-blue-700 space-y-1">
                <li>• No password management</li>
                <li>• Trusted authentication</li>
                <li>• Quick sign-up process</li>
                <li>• Automatic profile sync</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// Server-side protection alternative
export async function getServerSideProps(context) {
  const session = await getSession(context)

  if (!session) {
    return {
      redirect: {
        destination: '/auth/signin',
        permanent: false,
      },
    }
  }

  return {
    props: { session },
  }
}`;

  const handleDemoOAuth = (provider: string) => {
    toast({
      title: "OAuth Demo",
      description: `In a real app, this would redirect to ${provider} for authentication`,
    });
  };

  const providers = [
    {
      id: 'google',
      name: 'Google',
      icon: Chrome,
      color: 'bg-red-500 hover:bg-red-600',
      description: 'Most popular OAuth provider with billions of users'
    },
    {
      id: 'github',
      name: 'GitHub',
      icon: Github,
      color: 'bg-gray-800 hover:bg-gray-900',
      description: 'Perfect for developer-focused applications'
    },
    {
      id: 'facebook',
      name: 'Facebook',
      icon: Facebook,
      color: 'bg-blue-600 hover:bg-blue-700',
      description: 'Social authentication with extensive user base'
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">OAuth Authentication</Badge>
          <h1 className="text-4xl font-bold mb-4">OAuth 2.0 Integration</h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Learn how to implement third-party authentication using OAuth providers like Google, GitHub, and Facebook in Next.js applications.
          </p>
        </div>

        {/* OAuth Overview */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              Understanding OAuth 2.0
            </CardTitle>
            <CardDescription>
              The authorization framework that powers modern social login
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
              <div className="text-center">
                <div className="w-12 h-12 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Users className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">User Consent</h4>
                <p className="text-sm text-muted-foreground">User authorizes your app</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-green-100 text-green-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Key className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Authorization Code</h4>
                <p className="text-sm text-muted-foreground">Provider returns auth code</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-purple-100 text-purple-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <ExternalLink className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">Token Exchange</h4>
                <p className="text-sm text-muted-foreground">Code exchanged for tokens</p>
              </div>
              <div className="text-center">
                <div className="w-12 h-12 bg-orange-100 text-orange-600 rounded-lg flex items-center justify-center mx-auto mb-3">
                  <Shield className="h-6 w-6" />
                </div>
                <h4 className="font-semibold mb-2">User Data</h4>
                <p className="text-sm text-muted-foreground">Access user information</p>
              </div>
            </div>
            
            <CodeBlock
              code={oauthBasics}
              language="javascript"
              title="OAuth 2.0 Flow Explained"
              description="Understanding the authorization code flow used by most OAuth providers"
            />
          </CardContent>
        </Card>

        {/* Interactive Demo */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Play className="h-5 w-5 text-green-500" />
              OAuth Provider Demo
            </CardTitle>
            <CardDescription>
              Try different OAuth providers (demo mode)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {providers.map((provider) => (
                <div key={provider.id} className="text-center">
                  <Button
                    onClick={() => handleDemoOAuth(provider.name)}
                    className={`w-full ${provider.color} text-white mb-3`}
                  >
                    <provider.icon className="mr-2 h-5 w-5" />
                    Sign in with {provider.name}
                  </Button>
                  <p className="text-sm text-muted-foreground">
                    {provider.description}
                  </p>
                </div>
              ))}
            </div>
            
            <Alert className="mt-6">
              <CheckCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Demo Mode:</strong> In a real application, these buttons would redirect to the respective OAuth providers for authentication.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>

        {/* Implementation Tabs */}
        <Tabs value={selectedProvider} onValueChange={setSelectedProvider} className="mb-8">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="setup">NextAuth Setup</TabsTrigger>
            <TabsTrigger value="google">Google OAuth</TabsTrigger>
            <TabsTrigger value="github">GitHub OAuth</TabsTrigger>
            <TabsTrigger value="custom">Custom Provider</TabsTrigger>
            <TabsTrigger value="protected">Protected Pages</TabsTrigger>
          </TabsList>
          
          <TabsContent value="setup">
            <Card>
              <CardHeader>
                <CardTitle>NextAuth.js Setup</CardTitle>
                <CardDescription>
                  Configure NextAuth.js for OAuth authentication
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={nextAuthSetup}
                  language="javascript"
                  filename="pages/api/auth/[...nextauth].js"
                  description="Complete NextAuth.js configuration with multiple OAuth providers"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="google">
            <Card>
              <CardHeader>
                <CardTitle>Google OAuth Integration</CardTitle>
                <CardDescription>
                  Step-by-step Google OAuth setup and implementation
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={googleSetupCode}
                  language="javascript"
                  filename="components/GoogleSignIn.jsx"
                  description="Complete Google OAuth setup including Google Cloud Console configuration"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="github">
            <Card>
              <CardHeader>
                <CardTitle>GitHub OAuth Integration</CardTitle>
                <CardDescription>
                  Implement GitHub authentication for developer-focused apps
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={githubSetupCode}
                  language="javascript"
                  filename="components/GitHubSignIn.jsx"
                  description="GitHub OAuth setup with GitHub Developer Settings configuration"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="custom">
            <Card>
              <CardHeader>
                <CardTitle>Custom OAuth Provider</CardTitle>
                <CardDescription>
                  Create custom OAuth providers for enterprise or university SSO
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={customProviderCode}
                  language="javascript"
                  filename="pages/api/auth/[...nextauth].js"
                  description="Custom OAuth provider configuration for university or enterprise SSO systems"
                />
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="protected">
            <Card>
              <CardHeader>
                <CardTitle>Protected Pages with OAuth</CardTitle>
                <CardDescription>
                  Implement route protection using OAuth session data
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CodeBlock
                  code={protectedPageCode}
                  language="javascript"
                  filename="pages/dashboard.js"
                  description="Protected page implementation with OAuth session management and user data display"
                />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* OAuth Security */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-red-500" />
              OAuth Security Considerations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-semibold text-green-600">✅ Security Best Practices:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use HTTPS for all OAuth redirects
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Validate redirect URIs strictly
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Use state parameter to prevent CSRF
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Store client secrets securely
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                    Implement proper scope validation
                  </li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h4 className="font-semibold text-red-600">❌ Common Vulnerabilities:</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Open redirect vulnerabilities
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    CSRF attacks on OAuth flow
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Authorization code interception
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Insufficient scope validation
                  </li>
                  <li className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    Client secret exposure
                  </li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* OAuth vs Other Methods */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>When to Use OAuth</CardTitle>
            <CardDescription>
              Comparing OAuth with other authentication methods
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-green-600 mb-3">✅ Use OAuth When:</h4>
                <ul className="text-sm space-y-2">
                  <li>• Building consumer applications</li>
                  <li>• Want to reduce sign-up friction</li>
                  <li>• Need social features integration</li>
                  <li>• Users already have provider accounts</li>
                  <li>• Want to leverage provider security</li>
                </ul>
              </div>
              
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-amber-600 mb-3">⚠️ Consider Alternatives When:</h4>
                <ul className="text-sm space-y-2">
                  <li>• Building enterprise applications</li>
                  <li>• Need complete user data control</li>
                  <li>• Have strict compliance requirements</li>
                  <li>• Target users without provider accounts</li>
                  <li>• Need offline access to user data</li>
                </ul>
              </div>
              
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-blue-600 mb-3">💡 Hybrid Approach:</h4>
                <ul className="text-sm space-y-2">
                  <li>• Offer both OAuth and email/password</li>
                  <li>• Allow account linking</li>
                  <li>• Progressive user data collection</li>
                  <li>• Fallback authentication methods</li>
                  <li>• Provider-specific features</li>
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
              Test your understanding of OAuth implementation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Challenge: Multi-Provider OAuth</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Implement a login page that supports Google, GitHub, and a custom university SSO provider. 
                  Include account linking functionality and proper error handling.
                </p>
                <Button variant="outline">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  View Solution
                </Button>
              </div>
              
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold mb-2">Quiz: OAuth Security</h4>
                <p className="text-sm text-muted-foreground mb-4">
                  Test your knowledge of OAuth security vulnerabilities and best practices.
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