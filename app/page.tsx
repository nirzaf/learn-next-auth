'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  BookOpen, 
  Code2, 
  Shield, 
  Users, 
  Key, 
  Lock,
  Play,
  CheckCircle,
  Clock,
  Star,
  Award,
  Zap,
  Target,
  Trophy,
  TrendingUp,
  Lightbulb,
  LogIn
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { useAuth } from '@/contexts/auth-context';
import { useProgress } from '@/contexts/progress-context';
import Link from 'next/link';

export default function Home() {
  const { user } = useAuth();
  const { getTotalProgress, getModuleProgress, achievements } = useProgress();

  const authMethods = [
    {
      title: 'Authentication Fundamentals',
      description: 'Core concepts, terminology, and Next.js features',
      icon: BookOpen,
      difficulty: 'Beginner',
      duration: '30 min',
      status: 'available',
      link: '/getting-started',
      moduleId: 'getting-started'
    },
    {
      title: 'JWT Authentication',
      description: 'Learn stateless authentication using JSON Web Tokens',
      icon: Key,
      difficulty: 'Beginner',
      duration: '45 min',
      status: 'available',
      link: '/jwt-auth',
      moduleId: 'jwt-auth'
    },
    {
      title: 'Session-Based Auth',
      description: 'Traditional server-side session management',
      icon: Lock,
      difficulty: 'Beginner',
      duration: '40 min',
      status: 'available',
      link: '/session-auth',
      moduleId: 'session-auth'
    },
    {
      title: 'OAuth Integration',
      description: 'Third-party authentication with Google, GitHub',
      icon: Users,
      difficulty: 'Intermediate',
      duration: '60 min',
      status: 'available',
      link: '/oauth-auth',
      moduleId: 'oauth-auth'
    },
    {
      title: 'Protected Routes',
      description: 'Implementing route guards and middleware',
      icon: Shield,
      difficulty: 'Intermediate',
      duration: '50 min',
      status: 'available',
      link: '/protected-routes',
      moduleId: 'protected-routes'
    },
    {
      title: 'Advanced Security',
      description: 'Security best practices and vulnerability prevention',
      icon: Target,
      difficulty: 'Advanced',
      duration: '90 min',
      status: 'available',
      link: '/advanced-security',
      moduleId: 'advanced-security'
    }
  ];

  const features = [
    {
      icon: BookOpen,
      title: 'Interactive Tutorials',
      description: 'Step-by-step guides with live code examples and detailed explanations'
    },
    {
      icon: Code2,
      title: 'Code Playground',
      description: 'Practice with real Next.js authentication code in an interactive environment'
    },
    {
      icon: Shield,
      title: 'Security Best Practices',
      description: 'Learn industry-standard security implementations and vulnerability prevention'
    },
    {
      icon: Award,
      title: 'Progress Tracking',
      description: 'Monitor your learning journey with achievements and detailed progress analytics'
    },
    {
      icon: Trophy,
      title: 'Achievement System',
      description: 'Unlock achievements as you master different authentication concepts'
    },
    {
      icon: TrendingUp,
      title: 'Skill Assessment',
      description: 'Test your knowledge with quizzes and practical coding challenges'
    }
  ];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Beginner': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
      case 'Intermediate': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300';
      case 'Advanced': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      <Navigation />
      
      <main className="container mx-auto px-4 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 bg-primary/10 text-primary px-4 py-2 rounded-full text-sm font-medium mb-6">
            <Zap className="h-4 w-4" />
            Next.js Authentication Mastery Platform
          </div>
          <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-primary to-blue-600 bg-clip-text text-transparent mb-6">
            Master Authentication
            <br />
            <span className="text-3xl md:text-5xl">in Next.js</span>
          </h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto mb-8">
            Complete learning platform for Next.js authentication. From basic concepts to advanced security patterns, 
            with interactive examples, progress tracking, and hands-on practice designed for university students and developers.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button size="lg" className="text-lg px-8" asChild>
              <Link href={user ? "/dashboard" : "/getting-started"}>
                <Play className="mr-2 h-5 w-5" />
                {user ? "Continue Learning" : "Start Learning"}
              </Link>
            </Button>
            <Button variant="outline" size="lg" className="text-lg px-8" asChild>
              <Link href="/playground">
                <Code2 className="mr-2 h-5 w-5" />
                Try Playground
              </Link>
            </Button>
          </div>
        </div>

        {/* User Progress Section */}
        {user && (
          <Card className="mb-12">
            <CardHeader>
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <CardTitle className="flex items-center gap-2">
                    <TrendingUp className="h-5 w-5 text-green-500" />
                    Your Learning Progress
                  </CardTitle>
                  <CardDescription>Continue your authentication mastery journey</CardDescription>
                </div>
                <div className="flex items-center gap-4">
                  <Badge variant="secondary" className="text-lg px-3 py-1">
                    {getTotalProgress()}% Complete
                  </Badge>
                  <Badge variant="outline" className="gap-1">
                    <Trophy className="h-3 w-3" />
                    {achievements.length} Achievements
                  </Badge>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Progress value={getTotalProgress()} className="mb-4" />
              <div className="flex justify-between text-sm text-muted-foreground">
                <span>{authMethods.filter(m => getModuleProgress(m.moduleId) === 100).length} of {authMethods.length} modules completed</span>
                <Button variant="link" className="p-0 h-auto" asChild>
                  <Link href="/dashboard">View Dashboard →</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Authentication Methods */}
        <div className="mb-12">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold mb-4">Complete Learning Path</h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Master Next.js authentication through our structured curriculum, from fundamentals to advanced security patterns.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {authMethods.map((method, index) => {
              const moduleProgress = user ? getModuleProgress(method.moduleId) : 0;
              
              return (
                <Card key={index} className="group hover:shadow-lg transition-all duration-300 border-2 hover:border-primary/20">
                  <CardHeader>
                    <div className="flex items-center justify-between mb-2">
                      <method.icon className="h-8 w-8 text-primary group-hover:scale-110 transition-transform" />
                      <Badge className={getDifficultyColor(method.difficulty)}>
                        {method.difficulty}
                      </Badge>
                    </div>
                    <CardTitle className="text-lg">{method.title}</CardTitle>
                    <CardDescription>{method.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <Clock className="h-4 w-4" />
                          {method.duration}
                        </div>
                        <div className="flex items-center gap-1">
                          <Star className="h-4 w-4 fill-current text-yellow-500" />
                          4.8
                        </div>
                      </div>
                      
                      {user && (
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span>Progress</span>
                            <span>{moduleProgress}%</span>
                          </div>
                          <Progress value={moduleProgress} />
                        </div>
                      )}
                      
                      <Button className="w-full" asChild>
                        <Link href={method.link}>
                          {moduleProgress > 0 ? (
                            <>
                              <Play className="mr-2 h-4 w-4" />
                              Continue
                            </>
                          ) : (
                            <>
                              <BookOpen className="mr-2 h-4 w-4" />
                              Start Module
                            </>
                          )}
                        </Link>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>

        {/* Features */}
        <div className="mb-12">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold mb-4">Why Choose This Platform?</h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Built specifically for comprehensive learning with modern teaching methodologies and real-world applications.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <Card key={index} className="text-center hover:shadow-md transition-shadow">
                <CardHeader>
                  <feature.icon className="h-12 w-12 mx-auto text-primary mb-4" />
                  <CardTitle className="text-xl">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Learning Path */}
        <Card className="mb-12">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl flex items-center justify-center gap-2">
              <Lightbulb className="h-6 w-6 text-yellow-500" />
              Recommended Learning Path
            </CardTitle>
            <CardDescription>
              Follow this structured approach to master Next.js authentication from beginner to expert level
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="beginner" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="beginner">Beginner Path</TabsTrigger>
                <TabsTrigger value="intermediate">Intermediate Path</TabsTrigger>
                <TabsTrigger value="advanced">Advanced Path</TabsTrigger>
              </TabsList>
              
              <TabsContent value="beginner" className="mt-6">
                <div className="space-y-4">
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center font-bold">1</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">Authentication Fundamentals</h4>
                      <p className="text-sm text-muted-foreground">Understanding basic concepts, terminology, and Next.js features</p>
                    </div>
                    <Badge variant="outline">30 min</Badge>
                  </div>
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center font-bold">2</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">JWT Implementation</h4>
                      <p className="text-sm text-muted-foreground">Build your first JWT authentication system</p>
                    </div>
                    <Badge variant="outline">45 min</Badge>
                  </div>
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-muted text-muted-foreground rounded-full flex items-center justify-center font-bold">3</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">Session Management</h4>
                      <p className="text-sm text-muted-foreground">Learn traditional session-based authentication</p>
                    </div>
                    <Badge variant="outline">40 min</Badge>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="intermediate" className="mt-6">
                <div className="space-y-4">
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center font-bold">1</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">OAuth Integration</h4>
                      <p className="text-sm text-muted-foreground">Implement third-party authentication providers</p>
                    </div>
                    <Badge variant="outline">60 min</Badge>
                  </div>
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center font-bold">2</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">Route Protection</h4>
                      <p className="text-sm text-muted-foreground">Secure your application with middleware and guards</p>
                    </div>
                    <Badge variant="outline">50 min</Badge>
                  </div>
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-muted text-muted-foreground rounded-full flex items-center justify-center font-bold">3</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">User Management</h4>
                      <p className="text-sm text-muted-foreground">Build comprehensive user management systems</p>
                    </div>
                    <Badge variant="outline">45 min</Badge>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="advanced" className="mt-6">
                <div className="space-y-4">
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center font-bold">1</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">Advanced Security Patterns</h4>
                      <p className="text-sm text-muted-foreground">Master CSRF, XSS prevention, and security headers</p>
                    </div>
                    <Badge variant="outline">90 min</Badge>
                  </div>
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center font-bold">2</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">Security Auditing</h4>
                      <p className="text-sm text-muted-foreground">Implement logging, monitoring, and vulnerability testing</p>
                    </div>
                    <Badge variant="outline">60 min</Badge>
                  </div>
                  <div className="flex items-center gap-4 p-4 border rounded-lg">
                    <div className="w-8 h-8 bg-muted text-muted-foreground rounded-full flex items-center justify-center font-bold">3</div>
                    <div className="flex-1">
                      <h4 className="font-semibold">Production Deployment</h4>
                      <p className="text-sm text-muted-foreground">Deploy secure authentication to production environments</p>
                    </div>
                    <Badge variant="outline">45 min</Badge>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Call to Action */}
        <Card className="text-center">
          <CardHeader>
            <CardTitle className="text-2xl">Ready to Become an Authentication Expert?</CardTitle>
            <CardDescription>
              Join thousands of developers who have mastered Next.js authentication through our comprehensive platform
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              {!user ? (
                <>
                  <Button size="lg" asChild>
                    <Link href="/login">
                      <LogIn className="mr-2 h-5 w-5" />
                      Get Started Free
                    </Link>
                  </Button>
                  <Button variant="outline" size="lg" asChild>
                    <Link href="/getting-started">
                      <BookOpen className="mr-2 h-5 w-5" />
                      Browse Content
                    </Link>
                  </Button>
                </>
              ) : (
                <>
                  <Button size="lg" asChild>
                    <Link href="/dashboard">
                      <Trophy className="mr-2 h-5 w-5" />
                      Continue Learning
                    </Link>
                  </Button>
                  <Button variant="outline" size="lg" asChild>
                    <Link href="/playground">
                      <Code2 className="mr-2 h-5 w-5" />
                      Practice Coding
                    </Link>
                  </Button>
                </>
              )}
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}