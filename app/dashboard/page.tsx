'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  BookOpen, 
  Code2, 
  Trophy, 
  Clock, 
  CheckCircle, 
  Star,
  Target,
  Calendar,
  TrendingUp,
  Award,
  Play,
  Lock,
  Unlock
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { useAuth } from '@/contexts/auth-context';
import { useProgress } from '@/contexts/progress-context';
import Link from 'next/link';

export default function Dashboard() {
  const { user } = useAuth();
  const { progress, achievements, getModuleProgress, getTotalProgress } = useProgress();
  const [currentStreak, setCurrentStreak] = useState(7);
  const [totalHours, setTotalHours] = useState(12.5);

  const modules = [
    {
      id: 'getting-started',
      title: 'Authentication Fundamentals',
      description: 'Core concepts and terminology',
      icon: BookOpen,
      difficulty: 'Beginner',
      estimatedTime: '30 min',
      link: '/getting-started',
      prerequisite: null
    },
    {
      id: 'jwt-auth',
      title: 'JWT Authentication',
      description: 'Stateless authentication with JSON Web Tokens',
      icon: Code2,
      difficulty: 'Beginner',
      estimatedTime: '45 min',
      link: '/jwt-auth',
      prerequisite: 'getting-started'
    },
    {
      id: 'session-auth',
      title: 'Session-Based Authentication',
      description: 'Traditional server-side session management',
      icon: Lock,
      difficulty: 'Beginner',
      estimatedTime: '40 min',
      link: '/session-auth',
      prerequisite: 'getting-started'
    },
    {
      id: 'oauth-auth',
      title: 'OAuth Integration',
      description: 'Third-party authentication providers',
      icon: Star,
      difficulty: 'Intermediate',
      estimatedTime: '60 min',
      link: '/oauth-auth',
      prerequisite: 'jwt-auth'
    },
    {
      id: 'protected-routes',
      title: 'Protected Routes & Middleware',
      description: 'Route guards and authorization',
      icon: Trophy,
      difficulty: 'Intermediate',
      estimatedTime: '50 min',
      link: '/protected-routes',
      prerequisite: 'jwt-auth'
    },
    {
      id: 'advanced-security',
      title: 'Advanced Security Patterns',
      description: 'Security best practices and vulnerabilities',
      icon: Target,
      difficulty: 'Advanced',
      estimatedTime: '90 min',
      link: '/advanced-security',
      prerequisite: 'protected-routes'
    }
  ];

  const recentActivity = [
    { action: 'Completed', module: 'JWT Authentication', time: '2 hours ago', points: 100 },
    { action: 'Started', module: 'Session Authentication', time: '1 day ago', points: 0 },
    { action: 'Completed', module: 'Getting Started', time: '2 days ago', points: 50 },
    { action: 'Achievement', module: 'First Login', time: '3 days ago', points: 25 }
  ];

  const isModuleUnlocked = (moduleId: string, prerequisite: string | null) => {
    if (!prerequisite) return true;
    return getModuleProgress(prerequisite) === 100;
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Beginner': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
      case 'Intermediate': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300';
      case 'Advanced': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300';
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
        <Navigation />
        <div className="container mx-auto px-4 py-8 text-center">
          <h1 className="text-2xl font-bold mb-4">Please log in to access your dashboard</h1>
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
        {/* Welcome Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Welcome back, {user.name}! 👋</h1>
          <p className="text-muted-foreground">Continue your Next.js authentication mastery journey</p>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Overall Progress</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{getTotalProgress()}%</div>
              <Progress value={getTotalProgress()} className="mt-2" />
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Current Streak</CardTitle>
              <Calendar className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{currentStreak} days</div>
              <p className="text-xs text-muted-foreground">Keep it up!</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Study Time</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{totalHours}h</div>
              <p className="text-xs text-muted-foreground">This month</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Achievements</CardTitle>
              <Award className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{achievements.length}</div>
              <p className="text-xs text-muted-foreground">Unlocked</p>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="modules" className="space-y-6">
          <TabsList>
            <TabsTrigger value="modules">Learning Modules</TabsTrigger>
            <TabsTrigger value="activity">Recent Activity</TabsTrigger>
            <TabsTrigger value="achievements">Achievements</TabsTrigger>
          </TabsList>
          
          <TabsContent value="modules">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {modules.map((module) => {
                const moduleProgress = getModuleProgress(module.id);
                const isUnlocked = isModuleUnlocked(module.id, module.prerequisite);
                
                return (
                  <Card key={module.id} className={`group transition-all duration-300 ${
                    isUnlocked ? 'hover:shadow-lg border-2 hover:border-primary/20' : 'opacity-60'
                  }`}>
                    <CardHeader>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <module.icon className={`h-6 w-6 ${isUnlocked ? 'text-primary' : 'text-muted-foreground'}`} />
                          {isUnlocked ? (
                            <Unlock className="h-4 w-4 text-green-500" />
                          ) : (
                            <Lock className="h-4 w-4 text-muted-foreground" />
                          )}
                        </div>
                        <Badge className={getDifficultyColor(module.difficulty)}>
                          {module.difficulty}
                        </Badge>
                      </div>
                      <CardTitle className="text-lg">{module.title}</CardTitle>
                      <CardDescription>{module.description}</CardDescription>
                    </CardHeader>
                    
                    <CardContent>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between text-sm text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {module.estimatedTime}
                          </div>
                          <div className="flex items-center gap-1">
                            <CheckCircle className="h-3 w-3" />
                            {moduleProgress}%
                          </div>
                        </div>
                        
                        <Progress value={moduleProgress} />
                        
                        {module.prerequisite && !isModuleUnlocked(module.id, module.prerequisite) && (
                          <p className="text-xs text-muted-foreground">
                            Complete "{modules.find(m => m.id === module.prerequisite)?.title}" to unlock
                          </p>
                        )}
                        
                        <Button 
                          className="w-full" 
                          disabled={!isUnlocked}
                          asChild={isUnlocked}
                        >
                          {isUnlocked ? (
                            <Link href={module.link}>
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
                          ) : (
                            <>
                              <Lock className="mr-2 h-4 w-4" />
                              Locked
                            </>
                          )}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </TabsContent>
          
          <TabsContent value="activity">
            <Card>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>Your learning progress over the past week</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentActivity.map((activity, index) => (
                    <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 rounded-full ${
                          activity.action === 'Completed' ? 'bg-green-500' : 
                          activity.action === 'Started' ? 'bg-blue-500' : 'bg-yellow-500'
                        }`} />
                        <div>
                          <p className="font-medium">{activity.action} {activity.module}</p>
                          <p className="text-sm text-muted-foreground">{activity.time}</p>
                        </div>
                      </div>
                      {activity.points > 0 && (
                        <Badge variant="secondary">+{activity.points} XP</Badge>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="achievements">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {achievements.map((achievement) => (
                <Card key={achievement.id} className="text-center">
                  <CardHeader>
                    <div className="w-16 h-16 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center mx-auto mb-4">
                      <Trophy className="h-8 w-8 text-white" />
                    </div>
                    <CardTitle className="text-lg">{achievement.title}</CardTitle>
                    <CardDescription>{achievement.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Badge variant="secondary">+{achievement.points} XP</Badge>
                    <p className="text-xs text-muted-foreground mt-2">
                      Earned {new Date(achievement.unlockedAt).toLocaleDateString()}
                    </p>
                  </CardContent>
                </Card>
              ))}
              
              {/* Locked achievements */}
              <Card className="text-center opacity-60">
                <CardHeader>
                  <div className="w-16 h-16 bg-gray-200 dark:bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Lock className="h-8 w-8 text-gray-400" />
                  </div>
                  <CardTitle className="text-lg">Security Expert</CardTitle>
                  <CardDescription>Complete all advanced security modules</CardDescription>
                </CardHeader>
                <CardContent>
                  <Badge variant="outline">Locked</Badge>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}