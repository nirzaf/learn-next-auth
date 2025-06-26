'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { useAuth } from '@/contexts/auth-context';
import { LogIn, Mail, Lock, User, AlertCircle } from 'lucide-react';
import Link from 'next/link';

export default function Login() {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    name: '',
    email: 'student@university.edu',
    password: 'password123'
  });
  const [error, setError] = useState('');
  const { login, register, loading } = useAuth();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      let success;
      if (isLogin) {
        success = await login(formData.email, formData.password);
      } else {
        success = await register(formData.name, formData.email, formData.password);
      }

      if (success) {
        router.push('/');
      } else {
        setError(isLogin ? 'Invalid credentials' : 'Registration failed');
      }
    } catch (err) {
      setError('An error occurred. Please try again.');
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <Card>
          <CardHeader className="text-center">
            <div className="w-12 h-12 bg-primary text-primary-foreground rounded-lg flex items-center justify-center mx-auto mb-4">
              <LogIn className="h-6 w-6" />
            </div>
            <CardTitle className="text-2xl">
              {isLogin ? 'Sign In' : 'Create Account'}
            </CardTitle>
            <CardDescription>
              {isLogin 
                ? 'Enter your credentials to access the learning platform'
                : 'Join the Next.js authentication learning platform'
              }
            </CardDescription>
          </CardHeader>
          
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {!isLogin && (
                <div className="space-y-2">
                  <Label htmlFor="name">Full Name</Label>
                  <div className="relative">
                    <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="name"
                      name="name"
                      type="text"
                      placeholder="Enter your full name"
                      value={formData.name}
                      onChange={handleInputChange}
                      className="pl-10"
                      required={!isLogin}
                    />
                  </div>
                </div>
              )}
              
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="Enter your email"
                    value={formData.email}
                    onChange={handleInputChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Enter your password"
                    value={formData.password}
                    onChange={handleInputChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
              </Button>
            </form>

            <div className="mt-6">
              <Separator className="my-4" />
              
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  {isLogin ? "Don't have an account?" : 'Already have an account?'}
                </p>
                <Button
                  variant="link"
                  onClick={() => setIsLogin(!isLogin)}
                  className="p-0 h-auto font-normal"
                >
                  {isLogin ? 'Create one here' : 'Sign in instead'}
                </Button>
              </div>
            </div>

            {/* Demo Credentials */}
            <Alert className="mt-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Demo Credentials:</strong><br />
                Email: student@university.edu<br />
                Password: password123
              </AlertDescription>
            </Alert>

            <div className="mt-6 text-center">
              <Link href="/" className="text-sm text-muted-foreground hover:text-primary">
                ← Back to Home
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}