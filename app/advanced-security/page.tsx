'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  AlertTriangle, 
  Lock, 
  Eye,
  Bug,
  Zap,
  CheckCircle,
  XCircle,
  Code2,
  Target,
  Skull
} from 'lucide-react';
import { Navigation } from '@/components/navigation';
import { CodeBlock } from '@/components/code-block';
import { useAuth } from '@/contexts/auth-context';
import { useProgress } from '@/contexts/progress-context';

interface VulnerabilityTestResult {
  passed: number;
  failed: number;
  issues: string[];
}

type VulnerabilityTestType = 'csrf' | 'xss' | 'injection';

interface VulnerabilityTest {
  type: VulnerabilityTestType;
  running: boolean;
  results?: VulnerabilityTestResult;
}

export default function AdvancedSecurity() {
  const { user } = useAuth();
  const { updateModuleProgress } = useProgress();
  const [completedSections, setCompletedSections] = useState(new Set());
  const [vulnerabilityTest, setVulnerabilityTest] = useState<VulnerabilityTest | null>(null);

  const securityTopics = [
    {
      id: 'csrf',
      title: 'CSRF Protection',
      description: 'Cross-Site Request Forgery prevention',
      severity: 'High',
      icon: Shield
    },
    {
      id: 'xss',
      title: 'XSS Prevention',
      description: 'Cross-Site Scripting attack mitigation',
      severity: 'Critical',
      icon: Bug
    },
    {
      id: 'injection',
      title: 'Injection Attacks',
      description: 'SQL injection and NoSQL injection prevention',
      severity: 'Critical',
      icon: Skull
    },
    {
      id: 'rate-limiting',
      title: 'Rate Limiting',
      description: 'Preventing brute force and DoS attacks',
      severity: 'Medium',
      icon: Zap
    },
    {
      id: 'secure-headers',
      title: 'Security Headers',
      description: 'HTTP security headers implementation',
      severity: 'Medium',
      icon: Lock
    },
    {
      id: 'audit-logging',
      title: 'Security Auditing',
      description: 'Logging and monitoring security events',
      severity: 'High',
      icon: Eye
    }
  ];

  const csrfProtectionCode = `// lib/csrf.js
import { randomBytes } from 'crypto';

export function generateCSRFToken() {
  return randomBytes(32).toString('hex');
}

export function validateCSRFToken(token, sessionToken) {
  return token === sessionToken;
}

// middleware.js
import { NextResponse } from 'next/server';
import { getSession } from '@/lib/session';

export async function middleware(request) {
  // CSRF protection for state-changing operations
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
    const session = await getSession(request);
    const csrfToken = request.headers.get('x-csrf-token');
    
    if (!session || !csrfToken || csrfToken !== session.csrfToken) {
      return new NextResponse('CSRF token mismatch', { status: 403 });
    }
  }
  
  return NextResponse.next();
}

// pages/api/auth/csrf.js
export default function handler(req, res) {
  if (req.method === 'GET') {
    const token = generateCSRFToken();
    
    // Store in session
    req.session.csrfToken = token;
    
    res.status(200).json({ csrfToken: token });
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

// Client-side usage
const getCsrfToken = async () => {
  const response = await fetch('/api/auth/csrf');
  const { csrfToken } = await response.json();
  return csrfToken;
};

const makeSecureRequest = async (url, data) => {
  const csrfToken = await getCsrfToken();
  
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(data)
  });
};`;

  const xssPreventionCode = `// lib/sanitize.js
import DOMPurify from 'isomorphic-dompurify';

export function sanitizeHTML(dirty) {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href']
  });
}

export function escapeHTML(unsafe) {
  return unsafe
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, """)
    .replace(/'/g, "&#039;");
}

// Input validation middleware
export function validateInput(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        message: 'Invalid input',
        details: error.details.map(d => d.message)
      });
    }
    
    req.body = value;
    next();
  };
}

// Content Security Policy
export function setCSPHeaders(res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self';"
  );
}

// React component with XSS protection
function UserComment({ comment }) {
  // Safe rendering of user content
  return (
    <div 
      dangerouslySetInnerHTML={{
        __html: sanitizeHTML(comment.content)
      }}
    />
  );
}

// Safe URL validation
export function isValidURL(url) {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}`;

  const injectionPreventionCode = `// lib/database.js - SQL Injection Prevention
import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ❌ VULNERABLE - Never do this
export async function getUserByIdVulnerable(userId) {
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
  const result = await pool.query(query);
  return result.rows[0];
}

// ✅ SECURE - Use parameterized queries
export async function getUserById(userId) {
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await pool.query(query, [userId]);
  return result.rows[0];
}

// ✅ SECURE - Input validation with Joi
import Joi from 'joi';

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  name: Joi.string().max(100).required()
});

export async function createUser(userData) {
  const { error, value } = userSchema.validate(userData);
  if (error) {
    throw new Error('Invalid user data');
  }
  
  const query = \`
    INSERT INTO users (email, password_hash, name, created_at)
    VALUES ($1, $2, $3, NOW())
    RETURNING id, email, name, created_at
  \`;
  
  const hashedPassword = await bcrypt.hash(value.password, 12);
  const result = await pool.query(query, [
    value.email,
    hashedPassword,
    value.name
  ]);
  
  return result.rows[0];
}

// NoSQL Injection Prevention (MongoDB)
import { MongoClient } from 'mongodb';

// ❌ VULNERABLE
export async function findUserVulnerable(userInput) {
  const user = await db.collection('users').findOne({
    email: userInput.email,
    password: userInput.password
  });
  return user;
}

// ✅ SECURE - Validate and sanitize input
export async function findUser(userInput) {
  // Validate input structure
  if (typeof userInput.email !== 'string' || 
      typeof userInput.password !== 'string') {
    throw new Error('Invalid input types');
  }
  
  // Use exact match queries
  const user = await db.collection('users').findOne({
    email: { $eq: userInput.email }
  });
  
  if (user && await bcrypt.compare(userInput.password, user.passwordHash)) {
    return user;
  }
  
  return null;
}`;

  const rateLimitingCode = `// lib/rate-limit.js
import { LRUCache } from 'lru-cache';

const rateLimit = new LRUCache({
  max: 500,
  ttl: 60000, // 1 minute
});

export function createRateLimiter(options = {}) {
  const {
    windowMs = 60000, // 1 minute
    max = 10, // 10 requests per window
    message = 'Too many requests',
    keyGenerator = (req) => req.ip
  } = options;

  return (req, res, next) => {
    const key = keyGenerator(req);
    const current = rateLimit.get(key) || 0;
    
    if (current >= max) {
      return res.status(429).json({
        error: message,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
    
    rateLimit.set(key, current + 1);
    next();
  };
}

// Usage in API routes
// pages/api/auth/login.js
import { createRateLimiter } from '@/lib/rate-limit';

const loginRateLimit = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per 15 minutes
  message: 'Too many login attempts, please try again later',
  keyGenerator: (req) => \`login:\${req.ip}\`
});

export default async function handler(req, res) {
  // Apply rate limiting
  await new Promise((resolve, reject) => {
    loginRateLimit(req, res, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
  
  // Your login logic here...
}

// Advanced rate limiting with Redis
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export async function checkRateLimit(key, limit, window) {
  const current = await redis.incr(key);
  
  if (current === 1) {
    await redis.expire(key, window);
  }
  
  return {
    count: current,
    remaining: Math.max(0, limit - current),
    reset: Date.now() + (window * 1000)
  };
}

// Sliding window rate limiter
export async function slidingWindowRateLimit(key, limit, window) {
  const now = Date.now();
  const pipeline = redis.pipeline();
  
  // Remove old entries
  pipeline.zremrangebyscore(key, 0, now - window);
  
  // Count current requests
  pipeline.zcard(key);
  
  // Add current request
  pipeline.zadd(key, now, \`\${now}-\${Math.random()}\`);
  
  // Set expiration
  pipeline.expire(key, Math.ceil(window / 1000));
  
  const results = await pipeline.exec();
  const count = results[1][1];
  
  return count < limit;
}`;

  const securityHeadersCode = `// next.config.js - Security Headers Configuration
const securityHeaders = [
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on'
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload'
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block'
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY'
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  },
  {
    key: 'Referrer-Policy',
    value: 'origin-when-cross-origin'
  },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' blob: data:",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests"
    ].join('; ')
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};

// middleware.js - Dynamic security headers
import { NextResponse } from 'next/server';

export function middleware(request) {
  const response = NextResponse.next();
  
  // Add security headers
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'origin-when-cross-origin');
  
  // Add HSTS for HTTPS
  if (request.nextUrl.protocol === 'https:') {
    response.headers.set(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains'
    );
  }
  
  // Content Security Policy for specific routes
  if (request.nextUrl.pathname.startsWith('/admin')) {
    response.headers.set(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    );
  }
  
  return response;
}

// lib/security-headers.js - Utility functions
export function setSecurityHeaders(res) {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'origin-when-cross-origin');
  
  // Prevent caching of sensitive pages
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}

export function setCSPHeader(res, policy = {}) {
  const defaultPolicy = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-src': ["'none'"],
    'object-src': ["'none'"]
  };
  
  const mergedPolicy = { ...defaultPolicy, ...policy };
  const cspString = Object.entries(mergedPolicy)
    .map(([directive, sources]) => \`\${directive} \${sources.join(' ')}\`)
    .join('; ');
    
  res.setHeader('Content-Security-Policy', cspString);
}`;

  const auditLoggingCode = `// lib/audit-logger.js
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/audit.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

export class AuditLogger {
  static logAuthEvent(event, userId, details = {}) {
    logger.info('AUTH_EVENT', {
      event,
      userId,
      timestamp: new Date().toISOString(),
      ip: details.ip,
      userAgent: details.userAgent,
      ...details
    });
  }
  
  static logSecurityEvent(event, severity, details = {}) {
    logger.warn('SECURITY_EVENT', {
      event,
      severity,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
  
  static logFailedLogin(email, ip, reason) {
    this.logSecurityEvent('FAILED_LOGIN', 'medium', {
      email,
      ip,
      reason,
      action: 'login_attempt'
    });
  }
  
  static logSuccessfulLogin(userId, ip, userAgent) {
    this.logAuthEvent('LOGIN_SUCCESS', userId, {
      ip,
      userAgent,
      action: 'login'
    });
  }
  
  static logPasswordChange(userId, ip) {
    this.logAuthEvent('PASSWORD_CHANGE', userId, {
      ip,
      action: 'password_change'
    });
  }
  
  static logSuspiciousActivity(type, details) {
    this.logSecurityEvent('SUSPICIOUS_ACTIVITY', 'high', {
      type,
      ...details
    });
  }
}

// Usage in authentication routes
// pages/api/auth/login.js
import { AuditLogger } from '@/lib/audit-logger';

export default async function handler(req, res) {
  const { email, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  
  try {
    const user = await authenticateUser(email, password);
    
    if (!user) {
      AuditLogger.logFailedLogin(email, ip, 'invalid_credentials');
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    AuditLogger.logSuccessfulLogin(user.id, ip, userAgent);
    
    // Create session...
    res.status(200).json({ message: 'Login successful' });
    
  } catch (error) {
    AuditLogger.logSecurityEvent('LOGIN_ERROR', 'high', {
      email,
      ip,
      error: error.message
    });
    
    res.status(500).json({ message: 'Internal server error' });
  }
}

// Security monitoring middleware
export function securityMonitoring(req, res, next) {
  const startTime = Date.now();
  
  // Monitor for suspicious patterns
  const suspiciousPatterns = [
    /(\\.\\.\\/|\\.\\.\\\\)/g, // Path traversal
    /(union|select|insert|delete|update|drop)/gi, // SQL injection
    /<script|javascript:|vbscript:/gi, // XSS attempts
  ];
  
  const requestData = JSON.stringify(req.body);
  const queryData = JSON.stringify(req.query);
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(requestData) || pattern.test(queryData)) {
      AuditLogger.logSuspiciousActivity('MALICIOUS_INPUT', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        url: req.url,
        method: req.method,
        body: req.body,
        query: req.query
      });
      break;
    }
  }
  
  // Log response time for performance monitoring
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    if (duration > 5000) { // Log slow requests
      AuditLogger.logSecurityEvent('SLOW_REQUEST', 'low', {
        url: req.url,
        method: req.method,
        duration,
        ip: req.ip
      });
    }
  });
  
  next();
}`;

  const markSectionComplete = (sectionId: string) => {
    const newCompleted = new Set(completedSections);
    newCompleted.add(sectionId);
    setCompletedSections(newCompleted);
    
    const progress = (newCompleted.size / securityTopics.length) * 100;
    updateModuleProgress('advanced-security', progress);
  };

  const runVulnerabilityTest = (type: VulnerabilityTestType) => {
    setVulnerabilityTest({ type, running: true });
    
    setTimeout(() => {
      const results: Record<VulnerabilityTestType, VulnerabilityTestResult> = {
        csrf: {
          passed: 8,
          failed: 2,
          issues: ['Missing CSRF token validation on /api/user/update', 'Weak token generation algorithm']
        },
        xss: {
          passed: 9,
          failed: 1,
          issues: ['Unescaped user input in comment display']
        },
        injection: {
          passed: 10,
          failed: 0,
          issues: []
        }
      };
      
      setVulnerabilityTest({
        type,
        running: false,
        results: results[type] || { passed: 5, failed: 0, issues: [] }
      });
    }, 3000);
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
        <Navigation />
        <div className="container mx-auto px-4 py-8 text-center">
          <h1 className="text-2xl font-bold mb-4">Please log in to access advanced security content</h1>
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
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <Badge className="mb-4">Advanced Security</Badge>
          <h1 className="text-4xl font-bold mb-4">Advanced Security Patterns</h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Master advanced security concepts, vulnerability prevention, and security best practices for production Next.js applications.
          </p>
        </div>

        {/* Progress Overview */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5 text-primary" />
              Security Mastery Progress
            </CardTitle>
            <CardDescription>
              Complete all security topics to become a Next.js security expert
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between text-sm">
                <span>Overall Progress</span>
                <span>{Math.round((completedSections.size / securityTopics.length) * 100)}%</span>
              </div>
              <Progress value={(completedSections.size / securityTopics.length) * 100} />
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                {securityTopics.map((topic) => (
                  <div key={topic.id} className="flex items-center gap-2">
                    {completedSections.has(topic.id) ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                    )}
                    <span className="text-sm">{topic.title}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Security Topics */}
        <Tabs defaultValue="csrf" className="mb-8">
          <TabsList className="grid w-full grid-cols-3 lg:grid-cols-6">
            <TabsTrigger value="csrf">CSRF</TabsTrigger>
            <TabsTrigger value="xss">XSS</TabsTrigger>
            <TabsTrigger value="injection">Injection</TabsTrigger>
            <TabsTrigger value="rate-limiting">Rate Limiting</TabsTrigger>
            <TabsTrigger value="headers">Headers</TabsTrigger>
            <TabsTrigger value="audit">Auditing</TabsTrigger>
          </TabsList>
          
          <TabsContent value="csrf">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-red-500" />
                      CSRF Protection
                    </CardTitle>
                    <CardDescription>
                      Prevent Cross-Site Request Forgery attacks with token-based protection
                    </CardDescription>
                  </div>
                  <Badge variant="destructive">High Risk</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>CSRF attacks</strong> trick users into performing unwanted actions on applications where they're authenticated. 
                      Always validate CSRF tokens for state-changing operations.
                    </AlertDescription>
                  </Alert>
                  
                  <CodeBlock
                    code={csrfProtectionCode}
                    language="javascript"
                    title="Complete CSRF Protection Implementation"
                    description="Token generation, validation, and client-side integration"
                  />
                  
                  <div className="flex justify-between items-center">
                    <div>
                      <h4 className="font-semibold">Key Concepts Covered:</h4>
                      <ul className="text-sm text-muted-foreground mt-1">
                        <li>• Token generation and validation</li>
                        <li>• Middleware integration</li>
                        <li>• Client-side token handling</li>
                        <li>• Double-submit cookie pattern</li>
                      </ul>
                    </div>
                    <Button onClick={() => markSectionComplete('csrf')}>
                      {completedSections.has('csrf') ? (
                        <>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Completed
                        </>
                      ) : (
                        'Mark Complete'
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="xss">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Bug className="h-5 w-5 text-red-600" />
                      XSS Prevention
                    </CardTitle>
                    <CardDescription>
                      Protect against Cross-Site Scripting attacks through input sanitization and CSP
                    </CardDescription>
                  </div>
                  <Badge variant="destructive">Critical</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <Alert>
                    <Bug className="h-4 w-4" />
                    <AlertDescription>
                      <strong>XSS attacks</strong> inject malicious scripts into web applications. 
                      Always sanitize user input and implement Content Security Policy headers.
                    </AlertDescription>
                  </Alert>
                  
                  <CodeBlock
                    code={xssPreventionCode}
                    language="javascript"
                    title="XSS Prevention Strategies"
                    description="Input sanitization, output encoding, and CSP implementation"
                  />
                  
                  <div className="flex justify-between items-center">
                    <div>
                      <h4 className="font-semibold">Protection Methods:</h4>
                      <ul className="text-sm text-muted-foreground mt-1">
                        <li>• Input sanitization with DOMPurify</li>
                        <li>• Output encoding and escaping</li>
                        <li>• Content Security Policy</li>
                        <li>• Safe React rendering practices</li>
                      </ul>
                    </div>
                    <Button onClick={() => markSectionComplete('xss')}>
                      {completedSections.has('xss') ? (
                        <>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Completed
                        </>
                      ) : (
                        'Mark Complete'
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="injection">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Skull className="h-5 w-5 text-red-600" />
                      Injection Attack Prevention
                    </CardTitle>
                    <CardDescription>
                      Prevent SQL injection, NoSQL injection, and command injection attacks
                    </CardDescription>
                  </div>
                  <Badge variant="destructive">Critical</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <Alert>
                    <Skull className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Injection attacks</strong> are among the most dangerous vulnerabilities. 
                      Always use parameterized queries and validate all user input.
                    </AlertDescription>
                  </Alert>
                  
                  <CodeBlock
                    code={injectionPreventionCode}
                    language="javascript"
                    title="Injection Prevention Techniques"
                    description="Parameterized queries, input validation, and secure database practices"
                  />
                  
                  <div className="flex justify-between items-center">
                    <div>
                      <h4 className="font-semibold">Prevention Strategies:</h4>
                      <ul className="text-sm text-muted-foreground mt-1">
                        <li>• Parameterized queries and prepared statements</li>
                        <li>• Input validation and type checking</li>
                        <li>• Least privilege database access</li>
                        <li>• NoSQL injection prevention</li>
                      </ul>
                    </div>
                    <Button onClick={() => markSectionComplete('injection')}>
                      {completedSections.has('injection') ? (
                        <>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Completed
                        </>
                      ) : (
                        'Mark Complete'
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="rate-limiting">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Zap className="h-5 w-5 text-yellow-500" />
                      Rate Limiting & DDoS Protection
                    </CardTitle>
                    <CardDescription>
                      Implement rate limiting to prevent brute force and denial of service attacks
                    </CardDescription>
                  </div>
                  <Badge variant="secondary">Medium Risk</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <CodeBlock
                    code={rateLimitingCode}
                    language="javascript"
                    title="Advanced Rate Limiting Implementation"
                    description="Memory-based, Redis-based, and sliding window rate limiting"
                  />
                  
                  <div className="flex justify-between items-center">
                    <div>
                      <h4 className="font-semibold">Rate Limiting Strategies:</h4>
                      <ul className="text-sm text-muted-foreground mt-1">
                        <li>• Fixed window rate limiting</li>
                        <li>• Sliding window implementation</li>
                        <li>• Distributed rate limiting with Redis</li>
                        <li>• Adaptive rate limiting</li>
                      </ul>
                    </div>
                    <Button onClick={() => markSectionComplete('rate-limiting')}>
                      {completedSections.has('rate-limiting') ? (
                        <>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Completed
                        </>
                      ) : (
                        'Mark Complete'
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="headers">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Lock className="h-5 w-5 text-blue-500" />
                      Security Headers
                    </CardTitle>
                    <CardDescription>
                      Configure HTTP security headers for defense in depth
                    </CardDescription>
                  </div>
                  <Badge variant="secondary">Medium Risk</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <CodeBlock
                    code={securityHeadersCode}
                    language="javascript"
                    title="Comprehensive Security Headers Setup"
                    description="Next.js configuration and middleware implementation"
                  />
                  
                  <div className="flex justify-between items-center">
                    <div>
                      <h4 className="font-semibold">Essential Headers:</h4>
                      <ul className="text-sm text-muted-foreground mt-1">
                        <li>• Content Security Policy (CSP)</li>
                        <li>• Strict Transport Security (HSTS)</li>
                        <li>• X-Frame-Options and X-Content-Type-Options</li>
                        <li>• Referrer Policy and Feature Policy</li>
                      </ul>
                    </div>
                    <Button onClick={() => markSectionComplete('headers')}>
                      {completedSections.has('headers') ? (
                        <>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Completed
                        </>
                      ) : (
                        'Mark Complete'
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="audit">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Eye className="h-5 w-5 text-green-500" />
                      Security Auditing & Monitoring
                    </CardTitle>
                    <CardDescription>
                      Implement comprehensive logging and monitoring for security events
                    </CardDescription>
                  </div>
                  <Badge>High Priority</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <CodeBlock
                    code={auditLoggingCode}
                    language="javascript"
                    title="Security Audit Logging System"
                    description="Comprehensive logging, monitoring, and alerting implementation"
                  />
                  
                  <div className="flex justify-between items-center">
                    <div>
                      <h4 className="font-semibold">Monitoring Capabilities:</h4>
                      <ul className="text-sm text-muted-foreground mt-1">
                        <li>• Authentication event logging</li>
                        <li>• Suspicious activity detection</li>
                        <li>• Performance monitoring</li>
                        <li>• Security incident response</li>
                      </ul>
                    </div>
                    <Button onClick={() => markSectionComplete('audit')}>
                      {completedSections.has('audit') ? (
                        <>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          Completed
                        </>
                      ) : (
                        'Mark Complete'
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Vulnerability Testing */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-5 w-5 text-red-500" />
              Vulnerability Testing
            </CardTitle>
            <CardDescription>
              Test your application for common security vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {(['csrf', 'xss', 'injection'] as const).map((testType) => (
                <Card key={testType} className="p-4">
                  <div className="text-center">
                    <h4 className="font-semibold mb-2 capitalize">{testType} Test</h4>
                    <Button 
                      onClick={() => runVulnerabilityTest(testType)}
                      disabled={vulnerabilityTest?.running}
                      className="w-full mb-3"
                    >
                      {vulnerabilityTest?.running && vulnerabilityTest?.type === testType ? (
                        'Testing...'
                      ) : (
                        `Run ${testType.toUpperCase()} Test`
                      )}
                    </Button>
                    
                    {vulnerabilityTest?.type === testType && vulnerabilityTest?.results && (
                      <div className="text-left">
                        <div className="flex justify-between text-sm mb-2">
                          <span className="text-green-600">✓ {vulnerabilityTest.results.passed} passed</span>
                          <span className="text-red-600">✗ {vulnerabilityTest.results.failed} failed</span>
                        </div>
                        {vulnerabilityTest.results.issues.length > 0 && (
                          <div className="text-xs text-muted-foreground">
                            <p className="font-medium">Issues found:</p>
                            <ul className="list-disc list-inside">
                              {vulnerabilityTest.results.issues.map((issue, i) => (
                                <li key={i}>{issue}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Security Checklist */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-500" />
              Production Security Checklist
            </CardTitle>
            <CardDescription>
              Essential security measures for production deployment
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-3">Authentication & Authorization</h4>
                <div className="space-y-2">
                  {[
                    'Implement strong password policies',
                    'Use secure session management',
                    'Enable multi-factor authentication',
                    'Implement proper role-based access control',
                    'Use secure password hashing (bcrypt, scrypt)'
                  ].map((item, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h4 className="font-semibold mb-3">Infrastructure & Deployment</h4>
                <div className="space-y-2">
                  {[
                    'Use HTTPS everywhere',
                    'Configure security headers',
                    'Implement rate limiting',
                    'Set up monitoring and alerting',
                    'Regular security updates'
                  ].map((item, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-sm">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}