import './globals.css';
import type { Metadata } from 'next';
import { ThemeProvider } from '@/components/theme-provider';
import { Toaster } from '@/components/ui/toaster';
import { AuthProvider } from '@/contexts/auth-context';
import { ProgressProvider } from '@/contexts/progress-context';

export const metadata: Metadata = {
  metadataBase: new URL('http://localhost:3000'),
  title: 'Next.js Authentication Learning Platform',
  description: 'Master authentication in Next.js through interactive examples, comprehensive tutorials, and hands-on practice',
  keywords: 'Next.js, authentication, JWT, OAuth, security, learning, tutorial',
  authors: [{ name: 'Next.js Auth Learning Platform' }],
  openGraph: {
    title: 'Next.js Authentication Learning Platform',
    description: 'Master authentication in Next.js through interactive examples and comprehensive tutorials',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="font-sans antialiased">
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <AuthProvider>
            <ProgressProvider>
              {children}
              <Toaster />
            </ProgressProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
