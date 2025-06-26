'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Copy, Check, Play } from 'lucide-react';
import { cn } from '@/lib/utils';

interface CodeBlockProps {
  code: string;
  language: string;
  title?: string;
  description?: string;
  filename?: string;
  runnable?: boolean;
  onRun?: () => void;
}

export function CodeBlock({
  code,
  language,
  title,
  description,
  filename,
  runnable = false,
  onRun
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="overflow-hidden">
      {(title || filename) && (
        <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/50">
          <div className="flex items-center gap-3">
            {filename && (
              <Badge variant="outline" className="font-mono text-xs">
                {filename}
              </Badge>
            )}
            {title && (
              <h4 className="font-semibold text-sm">{title}</h4>
            )}
          </div>
          <div className="flex items-center gap-2">
            {runnable && (
              <Button size="sm" variant="outline" onClick={onRun}>
                <Play className="h-3 w-3 mr-1" />
                Run
              </Button>
            )}
            <Button
              size="sm"
              variant="outline"
              onClick={copyToClipboard}
              className="gap-1"
            >
              {copied ? (
                <Check className="h-3 w-3" />
              ) : (
                <Copy className="h-3 w-3" />
              )}
              {copied ? 'Copied!' : 'Copy'}
            </Button>
          </div>
        </div>
      )}
      
      {description && (
        <div className="px-4 py-2 text-sm text-muted-foreground bg-muted/30">
          {description}
        </div>
      )}
      
      <div className="relative">
        <pre className={cn(
          "overflow-x-auto p-4 text-sm",
          "bg-slate-950 dark:bg-slate-900 text-slate-50"
        )}>
          <code className={`language-${language}`}>
            {code}
          </code>
        </pre>
        
        {!title && !filename && (
          <Button
            size="sm"
            variant="secondary"
            onClick={copyToClipboard}
            className="absolute top-2 right-2 gap-1"
          >
            {copied ? (
              <Check className="h-3 w-3" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
          </Button>
        )}
      </div>
    </Card>
  );
}