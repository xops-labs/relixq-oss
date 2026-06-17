// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../lib/cn';
import type { Severity } from '../types';

const badgeVariants = cva(
  'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
  {
    variants: {
      tone: {
        neutral: 'bg-muted text-foreground ring-border',
        outline: 'bg-transparent text-foreground ring-border',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone, className }))} {...props} />;
}

const severityClass: Record<Severity, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical ring-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high ring-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium ring-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low ring-severity-low/30',
  info: 'bg-severity-info/15 text-severity-info ring-severity-info/30',
};

/** Severity chip with a color-coded dot. Pure presentational, no app deps. */
export function SeverityBadge({ value, className }: { value: Severity; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
        severityClass[value],
        className,
      )}
      aria-label={`Severity: ${value}`}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-current" />
      {value}
    </span>
  );
}
