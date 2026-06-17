// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import type { ReactNode } from 'react';
import { cn } from '../lib/cn';

export function EmptyState({
  title,
  description,
  action,
  className,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-muted/30 p-10 text-center',
        className,
      )}
    >
      <h3 className="text-sm font-medium">{title}</h3>
      {description && <p className="max-w-md text-sm text-muted-foreground">{description}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

/** One shimmering placeholder row for tables while findings load. */
export function SkeletonRow({ columns = 6, className }: { columns?: number; className?: string }) {
  return (
    <tr className={cn('border-b border-border', className)} aria-hidden>
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="p-3 align-middle">
          <div className="h-3 w-full animate-pulse rounded bg-muted" />
        </td>
      ))}
    </tr>
  );
}
