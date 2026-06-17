'use client';

// Filterable card grid for the algorithm families. Imports the shared
// knowledge base directly (client bundle), so no serialization is needed.

import { useState } from 'react';
import { cn } from '@relix-q/web-components';
import { CRYPTO_FAMILIES, type ThreatModel } from '@/lib/crypto-help';

const FILTERS: { label: string; value: ThreatModel | 'all' }[] = [
  { label: 'All families', value: 'all' },
  { label: 'Shor-broken', value: 'Shor-broken' },
  { label: 'Classical', value: 'Classical' },
  { label: 'Grover-weakened', value: 'Grover-weakened' },
];

const THREAT_BADGE: Record<ThreatModel, string> = {
  'Shor-broken': 'bg-severity-critical/15 text-severity-critical ring-severity-critical/30',
  Classical: 'bg-severity-medium/15 text-severity-medium ring-severity-medium/30',
  'Grover-weakened': 'bg-severity-low/15 text-severity-low ring-severity-low/30',
};

function DocIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-3.5 w-3.5 shrink-0 text-muted-foreground">
      <path
        d="M4 1.5h5.5L13 5v9a.5.5 0 0 1-.5.5h-9A.5.5 0 0 1 3 14V2a.5.5 0 0 1 .5-.5Z"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
      <path d="M9.5 1.5V5H13M5.5 8h5M5.5 10.5h5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

export function FamilyGrid() {
  const [filter, setFilter] = useState<ThreatModel | 'all'>('all');
  const shown = CRYPTO_FAMILIES.filter((f) => filter === 'all' || f.threat === filter);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter families by threat model">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            type="button"
            onClick={() => setFilter(f.value)}
            aria-pressed={filter === f.value}
            className={cn(
              'focus-ring rounded-md border px-3 py-1 text-sm transition-colors',
              filter === f.value
                ? 'border-border bg-muted font-medium text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {shown.map((family) => (
          <div key={family.name} className="flex flex-col rounded-lg border p-4">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-medium">{family.name}</h3>
              <span
                className={cn(
                  'rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
                  THREAT_BADGE[family.threat],
                )}
              >
                {family.threat}
              </span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {family.examples.split(', ').map((algo) => (
                <code key={algo} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {algo}
                </code>
              ))}
            </div>
            <p className="mt-3 text-sm text-muted-foreground">{family.why}</p>
            <p className="mt-2 text-sm">
              <span className="font-medium">Migrate:</span> {family.fix}
            </p>
            <ul className="mt-3 space-y-1.5 border-t pt-3">
              {family.refs.map((ref) => (
                <li key={ref.url} className="flex items-start gap-2 text-sm">
                  <span className="mt-0.5">
                    <DocIcon />
                  </span>
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noreferrer"
                    className="focus-ring rounded-sm underline decoration-border underline-offset-2 hover:decoration-foreground"
                  >
                    {ref.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
