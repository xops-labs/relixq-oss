// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import type { RuleSummary } from '../types';
import { SeverityBadge } from '../ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { EmptyState } from '../ui/empty-state';
import { cn } from '../lib/cn';

const safetyClass: Record<RuleSummary['quantumSafety'], string> = {
  vulnerable: 'text-severity-critical',
  grover_weakened: 'text-severity-medium',
  classically_broken: 'text-severity-high',
  hybrid: 'text-severity-medium',
  quantum_safe: 'text-severity-low',
  unknown: 'text-muted-foreground',
};

const safetyLabel: Record<RuleSummary['quantumSafety'], string> = {
  vulnerable: 'vulnerable',
  grover_weakened: 'Grover-weakened',
  classically_broken: 'classically broken',
  hybrid: 'hybrid',
  quantum_safe: 'quantum-safe',
  unknown: 'unknown',
};

export interface RuleBrowserProps {
  rules: RuleSummary[];
  /** Optional click handler for a rule row (e.g. open rule detail). */
  onSelect?: (ruleId: string) => void;
  className?: string;
}

/**
 * Browse the active rule pack — works for any loaded rule pack.
 * Pure presentational table over a structural `RuleSummary[]`.
 */
export function RuleBrowser({ rules, onSelect, className }: RuleBrowserProps) {
  if (rules.length === 0) {
    return <EmptyState title="No rules" description="No rules match the current pack or filter." />;
  }
  return (
    <div className={cn('rounded-lg border border-border bg-card', className)}>
      <Table>
        <caption className="sr-only">Active rule pack</caption>
        <TableHeader>
          <TableRow>
            <TableHead>Rule</TableHead>
            <TableHead>Language</TableHead>
            <TableHead>Pack</TableHead>
            <TableHead>Quantum safety</TableHead>
            <TableHead className="w-24">Severity</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((r) => (
            <TableRow
              key={r.ruleId}
              onClick={onSelect ? () => onSelect(r.ruleId) : undefined}
              className={onSelect ? 'cursor-pointer' : undefined}
              data-rule-id={r.ruleId}
            >
              <TableCell>
                <div className="font-mono text-xs text-foreground">{r.ruleId}</div>
                <div className="text-xs text-muted-foreground">{r.title}</div>
              </TableCell>
              <TableCell className="text-xs">{r.language}</TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">{r.pack}</TableCell>
              <TableCell className={cn('text-xs font-medium', safetyClass[r.quantumSafety])}>
                {safetyLabel[r.quantumSafety]}
              </TableCell>
              <TableCell>
                <SeverityBadge value={r.severity} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
