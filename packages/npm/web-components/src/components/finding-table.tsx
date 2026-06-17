// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import * as React from 'react';
import type { FindingRow } from '../types';
import { SeverityBadge } from '../ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { cn, formatRelative } from '../lib/cn';

/**
 * Render a location cell as a link. Framework-agnostic: defaults to a plain
 * anchor, but a host app passes its router-aware link (e.g. Next.js `Link`)
 * via the `renderLink` prop so client-side navigation is preserved.
 */
export type RenderLink = (props: {
  href: string;
  className: string;
  children: React.ReactNode;
}) => React.ReactElement;

const defaultRenderLink: RenderLink = ({ href, className, children }) => (
  <a href={href} className={className}>
    {children}
  </a>
);

// Column-header hint. The Table scroll wrapper (`overflow-auto`) would clip an
// absolutely-positioned tooltip panel, so headers use the native title attr.
function HintLabel({ hint, children }: { hint: string; children: React.ReactNode }) {
  return (
    <span title={hint} className="cursor-help underline decoration-border decoration-dotted underline-offset-4">
      {children}
    </span>
  );
}

export interface FindingTableProps {
  findings: FindingRow[];
  /** Build the detail-page href for a finding id. */
  detailHrefBuilder: (id: string) => string;
  /** Inject a router-aware link component; falls back to a plain `<a>`. */
  renderLink?: RenderLink;
  /**
   * Render an expanded explanation panel beneath a row. Expansion is
   * controlled: provide this together with `expandedIds` / `onToggleExpand`.
   * The toggle attaches click handlers, so expandable tables must be rendered
   * from a client tree; without these props the table stays server-safe.
   */
  renderDetails?: (finding: FindingRow) => React.ReactNode;
  expandedIds?: ReadonlySet<string>;
  onToggleExpand?: (findingId: string) => void;
}

/**
 * Sortable findings list. The core table of every Relix-Q view. Pure
 * presentational — accepts a structural `FindingRow[]` (a subset of the host
 * app's finding model) so it is reusable across any consuming app.
 */
export function FindingTable({
  findings,
  detailHrefBuilder,
  renderLink = defaultRenderLink,
  renderDetails,
  expandedIds,
  onToggleExpand,
}: FindingTableProps) {
  const expandable = Boolean(renderDetails && onToggleExpand);
  return (
    <Table>
      <caption className="sr-only">Findings list, sortable by risk score</caption>
      <TableHeader>
        <TableRow>
          {expandable && <TableHead className="w-8" aria-label="Details" />}
          <TableHead className="w-24">
            <HintLabel hint="Rule-assigned severity of the finding, from critical down to info.">Severity</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="Cryptographic algorithm or primitive the rule detected (RSA, ECDH, MD5, …).">Algorithm</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="File and line where the crypto usage was found.">Location</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="Owning service from the service catalog. Populated by context enrichment when available.">Service</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="Deployment environment of the affected code (production, staging, dev). 'unknown' when no enrichment source is configured.">Env</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="Network exposure of the affected component (public, partner, internal). 'unknown' when no enrichment source is configured.">Exposure</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="Code owner, from CODEOWNERS or the service catalog.">Owner</HintLabel>
          </TableHead>
          <TableHead className="text-right">
            <HintLabel hint="Per-finding risk score, 0–100 (higher = worse). Computed from algorithm risk, usage criticality, exposure, and environment.">Risk</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="When this finding was last observed by a scan.">Last seen</HintLabel>
          </TableHead>
          <TableHead>
            <HintLabel hint="Triage state: open, acknowledged, resolved, exception, or false positive.">Status</HintLabel>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => {
          const open = expandable && (expandedIds?.has(f.findingId) ?? false);
          return (
          <React.Fragment key={f.findingId}>
          <TableRow>
            {expandable && (
              <TableCell className="w-8 pr-0">
                <button
                  type="button"
                  onClick={() => onToggleExpand?.(f.findingId)}
                  aria-expanded={open}
                  aria-label={`${open ? 'Collapse' : 'Expand'} explanation for ${f.filePath}:${f.lineNumber}`}
                  className="focus-ring rounded-sm p-1 text-muted-foreground transition-colors hover:text-foreground"
                >
                  <svg
                    viewBox="0 0 16 16"
                    fill="none"
                    aria-hidden
                    className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-90')}
                  >
                    <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </TableCell>
            )}
            <TableCell>
              <SeverityBadge value={f.severity} />
            </TableCell>
            <TableCell className="font-mono text-xs">{f.algorithm}</TableCell>
            <TableCell>
              {renderLink({
                href: detailHrefBuilder(f.findingId),
                // break-all so deep vendored paths wrap instead of forcing a
                // horizontal scrollbar on the whole table
                className:
                  'focus-ring break-all rounded-sm font-mono text-xs text-foreground underline-offset-2 hover:underline',
                children: `${f.filePath}:${f.lineNumber}`,
              })}
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">{f.serviceId ?? '—'}</TableCell>
            <TableCell className="text-xs">{f.environment}</TableCell>
            <TableCell className="text-xs">{f.exposure}</TableCell>
            <TableCell className="text-xs text-muted-foreground">{f.owner ?? '—'}</TableCell>
            <TableCell className="text-right font-mono text-xs">{f.riskScore}</TableCell>
            <TableCell className="text-xs text-muted-foreground">{formatRelative(f.lastSeenDate)}</TableCell>
            <TableCell className="text-xs">{f.status}</TableCell>
          </TableRow>
          {open && (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={11} className="bg-muted/30 p-0">
                {renderDetails?.(f)}
              </TableCell>
            </TableRow>
          )}
          </React.Fragment>
          );
        })}
      </TableBody>
    </Table>
  );
}
