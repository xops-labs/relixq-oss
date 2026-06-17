'use client';

// Filterable wrapper around the shared FindingTable: severity chips, an
// algorithm dropdown, a file-path search box, and a vendored-paths toggle.
// Filtering is in-memory — the server page already ships the full rows.

import { useMemo, useState } from 'react';
import {
  cn,
  FindingTable,
  SeverityBadge,
  type Severity,
} from '@relix-q/web-components';
import { toFindingRow, type Finding } from '@/lib/types';
import { FindingDetails } from './finding-details';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// Path fragments treated as vendored / build output rather than first-party code.
const VENDORED = ['node_modules/', '.next/', 'vendor/', 'third_party/', 'dist/', 'build/', 'out/', 'bin/', 'obj/'];

function isVendored(path: string): boolean {
  const p = path.replace(/\\/g, '/').toLowerCase();
  return VENDORED.some((v) => p.includes(`/${v}`) || p.startsWith(v));
}

export function FindingsExplorer({ findings }: { findings: Finding[] }) {
  const [severities, setSeverities] = useState<ReadonlySet<Severity>>(new Set());
  const [algorithm, setAlgorithm] = useState('all');
  const [query, setQuery] = useState('');
  const [hideVendored, setHideVendored] = useState(false);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const rows = useMemo(() => findings.map(toFindingRow), [findings]);
  const byId = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);

  const severityCounts = useMemo(() => {
    const counts = new Map<Severity, number>();
    for (const r of rows) counts.set(r.severity, (counts.get(r.severity) ?? 0) + 1);
    return counts;
  }, [rows]);

  const algorithms = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rows) counts.set(r.algorithm, (counts.get(r.algorithm) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [rows]);

  const needle = query.trim().toLowerCase();
  const filtered = rows.filter(
    (r) =>
      (severities.size === 0 || severities.has(r.severity)) &&
      (algorithm === 'all' || r.algorithm === algorithm) &&
      (!needle || r.filePath.toLowerCase().includes(needle)) &&
      (!hideVendored || !isVendored(r.filePath)),
  );

  const isFiltered = severities.size > 0 || algorithm !== 'all' || needle !== '' || hideVendored;

  // Clamp instead of resetting in an effect: filters changing can shrink the
  // result set below the current page without an extra render.
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const paged = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  function toggleSeverity(s: Severity) {
    setPage(1);
    setSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function clear() {
    setSeverities(new Set());
    setAlgorithm('all');
    setQuery('');
    setHideVendored(false);
    setPage(1);
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <input
          type="search"
          value={query}
          onChange={(e) => {
            setPage(1);
            setQuery(e.target.value);
          }}
          placeholder="Filter by file path…"
          aria-label="Filter findings by file path"
          className="focus-ring w-60 rounded-md border border-input bg-background px-3 py-1.5 text-sm shadow-sm"
        />

        <div className="flex items-center gap-1.5" role="group" aria-label="Filter by severity">
          {SEVERITIES.map((s) => {
            const count = severityCounts.get(s) ?? 0;
            if (count === 0) return null;
            const on = severities.has(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggleSeverity(s)}
                aria-pressed={on}
                title={on ? `Stop filtering by ${s}` : `Show only ${s} findings (toggles)`}
                className={cn(
                  'focus-ring flex items-center gap-1 rounded-md transition-opacity',
                  severities.size > 0 && !on && 'opacity-35 hover:opacity-70',
                )}
              >
                <SeverityBadge value={s} />
                <span className="font-mono text-xs text-muted-foreground">{count}</span>
              </button>
            );
          })}
        </div>

        <select
          value={algorithm}
          onChange={(e) => {
            setPage(1);
            setAlgorithm(e.target.value);
          }}
          aria-label="Filter by algorithm"
          className="focus-ring rounded-md border border-input bg-background px-2 py-1.5 text-sm"
        >
          <option value="all">All algorithms</option>
          {algorithms.map(([algo, count]) => (
            <option key={algo} value={algo}>
              {algo} ({count})
            </option>
          ))}
        </select>

        <label className="flex cursor-pointer items-center gap-1.5 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={hideVendored}
            onChange={(e) => {
              setPage(1);
              setHideVendored(e.target.checked);
            }}
            className="focus-ring h-3.5 w-3.5 rounded border-input accent-current"
          />
          Hide vendored / build paths
        </label>

        <span className="ml-auto text-sm text-muted-foreground">
          <span className="font-mono text-foreground">{filtered.length}</span> of{' '}
          <span className="font-mono">{rows.length}</span> findings
          {isFiltered && (
            <button
              type="button"
              onClick={clear}
              className="focus-ring ml-2 rounded-sm underline underline-offset-2 hover:text-foreground"
            >
              Clear filters
            </button>
          )}
        </span>
      </div>

      {filtered.length > 0 ? (
        <>
          <div className="rounded-lg border">
            <FindingTable
              findings={paged}
              detailHrefBuilder={() => '#'}
              expandedIds={expanded}
              onToggleExpand={toggleExpanded}
              renderDetails={(row) => {
                const finding = byId.get(row.findingId);
                return finding ? <FindingDetails finding={finding} /> : null;
              }}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
            <span>
              Showing{' '}
              <span className="font-mono text-foreground">
                {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, filtered.length)}
              </span>{' '}
              of <span className="font-mono text-foreground">{filtered.length}</span>
            </span>
            <div className="flex items-center gap-2">
              <select
                value={pageSize}
                onChange={(e) => {
                  setPage(1);
                  setPageSize(Number(e.target.value));
                }}
                aria-label="Findings per page"
                className="focus-ring rounded-md border border-input bg-background px-2 py-1 text-sm"
              >
                {[10, 25, 50, 100].map((n) => (
                  <option key={n} value={n}>
                    {n} / page
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={() => setPage(currentPage - 1)}
                disabled={currentPage === 1}
                className="focus-ring rounded-md border px-2.5 py-1 transition-colors hover:bg-muted disabled:pointer-events-none disabled:opacity-40"
              >
                ← Prev
              </button>
              <span className="font-mono text-xs">
                {currentPage} / {pageCount}
              </span>
              <button
                type="button"
                onClick={() => setPage(currentPage + 1)}
                disabled={currentPage === pageCount}
                className="focus-ring rounded-md border px-2.5 py-1 transition-colors hover:bg-muted disabled:pointer-events-none disabled:opacity-40"
              >
                Next →
              </button>
            </div>
          </div>
        </>
      ) : (
        <p className="rounded-lg border px-4 py-8 text-center text-sm text-muted-foreground">
          No findings match the current filters.
        </p>
      )}
    </div>
  );
}
