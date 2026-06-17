// CSS-only export dropdown (native <details>) — no client JS, matching the
// rest of the page. Links hit the proxy route, which streams the attachment.

const FORMATS: { format: string; label: string; hint: string }[] = [
  { format: 'json', label: 'JSON', hint: 'full structured report' },
  { format: 'sarif', label: 'SARIF', hint: 'GitHub Code Scanning' },
  { format: 'markdown', label: 'Markdown', hint: 'paste into docs / PRs' },
  { format: 'html', label: 'HTML', hint: 'standalone report' },
];

export function ExportMenu({ projectId }: { projectId: string }) {
  return (
    <details className="relative">
      <summary className="focus-ring inline-flex cursor-pointer list-none items-center gap-1.5 rounded-md border border-input bg-background px-4 py-2 text-sm font-medium transition hover:bg-muted [&::-webkit-details-marker]:hidden">
        Export
        <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-3.5 w-3.5 text-muted-foreground">
          <path d="m4 6 4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </summary>
      <div className="absolute right-0 z-20 mt-1 w-56 rounded-md border bg-card p-1 shadow-md">
        {FORMATS.map((f) => (
          <a
            key={f.format}
            href={`/api/projects/${projectId}/export?format=${f.format}`}
            download
            className="focus-ring block rounded px-3 py-1.5 text-sm transition hover:bg-muted"
          >
            {f.label} <span className="text-xs text-muted-foreground">— {f.hint}</span>
          </a>
        ))}
      </div>
    </details>
  );
}
