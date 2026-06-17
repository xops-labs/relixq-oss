import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle, EmptyState } from '@relix-q/web-components';
import { apiGet } from '@/lib/api';
import { requireUser } from '@/lib/session';
import type { Project } from '@/lib/types';
import { Button } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function ProjectsPage() {
  await requireUser();
  const projects = (await apiGet<Project[]>('/api/v1/projects')) ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="text-sm text-muted-foreground">Scan a codebase for quantum-vulnerable cryptography.</p>
        </div>
        <Link href="/projects/new">
          <Button>New project</Button>
        </Link>
      </div>

      {projects.length === 0 ? (
        <EmptyState
          title="No projects yet"
          description="Create your first project to run a scan against the bundled sample or a git repository."
        />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {projects.map((p) => (
            <Link key={p.id} href={`/projects/${p.id}`} className="focus-ring rounded-lg">
              <Card className="h-full transition hover:border-foreground/30">
                <CardHeader>
                  <CardTitle>{p.name}</CardTitle>
                  <p className="text-xs text-muted-foreground">
                    {p.source.kind === 'git'
                      ? `git · ${p.source.value}`
                      : p.source.kind === 'local'
                        ? `local · ${p.source.value || '(all of scan-targets)'}`
                        : p.source.kind === 'upload'
                          ? 'upload · uploaded .zip archive'
                          : `sample · ${p.source.value}`}
                  </p>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  {p.latestScan ? (
                    <ScanLine project={p} />
                  ) : (
                    <span>Never scanned</span>
                  )}
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function ScanLine({ project }: { project: Project }) {
  const s = project.latestScan!;
  if (s.status === 'running') return <span>Scan running…</span>;
  if (s.status === 'failed') return <span className="text-destructive">Last scan failed</span>;
  return (
    <span
      title="Findings detected by the latest scan, and the risk score (0–100, higher = worse) of its most severe finding."
      className="cursor-help"
    >
      <span className="font-mono text-foreground">{s.findingCount}</span> findings · risk{' '}
      <span className="font-mono text-foreground">{s.score ?? '—'}</span>
      {s.scoreLevel ? ` (${s.scoreLevel})` : ''}
    </span>
  );
}
