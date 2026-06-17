import Link from 'next/link';
import { notFound } from 'next/navigation';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  InfoTip,
  ScoreGauge,
  SeverityBadge,
} from '@relix-q/web-components';
import { apiGet } from '@/lib/api';
import { requireUser } from '@/lib/session';
import { toFindingRow, type Finding, type Project } from '@/lib/types';
import { BreakdownPie } from './breakdown-pie';
import { DeleteProjectButton } from './delete-button';
import { ExportMenu } from './export-menu';
import { FindingsExplorer } from './findings-explorer';
import { ScanPanel } from './scan-panel';

export const dynamic = 'force-dynamic';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

export default async function ProjectDetailPage({ params }: { params: Promise<{ id: string }> }) {
  await requireUser();
  const { id } = await params;
  const project = await apiGet<Project>(`/api/v1/projects/${id}`);
  if (!project) notFound();

  const findings = (await apiGet<Finding[]>(`/api/v1/projects/${id}/findings`)) ?? [];
  const rows = findings.map(toFindingRow);
  const scan = project.latestScan;
  const succeeded = scan?.status === 'succeeded';

  // rows carry the normalized severity, so unknown values land in "medium"
  // here exactly as they do in the table below.
  const severityCounts: Record<string, number> = {};
  for (const row of rows) severityCounts[row.severity] = (severityCounts[row.severity] ?? 0) + 1;

  const algorithmCounts: Record<string, number> = {};
  for (const f of findings) {
    const algorithm = f.algorithm?.trim() || 'unknown';
    algorithmCounts[algorithm] = (algorithmCounts[algorithm] ?? 0) + 1;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <Link href="/projects" className="text-sm text-muted-foreground hover:text-foreground focus-ring rounded-sm">
            ← Projects
          </Link>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">{project.name}</h1>
          <p className="font-mono text-xs text-muted-foreground">
            {project.source.kind === 'git'
              ? `git · ${project.source.value}${project.hasToken ? ' · 🔒 token saved' : ''}`
              : project.source.kind === 'local'
                ? `local · ${project.source.value || '(all of scan-targets)'}`
                : project.source.kind === 'upload'
                  ? 'upload · uploaded .zip archive'
                  : `sample · ${project.source.value}`}
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex items-center gap-2">
            {succeeded && <ExportMenu projectId={project.id} />}
            <ScanPanel projectId={project.id} initiallyRunning={scan?.status === 'running'} />
          </div>
          <DeleteProjectButton projectId={project.id} />
        </div>
      </div>

      {succeeded && scan && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          <Card className="relative">
            <InfoTip
              className="absolute right-3 top-3"
              label="About the risk score"
              side="bottom"
              moreHref="/help#risk-score"
              text="Risk of the most severe finding in the latest scan, 0–100 (higher = worse). Each finding is scored on algorithm risk, usage criticality, exposure, and environment (scoring formula v1)."
            />
            <CardContent className="flex items-center justify-center py-6">
              <ScoreGauge value={scan.score ?? 0} mode="risk" label="Risk score" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-1.5">
                <CardTitle>Findings</CardTitle>
                <InfoTip
                  label="About findings"
                  side="bottom"
                  moreHref="/help#severity"
                  text="Weak or quantum-vulnerable crypto usages detected by the latest scan, broken down by rule-assigned severity."
                />
              </div>
            </CardHeader>
            <CardContent>
              <p className="font-mono text-3xl">{scan.findingCount}</p>
              <p className="text-sm text-muted-foreground">weak / quantum-vulnerable usages</p>
              {rows.length > 0 && (
                <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5">
                  {SEVERITY_ORDER.map((severity) =>
                    severityCounts[severity] ? (
                      <span key={severity} className="flex items-center gap-1.5">
                        <SeverityBadge value={severity} />
                        <span className="font-mono text-sm">{severityCounts[severity]}</span>
                      </span>
                    ) : null,
                  )}
                </div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-1.5">
                <CardTitle>Crypto agility</CardTitle>
                <InfoTip
                  label="About crypto agility"
                  side="bottom"
                  moreHref="/help#crypto-agility"
                  text="How mechanically easy this repo's crypto is to migrate, 0–100 (higher = better). Four equally-weighted sub-metrics: library consolidation, call-site concentration, algorithm diversity, hardcoded-key prevalence. 75+ Agile · 50–74 Manageable · 25–49 Difficult · below 25 Brittle."
                />
              </div>
            </CardHeader>
            <CardContent>
              <p className="font-mono text-3xl">{scan.agilityScore ?? '—'}</p>
              <p className="text-sm text-muted-foreground">{scan.agilityGrade ?? 'not computed'}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-1.5">
                <CardTitle>Files scanned</CardTitle>
                <InfoTip
                  label="About files scanned"
                  side="bottom"
                  moreHref="/help#scanning"
                  text="Files analyzed by the latest scan, grouped by detected language. Languages beyond the palette are grouped into 'other'."
                />
              </div>
            </CardHeader>
            <CardContent>
              {scan.languages && Object.keys(scan.languages).length > 0 ? (
                <BreakdownPie
                  total={scan.filesScanned ?? 0}
                  data={scan.languages}
                  ariaLabel={`${scan.filesScanned ?? 0} files scanned by language`}
                />
              ) : (
                <>
                  <p className="font-mono text-3xl">{scan.filesScanned ?? '—'}</p>
                  <p className="text-sm text-muted-foreground">language breakdown unavailable</p>
                </>
              )}
            </CardContent>
          </Card>
          {rows.length > 0 && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-1.5">
                <CardTitle>Findings by algorithm</CardTitle>
                <InfoTip
                  label="About findings by algorithm"
                  side="bottom"
                  moreHref="/help#nist-standards"
                  text="Latest-scan findings grouped by the detected cryptographic algorithm. Findings a rule could not attribute to a specific algorithm are counted as 'unknown'."
                />
              </div>
            </CardHeader>
            <CardContent>
              <BreakdownPie
                total={findings.length}
                data={algorithmCounts}
                ariaLabel={`${findings.length} findings grouped by algorithm`}
              />
            </CardContent>
          </Card>
          )}
        </div>
      )}

      {scan?.status === 'failed' && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Last scan failed: {scan.error ?? 'unknown error'}
        </p>
      )}

      {rows.length > 0 ? (
        <FindingsExplorer findings={findings} />
      ) : (
        <EmptyState
          title={succeeded ? 'No findings' : 'No scan yet'}
          description={
            succeeded
              ? 'This scan produced no findings against the OSS community rule pack.'
              : 'Run a scan to detect weak and quantum-vulnerable cryptography.'
          }
        />
      )}
    </div>
  );
}
