import type { FindingRow } from '@relix-q/web-components';

export interface User {
  id: string;
  email: string;
  displayName: string;
}

export interface ProjectSource {
  kind: string; // "sample" | "git" | "local" | "upload"
  value: string;
  token?: string; // write-only on create; never returned by the API
}

export interface ScanRun {
  id: string;
  projectId: string;
  status: string; // running | succeeded | failed
  startedAt: string;
  completedAt: string | null;
  findingCount: number;
  score: number | null;
  scoreLevel: string | null;
  agilityScore: number | null;
  agilityGrade: string | null;
  filesScanned: number | null;
  languages: Record<string, number> | null;
  error: string | null;
}

export interface Project {
  id: string;
  slug: string;
  name: string;
  description: string;
  source: ProjectSource;
  hasToken: boolean;
  createdAt: string;
  latestScan: ScanRun | null;
}

export interface Finding {
  id: string;
  ruleId: string;
  language: string;
  algorithm: string | null;
  severity: string;
  filePath: string;
  lineNumber: number;
  snippet: string | null;
  category: string | null;
  message: string | null;
  recommendation: string | null;
  score: number;
  scoreLevel: string;
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

/** Adapt an API Finding to the structural FindingRow the shared table renders. */
export function toFindingRow(f: Finding): FindingRow {
  const severity = SEVERITIES.has(f.severity) ? f.severity : 'medium';
  return {
    findingId: f.id,
    serviceId: null,
    algorithm: f.algorithm ?? '—',
    usageType: 'unknown',
    filePath: f.filePath,
    lineNumber: f.lineNumber,
    environment: 'unknown',
    exposure: 'unknown',
    severity: severity as FindingRow['severity'],
    riskScore: f.score,
    confidence: 1,
    owner: null,
    status: 'open',
    lastSeenDate: new Date().toISOString(),
  };
}
