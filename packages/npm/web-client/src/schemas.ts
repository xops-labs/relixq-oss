// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// JS-side mirror of the canonical wire schema embedded in RelixQ.Contracts
// (packages/dotnet/RelixQ.Contracts/schemas/CryptoFinding.json). Property
// names are snake_case to match scanner output 1:1, so a finding written by
// the Go scanner (packages/go/finding) → scored by RelixQ.Scoring → served via
// API is a single shape across Go, C#, and TypeScript. Keep in lockstep with
// the JSON Schema — this is the source of truth on the JS side.
import { z } from 'zod';

export const SeveritySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof SeveritySchema>;

export const QuantumSafetySchema = z.enum([
  'vulnerable',
  'grover_weakened',
  'classically_broken',
  'hybrid',
  'quantum_safe',
  'unknown',
]);
export type QuantumSafety = z.infer<typeof QuantumSafetySchema>;

export const DeltaStateSchema = z.enum(['new', 'modified', 'removed', '']);
export type DeltaState = z.infer<typeof DeltaStateSchema>;

/**
 * Canonical wire shape for one crypto finding emitted by a Relix-Q scanner
 *. Mirrors RelixQ.Contracts.CryptoFinding and the Go
 * finding.Finding struct. Required fields match the JSON Schema `required`
 * list; optional fields are the enrichment context.
 */
export const CryptoFindingSchema = z.object({
  finding_id: z.string().uuid(),
  scan_job_id: z.string(),
  rule_id: z.string(),
  language: z.string(),
  algorithm: z.string().optional(),
  usage_type: z.string().optional(),
  quantum_safety: QuantumSafetySchema,
  severity: SeveritySchema,
  key_size: z.number().int().nullable().optional(),
  file_path: z.string(),
  line_number: z.number().int().min(0),
  column: z.number().int().min(0),
  snippet: z.string(),
  snippet_context: z.array(z.string()).optional(),
  confidence: z.number().min(0).max(1),
  category: z.string().optional(),
  message: z.string().optional(),
  recommendation: z.string().optional(),
  references: z.array(z.string()).optional(),
  cwe: z.array(z.number().int()).optional(),
  git_blame_author: z.string().optional(),
  git_blame_commit: z.string().optional(),
  detected_at: z.string().datetime({ offset: true }),
  delta_state: DeltaStateSchema.optional(),
});
export type CryptoFinding = z.infer<typeof CryptoFindingSchema>;

/** Finding DTO returned by the current OSS API (`apps/api/Dtos.cs`). */
export const FindingDtoSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  language: z.string(),
  algorithm: z.string().nullable(),
  severity: SeveritySchema,
  filePath: z.string(),
  lineNumber: z.number().int().min(0),
  snippet: z.string().nullable(),
  category: z.string().nullable(),
  message: z.string().nullable(),
  recommendation: z.string().nullable(),
  score: z.number().int().min(0).max(100),
  scoreLevel: z.string(),
});
export type FindingDto = z.infer<typeof FindingDtoSchema>;

/** Legacy/future paged scanner-output shape; current OSS findings return `FindingDto[]`. */
export const FindingsPageSchema = z.object({
  items: z.array(CryptoFindingSchema),
  total: z.number().int().min(0),
  page: z.number().int().min(1),
  page_size: z.number().int().min(1),
});
export type FindingsPage = z.infer<typeof FindingsPageSchema>;

export const ScanStatusSchema = z.enum(['running', 'succeeded', 'failed']);
export type ScanStatus = z.infer<typeof ScanStatusSchema>;

export const TriggerSourceSchema = z.enum(['manual', 'pr', 'scheduled', 'cli', 'api']);
export type TriggerSource = z.infer<typeof TriggerSourceSchema>;

/** Scan DTO returned by the current OSS API (`apps/api/Dtos.cs`). */
export const ScanRunSchema = z.object({
  id: z.string(),
  projectId: z.string(),
  status: ScanStatusSchema,
  startedAt: z.string().datetime({ offset: true }),
  completedAt: z.string().datetime({ offset: true }).nullable(),
  findingCount: z.number().int().min(0),
  score: z.number().int().min(0).max(100).nullable(),
  scoreLevel: z.string().nullable(),
  agilityScore: z.number().int().min(0).max(100).nullable(),
  agilityGrade: z.string().nullable(),
  filesScanned: z.number().int().min(0).nullable(),
  languages: z.record(z.number().int().min(0)).nullable(),
  error: z.string().nullable(),
});
export type ScanRun = z.infer<typeof ScanRunSchema>;

/** Latest project score returned by `GET /api/v1/scores/projects/{id}`. */
export const ProjectScoreSchema = z.object({
  score: z.number().int().min(0).max(100).nullable(),
  level: z.string().nullable(),
  findingCount: z.number().int().min(0),
  agilityScore: z.number().int().min(0).max(100).nullable().optional(),
  agilityGrade: z.string().nullable().optional(),
  scanId: z.string().optional(),
});
export type ProjectScore = z.infer<typeof ProjectScoreSchema>;

/** Future/server analytics shape; current OSS score endpoint returns `ProjectScore`. */
export const ReadinessScoreSchema = z.object({
  scope: z.enum(['organization', 'project', 'service', 'application']),
  scope_id: z.string(),
  score: z.number().min(0).max(100),
  delta_30d: z.number(),
  as_of: z.string().datetime({ offset: true }),
});
export type ReadinessScore = z.infer<typeof ReadinessScoreSchema>;

/** Future/server analytics shape; not exposed by the current OSS API. */
export const TrendPointSchema = z.object({
  date: z.string(),
  score: z.number().min(0).max(100),
});
export type TrendPoint = z.infer<typeof TrendPointSchema>;

/** Future/server analytics shape; not exposed by the current OSS API. */
export const AggregateBucketSchema = z.object({
  key: z.string(),
  label: z.string(),
  count: z.number().int().min(0),
  critical_count: z.number().int().min(0),
});
export type AggregateBucket = z.infer<typeof AggregateBucketSchema>;
