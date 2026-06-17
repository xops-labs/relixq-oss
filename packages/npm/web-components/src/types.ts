// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// View-model types for the presentational components in this package. These
// describe only the fields the components render — they are intentionally a
// structural subset of the richer application finding model, so a host app's
// CryptoFinding satisfies them without conversion. The canonical wire shape
// (snake_case, emitted by the scanners) lives in @relix-q/web-client.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus =
  | 'open'
  | 'fixed'
  | 'false_positive'
  | 'accepted_risk'
  | 'in_progress';

export type Exposure = 'internal' | 'external' | 'partner' | 'unknown';
export type Environment = 'prod' | 'staging' | 'dev' | 'test' | 'unknown';

export type UsageType =
  | 'signing'
  | 'key_exchange'
  | 'encryption_at_rest'
  | 'encryption_in_transit'
  | 'hashing'
  | 'certificate'
  | 'unknown';

/**
 * The fields a finding row / detail panel renders. A subset of the host app's
 * finding model — kept narrow so components stay reusable across any
 * consuming web app.
 */
export interface FindingRow {
  findingId: string;
  serviceId: string | null;
  algorithm: string;
  usageType: UsageType;
  filePath: string;
  lineNumber: number;
  environment: Environment;
  exposure: Exposure;
  severity: Severity;
  riskScore: number;
  confidence: number;
  owner: string | null;
  status: FindingStatus;
  lastSeenDate: string;
}

/** One bucket of an aggregate query (by service, algorithm, language, …). */
export interface AggregateBucket {
  key: string;
  label: string;
  count: number;
  criticalCount: number;
}

/** A single point on a readiness-score trend line. */
export interface TrendPoint {
  date: string;
  score: number;
}

export type QuantumSafety =
  | 'vulnerable'
  | 'grover_weakened'
  | 'classically_broken'
  | 'hybrid'
  | 'quantum_safe'
  | 'unknown';

/**
 * One row in the rule-pack browser. A structural subset of a scanner rule —
 * just the fields the browser renders. Works for any loaded rule pack.
 */
export interface RuleSummary {
  ruleId: string;
  title: string;
  language: string;
  severity: Severity;
  quantumSafety: QuantumSafety;
  /** Pack the rule belongs to (e.g. "go", "python", "k8s"). */
  pack: string;
  description?: string;
}
