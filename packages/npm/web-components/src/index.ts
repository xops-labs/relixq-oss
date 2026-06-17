// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Shared, framework-agnostic React components for any consumer of a Relix-Q
// scan, including the OSS web app.
// Tailwind-token styled; bring your own `react` / `react-dom` (peer deps).

export const PACKAGE_VERSION = '0.1.0';

// Headline components
export { FindingTable } from './components/finding-table';
export type { FindingTableProps, RenderLink } from './components/finding-table';
export { ScoreGauge } from './components/score-gauge';
export type { ScoreGaugeProps } from './components/score-gauge';
export { RuleBrowser } from './components/rule-browser';
export type { RuleBrowserProps } from './components/rule-browser';
export { CodeViewer } from './components/code-viewer';
export type { CodeViewerProps } from './components/code-viewer';

// UI primitives
export { Badge, SeverityBadge } from './ui/badge';
export type { BadgeProps } from './ui/badge';
export {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from './ui/card';
export {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from './ui/table';
export { EmptyState, SkeletonRow } from './ui/empty-state';
export { InfoTip } from './ui/info-tip';
export type { InfoTipProps } from './ui/info-tip';

// Presentational helpers
export { cn, formatRelative, formatNumber, formatDuration } from './lib/cn';

// View-model types
export type {
  Severity,
  FindingStatus,
  Exposure,
  Environment,
  UsageType,
  FindingRow,
  AggregateBucket,
  TrendPoint,
  QuantumSafety,
  RuleSummary,
} from './types';
