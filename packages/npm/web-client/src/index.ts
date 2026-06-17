// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Typed API SDK + zod schemas for talking to the Relix-Q OSS API. The package
// also exports the JS-side mirror of the CryptoFinding JSON Schema embedded in
// RelixQ.Contracts for consumers that handle scanner output directly.

export const PACKAGE_VERSION = '0.1.0';

export { RelixQClient } from './client';
export type { RelixQClientOptions, RequestOptions } from './client';

export {
  RelixQApiError,
  AuthenticationRequiredError,
  RateLimitedError,
  ResponseValidationError,
} from './errors';

export {
  // schemas
  CryptoFindingSchema,
  FindingDtoSchema,
  FindingsPageSchema,
  ScanRunSchema,
  ProjectScoreSchema,
  ReadinessScoreSchema,
  TrendPointSchema,
  AggregateBucketSchema,
  SeveritySchema,
  QuantumSafetySchema,
  DeltaStateSchema,
  ScanStatusSchema,
  TriggerSourceSchema,
} from './schemas';

export type {
  // inferred types
  CryptoFinding,
  FindingDto,
  FindingsPage,
  ScanRun,
  ProjectScore,
  ReadinessScore,
  TrendPoint,
  AggregateBucket,
  Severity,
  QuantumSafety,
  DeltaState,
  ScanStatus,
  TriggerSource,
} from './schemas';
