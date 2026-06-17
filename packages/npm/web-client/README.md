<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# @relix-q/web-client

Typed API SDK + zod schemas for talking to the current Relix-Q OSS API. The OSS
web app (`apps/web`) uses its own cookie-forwarding server-side fetch helper;
this package is the reusable JavaScript client for hosts that want a typed,
fetch-based API wrapper.

## Exports

| Export | Purpose |
|---|---|
| `RelixQClient` | Fetch-based SDK with bearer-token auth, retry-with-backoff on 429/5xx, zod-validated responses, and resource clients for the implemented OSS endpoints: project findings, project scans, scan status, and latest project score. |
| Typed errors | `RelixQApiError`, `AuthenticationRequiredError`, `RateLimitedError`, `ResponseValidationError`. |
| zod schemas | Current OSS API DTOs (`FindingDtoSchema`, `ScanRunSchema`, `ProjectScoreSchema`) plus `CryptoFindingSchema`, the JS-side mirror of `RelixQ.Contracts` for scanner output. |

## Schema source of truth

`CryptoFindingSchema` mirrors the JSON Schema embedded in the
`RelixQ.Contracts` .NET package and the scanner output shape. The live client
methods validate the DTOs served by `apps/api/Dtos.cs`: `FindingDtoSchema`,
`ScanRunSchema`, and `ProjectScoreSchema`. Keep those DTO schemas in lockstep
with `apps/api` whenever endpoints change.

The current OSS API does not expose finding detail, aggregate, status-patch, or
score-trend routes. Those belong to future/server variants and are intentionally
not represented as client methods here.

## Build

- `npm run build` -> `dist/index.{mjs,cjs,d.ts}` via tsup (dual ESM + CJS).
- Depends on `zod ^3.23.8`.
