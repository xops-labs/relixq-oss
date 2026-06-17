<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# packages/npm — Relix-Q web libraries

The shared TypeScript packages the OSS web app (`apps/web`) consumes, published
to npm so any JavaScript consumer of a Relix-Q scan can reuse them.

## Package inventory

| Package | Surface |
|---|---|
| [`@relix-q/web-components`](web-components/) | `FindingTable` / `ScoreGauge` / `RuleBrowser` / `CodeViewer` + Badge / Card / Table / EmptyState primitives + `cn` / `format*` helpers + view-model types. Framework-agnostic: a `renderLink` prop and a highlighter-agnostic `CodeViewer`, so the package pulls in neither Next.js nor Shiki. |
| [`@relix-q/web-client`](web-client/) | `RelixQClient` SDK for the implemented OSS API scan/findings/score endpoints + typed errors (`RelixQApiError` / `AuthenticationRequiredError` / `RateLimitedError` / `ResponseValidationError`) + zod schemas for the OSS API DTOs and the `RelixQ.Contracts` `CryptoFinding` shape. |

## Build pipeline

Each package builds with `tsup` (esbuild-backed), producing dual ESM + CJS +
`.d.ts`. `react` / `react-dom` are peer deps of `web-components` (the consumer
brings its own); `zod` is a regular dependency of `web-client`. Neither is
bundled into `dist/`.

## Workspace wiring

The repo-root `package.json` declares a workspace over `packages/npm/*` and
`apps/web`. The web app consumes `@relix-q/web-components` directly (listed in
`transpilePackages` in `next.config.mjs`): pages import `FindingTable` /
`ScoreGauge` / Card / `EmptyState` straight from the package,
`components/ui.tsx` builds its app-local primitives on the shared `cn`, and
`lib/types.ts` maps API findings onto the package's `FindingRow` view model.
`@relix-q/web-client` is published for external JS consumers; the web app talks
to the API through its own cookie-forwarding server-side fetch helper instead.

**Build-order note:** the web app resolves the package via its built `dist/`
(tsup emits the `.d.ts`), so run `npm run build:packages` before building or
typechecking the web app — a fresh checkout typechecks the consumer red until
the package is built. Root scripts: `build:packages` (builds
`@relix-q/web-components`), `build:web`, `dev:web`; each package carries its own
`build` / `typecheck` scripts.

## Publishing

Each package publishes to npm with `npm publish --provenance` (SLSA L3
attestation). `@relix-q/web-client` carries two schema layers: DTO schemas for
the current OSS API (`apps/api/Dtos.cs`) and `CryptoFindingSchema`, the JS-side
mirror of the JSON Schema embedded in the `RelixQ.Contracts` .NET package. Keep
the DTO schemas in lockstep with `apps/api`, and keep `CryptoFindingSchema` in
lockstep with `RelixQ.Contracts`.
