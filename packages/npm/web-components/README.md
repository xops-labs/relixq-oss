<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# @relix-q/web-components

Framework-agnostic React components for rendering a Relix-Q scan. Used by the
OSS web app (`apps/web`) and reusable by any consumer of a Relix-Q server.

## Exports

| Export | Purpose |
|---|---|
| `<FindingTable />` | Findings with severity badges + score gauges — the core UX of every Relix-Q view. Takes a `renderLink` prop so the host supplies its own router link (no Next.js dependency). |
| `<ScoreGauge />` | 0..100 risk-score visual; maps onto `RelixQ.Scoring` output. |
| `<RuleBrowser />` | Browse the active rule pack. Color-codes each rule's quantum-safety tier — all six values, with `grover_weakened` rendered "Grover-weakened" (medium tone) and `classically_broken` rendered "classically broken" (high tone). |
| `<CodeViewer />` | Syntax-highlighted finding context. Highlighter-agnostic: takes pre-rendered `html` (or raw `code`), so it pulls in no Shiki dependency. |
| Badge / `SeverityBadge`, Card*, Table*, `EmptyState` / `SkeletonRow` | UI primitives + severity color tokens. |
| `cn` / `format*` helpers, view-model types | Shared utilities and the finding/score/rule view models (`FindingRow`, `RuleSummary`, the six-value `QuantumSafety` union, …). |

## Framework-agnostic by design

The package depends on neither Next.js nor a specific syntax highlighter:
`FindingTable` injects links via `renderLink`, and `CodeViewer` renders
caller-supplied markup. `apps/web` wires the Next `<Link>` for tables and uses
its own lightweight snippet highlighter in the finding details panel; hosts that
want Shiki can pre-highlight server-side and pass the rendered HTML to
`CodeViewer`.

## Build

- `npm run build` → `dist/index.{mjs,cjs,d.ts}` via tsup (dual ESM + CJS).
- Peer deps `react ^18.3.0`, `react-dom ^18.3.0` — the consumer brings its own.
