<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->

# Unified Migration Plan

Package `migrationplan` (`github.com/relix-q/relix-q/migrationplan`) is
the deterministic synthesis layer for the scanner's migration-readiness
portfolio. It does not call an LLM. It joins the scanner's existing
auditable signals into one prioritised JSON work list:

- [`../agility`](../agility/) answers how mechanically hard the
  repository is to migrate.
- [`../fusion`](../fusion/) answers how strongly independent channels
  corroborate a finding's algorithm class.
- [`../graph`](../graph/) answers how wide the per-finding blast
  radius is.

The output schema version is `relixq.migration_plan.v1`. It contains
summary counters, repository agility, input counts, prioritised work
items, and compact execution phases.

## Usage

In this repo the planner is a library — the OSS `relixq-scan-code`
binary exposes only `-agility`, so callers compose the inputs
themselves (the missing ones are recomputed or defaulted):

```go
plan := migrationplan.Build(migrationplan.Input{
    ASTFindings:    findings,        // required signal source
    SBOMFindings:   sbomFindings,    // optional — sbom.Ingest output
    Scorecard:      scorecard,       // optional — recomputed from ASTFindings if empty
    FusionClusters: clusters,        // optional — fusion.Fuse output
    ImpactReports:  impacts,         // optional — graph.Impact output
})
```

`Build` is pure and deterministic: work items are sorted by priority
score, then blast radius, then file path / line / rule id, and the
result is stable across runs.

## Priority Score

Each work item receives a deterministic 0..100 score composed from:

- severity of the source finding;
- fused confidence plus corroboration count;
- blast-radius band and score;
- repository agility penalty, where brittle repositories lift priority.

This keeps the launch demo grounded: the plan is explainable from the
same JSON artifacts that the scanner already emits.
