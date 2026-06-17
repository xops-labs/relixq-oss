<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->

# Crypto Blast-Radius Graph (Build #3)

The Crypto Blast-Radius Graph answers a question no commercial PQC
scanner currently answers:

> "If you migrate this crypto finding, how many other files in your
>  repository are transitively affected?"

A finding of "RSA-1024 keypair generation in `crypto-core.go`" is not
the same risk in two different repositories. If `crypto-core.go` has
4 importers and those 4 each have 12 importers, migrating the
finding's file forces a coordinated update across ~50 files. If
`crypto-core.go` has zero importers (it is a leaf script), migration
is a single-file change. **Same finding, vastly different migration
cost** — and no other PQC scanner surfaces this distinction.

## How it fits

This is the third of three companion algorithms in the
migration-readiness pipeline:

| Build | Algorithm                       | Question answered                         |
|-------|----------------------------------|-------------------------------------------|
| #1    | Crypto-Agility Scorecard         | How hard will migration be? (per repo)    |
| #2    | Cross-Vertical Bayesian Fusion   | How sure are we this is a real risk?      |
| #3    | Crypto Blast-Radius Graph        | How wide is the impact per finding?       |

Together they convert a flat finding list into a forward-looking
migration plan: each finding carries its own *agility band* (from #1),
*corroboration count* (from #2), and *blast radius* (this build).

## Algorithm

### Graph construction

`BuildFromRepo(repoRoot)` walks the repository, registers every
non-noise file as a graph node, and extracts directed import edges
from supported languages. Noise dirs skipped: `node_modules`,
`vendor`, `.venv`, `.git`, `__pycache__`, `target`, `dist`, `build`,
`.idea`, `.vscode`.

Supported import extractors (v1):

| Language       | Extractor                                          |
|----------------|----------------------------------------------------|
| Go             | `import "..."` single + `import (...)` block       |
| Python         | `import X`, `from X import Y` (sub-module resolved), `from . import X` relative |
| JS / TS        | ES `import ... from '...'` + CommonJS `require('...')`, with full Node-style extension resolution (.js/.jsx/.mjs/.cjs/.ts/.tsx/.d.ts + `/index.<ext>`) |

Files in unsupported languages still register as nodes. Their
blast-radius computation falls back to **same-directory neighbours**
only — a useful proxy for tight coupling that doesn't require
language-specific parsing. Adding a new extractor is mechanical (one
function in `importers.go`).

### Per-finding blast-radius computation

For each finding `f` at `f.FilePath`:

```
direct      = |{ files that import f.FilePath directly }|
transitive  = |{ files that transitively import f.FilePath, full closure with cycle detection }|
same_dir    = |{ files in the same directory as f.FilePath, excluding self }|

blast_radius = 3 × transitive + direct + same_dir
```

The `3×` weighting on `transitive` reflects that transitive importers
represent **semantic dependency** (the code uses something the
crypto-bearing file exports). `same_dir` is the weakest signal —
directory co-location doesn't prove coupling but is a useful
fallback when import edges weren't resolved.

The formula is intentionally simple. Like the agility scorecard,
it's transparent and table-explainable, not tuned to a benchmark.

### Migration cost bands

`blast_radius` is binned into deterministic, integer-keyed bands:

| Score      | Band          | Migration disposition                       |
|------------|---------------|---------------------------------------------|
| 0..9       | Low           | leaf file or near-leaf; migrate in isolation |
| 10..49     | Medium        | a handful of importers; coordinate review   |
| 50..199    | High          | widely used; needs migration window         |
| 200+       | Catastrophic  | structural pillar; phased rollout required  |

## Output shape

Per-finding `ImpactReport`:

```json
{
  "file_path": "internal/detectors/regex/regex_test.go",
  "rule_id":   "CONFIG_HARDCODED_RSA_PRIVATE_KEY",
  "algorithm": "RSA",
  "severity":  "critical",
  "direct_importers":     2,
  "transitive_importers": 36,
  "same_directory_files": 1,
  "blast_radius":         111,
  "migration_cost_band":  "High",
  "affected_files":       [ "...", "..." ]
}
```

Output is sorted by `BlastRadius` desc, then `FilePath` asc — the
dashboard's "most impactful migration target" view is reproducible
across runs.

## Determinism

- Graph build is single-threaded over `filepath.WalkDir`'s lexical
  order; same repo → same node set → same edge set.
- BFS for `TransitiveImporters` is bounded by visited-set, with
  cycle detection. Iteration order over map keys is randomised
  (Go map semantics) but the output is sorted before being returned,
  so consumers see deterministic order regardless.
- Band thresholds are integer-keyed; no floating-point in the
  classification path.

## Demo result

Recorded run of an earlier build (which exposed a
`-blast-radius` flag; in this repo the graph is consumed as a library —
`BuildFromRepo` + `Impact` — by `../migrationplan`) against its own tree:

```
$ relixq-scan-code -path . -blast-radius /tmp/relixq-blast.json
scan complete       files_scanned=217 findings=1007
blast-radius written graph_nodes=335 graph_edges=316
                     catastrophic=0 high=1 medium=0 low=1006
```

**Top result:** `internal/detectors/regex/regex_test.go` —
`blast_radius=111` (High band), 36 transitive importers. The
finding (`CONFIG_HARDCODED_RSA_PRIVATE_KEY` in a test fixture) sits
inside the `regex` package, which is imported by every AST detector
and both `main.go` files. Migrating the underlying issue would
trigger a cascade.

**Mid-tier:** `internal/sbom/knowledge.go` — `blast_radius=8` (Low
band). The finding sits in a leaf-ish module imported only by the
CLI; migration is mostly local.

This is the core demonstration: same crypto severity, vastly different
migration cost, surfaced quantitatively per finding.

## What this composes with

`graph.Impact()` consumes the built `*Graph` plus plain
`[]finding.Finding`, but the signals compose higher when wired up:

- **From Build #1:** repo-level agility band lets the dashboard frame
  blast radius in context ("a finding with Catastrophic blast radius
  in an Agile repo is still tractable; in a Brittle repo it's a
  multi-quarter migration").
- **From Build #2:** fusion clusters mark which findings are
  multi-channel corroborated. A cluster with both AST and SBOM
  channels firing AND a high blast radius is the highest-priority
  migration target — high confidence × high impact.

`../migrationplan` now produces the unified "migration plan"
JSON that joins all three signals into a single prioritised work list.
Related specifications:

- `../agility/README.md` — synthesis layer #1 (migration cost)
- `../sbom/README.md`    — channel-N adapter pattern
- `../fusion/README.md`  — synthesis layer #2 (the corroboration core)
- `../graph/README.md`   — synthesis layer #3 (this file)

## Limitations and future work

1. **Limited language coverage for import parsing.** Go / Python /
   JS / TS only in v1. Other languages contribute graph nodes but
   no edges. Adding Java (Maven `pom.xml` + `import`), Ruby
   (`require` / `Gemfile`), Rust (`use` + `Cargo.toml`) is the
   mechanical next step.
2. **Heuristic Go import resolution.** Last-segment-of-import-path
   substring match. Works on conventional layouts (this repo); fails
   on creative module naming. A future version would consume the
   project's `go.mod` to resolve module paths properly.
3. **No cross-repo edges.** Blast radius is repo-local. Multi-repo
   migration impact (e.g. "what services depend on the auth library
   I'm migrating") needs the LLD-14 graph DB, not in scope here.
4. **No call-graph awareness.** Edges are file-to-file imports, not
   function-to-function calls. A file may import another and use
   only a non-crypto function from it; we count it as a dependency
   either way. AST-based call extraction is a future precision lift.

None of these block the core contribution — graph traversal
plus weighted score plus deterministic banding; the input precision
can grow over time.
