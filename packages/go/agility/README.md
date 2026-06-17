<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->

# Crypto-Agility Scorecard (Build #1)

The Crypto-Agility Scorecard quantifies **how mechanically replaceable** the
cryptographic surface of a repository is — independent of which specific
algorithms it uses. It answers a question no commercial PQC scanner
currently answers:

> "Given that you have to migrate this crypto, how hard will it be?"

Two repositories may both depend on RSA-2048. The one with all crypto
behind a single `CryptoProvider` interface migrates in a day; the one
with 47 scattered direct-API call sites takes weeks. The scorecard
predicts which of those two you are looking at, **before** the migration
begins.

## Why this is novel

No commercial competitor we are aware of (IBM Quantum Safe Explorer,
SandboxAQ AQtive Guard, PQShield's tooling, CycloneDX CBOM consumers,
Snyk / Checkmarx / Semgrep generic SAST) ships a per-repository
**migration-cost predictor**. Existing scanners stop at inventory and
algorithm-strength scoring. The scorecard is a downstream synthesis
step that converts inventory into a forward-looking migration plan
estimate.

The novelty is the **algorithm**, not the inputs. The inputs (rule
findings) are produced by detectors most scanners already ship. The
synthesis step — four orthogonal dimensions, equal weighting,
deterministic table-driven banding, no model training — is the
contribution.

## Methodology

Total score = sum of four sub-metrics, each in `[0, 25]`. Final score
is in `[0, 100]`.

| Score | Grade        | Migration disposition                                    |
|-------|--------------|----------------------------------------------------------|
| 75–100 | **Agile**     | mechanical: library / config swap suffices              |
| 50–74  | **Manageable** | focused refactoring, single-sprint scope                |
| 25–49  | **Difficult**  | architectural changes; design-review required           |
| 0–24   | **Brittle**    | structural rewrite; crypto is fundamentally entangled   |

### Sub-metric 1: Library consolidation (0–25)

**Hypothesis:** Each additional crypto library is a separate migration
project. Different ecosystems ship PQC support at different paces;
coordinating cutover is the dominant cost in real migrations.

**Algorithm:** Count distinct libraries imported. A "library-surface
rule" is any rule whose ID contains `_IMPORT_`, `_REQUIRE_`, `_USE_`, or
`_OPEN_` (or ends with one of those markers). The rule pack convention
is consistent across the 31 programming-language packs.

| Distinct libs | Score |
|---------------|-------|
| 1             | 25    |
| 2             | 20    |
| 3–4           | 12    |
| 5+            | 5     |
| (no rules fired) | 18 (neutral)  |

### Sub-metric 2: Call-site concentration (0–25)

**Hypothesis:** Concentrated crypto is cheaper to refactor than scattered
crypto. Touching 3 files is dramatically faster than touching 40.

**Algorithm:** Compute the fraction of findings in the **top 3 files**
by finding-count. Configuration files (e.g. `nginx.conf`) count as
files for this purpose — concentration of TLS misconfiguration in one
config file is itself easier to migrate than the same misconfiguration
spread across many.

| Top-3 fraction | Score | Description                  |
|----------------|-------|------------------------------|
| ≥ 0.80         | 25    | highly concentrated          |
| ≥ 0.50         | 18    | concentrated                 |
| ≥ 0.30         | 12    | moderately scattered         |
| < 0.30         | 5     | highly scattered             |

### Sub-metric 3: Algorithm diversity (0–25)

**Hypothesis:** Migration cost scales with the number of distinct
primitives that must be replaced. Swapping `MD5 → SHA-3` is a
different plan from swapping `RSA-2048 → ML-KEM-768`.

**Algorithm:** Count distinct values of the `Algorithm` field across
findings, after filtering out catch-all tags (`TLS`, `CIPHER`, `HASH`,
`HMAC`, `MAC`, `RNG`, `SIGNATURE`). The catch-all filter is critical —
without it, a single `TLS` tag could conceal RSA + ECDHE + 3DES + AES
all rolled into one and would falsely reduce the apparent diversity.

| Distinct algos | Score |
|----------------|-------|
| ≤ 2            | 25    |
| 3–4            | 18    |
| 5–6            | 12    |
| 7+             | 5     |

### Sub-metric 4: Hardcoded-key prevalence (0–25)

**Hypothesis:** Hardcoded keys are the least agile of all crypto
surfaces. They are not swappable by changing an import or a config
flag — every embedded key requires generation of a replacement,
redistribution, and cutover. A repo with even 5% hardcoded-key
findings is structurally rigid.

**Algorithm:** Compute `hardcoded_count / total_count`. A finding is
"hardcoded" if its `Category` field contains `hardcoded` or its rule
ID contains `HARDCODED`.

| Hardcoded fraction | Score |
|--------------------|-------|
| 0                  | 25    |
| ≤ 0.02             | 20    |
| ≤ 0.05             | 12    |
| ≤ 0.10             | 5     |
| > 0.10             | 0     |

## Determinism and reproducibility

`Score()` is a pure function over the finding slice — same inputs,
always the same scorecard. Three implementation choices preserve this:

1. **No floating-point in band selection.** All thresholds are
   integer-keyed table lookups. The one floating-point computation
   (top-3 fraction) is consumed by a `case` ladder; the underlying
   comparison is monotonic, so floating-point representation noise
   cannot move a result across a band boundary in any realistic case.

2. **Sorted output.** `DistinctLibraries`, `DistinctAlgorithms`, and
   `TopFiles` are sorted before emission (alphabetic for the first
   two; by count desc / path asc for the third). Two runs over the
   same findings produce byte-identical JSON.

3. **No training / no thresholds inferred from data.** Every constant
   in the algorithm is human-set; the scorecard cannot drift between
   versions without an explicit code change.

## Edge cases

- **Zero findings.** Returns 100 / "Agile". A clean repo cannot be
  made harder to migrate. This is by design — a repo without
  detected crypto should not be penalized.

- **Findings without algorithm.** Counted for file-concentration
  and hardcoded-key prevalence, ignored for algorithm-diversity.
  Confidence in concentration-only scoring is unchanged because
  diversity is one of four independent sub-metrics.

- **Library-surface rules absent.** Some language packs may not yet
  ship `_IMPORT_` rules; in that case sub-metric 1 returns a neutral
  18 (not 25, not 5) to reflect missing signal rather than perfect
  consolidation. This keeps the metric honest as new language packs
  ship.

## Usage

CLI:

```
relixq-scan-code -path ./myrepo -agility ./agility.json
```

The scorecard is written as pretty-printed JSON alongside the standard
`findings.jsonl`. If `-agility` is omitted, scorecard computation is
skipped — the standalone scan path is single-purpose by default.

Library:

```go
import (
    "github.com/relix-q/relix-q/agility"
    "github.com/relix-q/relix-q/finding"
)

findings, _ := finding.ReadAll(file)
sc := agility.Score(findings)
fmt.Printf("score=%d grade=%s\n", sc.TotalScore, sc.Grade)
```

## Demo result

Recorded run against a larger deliberately-vulnerable corpus used for
integration testing — 72 files, 35 languages, 739 findings; that larger
corpus is not shipped in this repo, while this repo ships the smaller
labeled `fixtures/validation-corpus/` instead):

| Sub-metric              | Score | Diagnosis                                      |
|-------------------------|-------|------------------------------------------------|
| Library consolidation   | 5     | 35+ distinct libraries imported                |
| Call-site concentration | 5     | highly scattered (deliberate per-language test files) |
| Algorithm diversity     | 5     | 60+ distinct algorithm families                |
| Hardcoded-key prevalence | 12   | 2–5% hardcoded                                 |
| **Total**               | **27 / 100** | **Difficult**                            |

This is the expected diagnosis — the fixture corpus is built to
exercise every detector across every language, which by construction
is the antithesis of an "Agile" repository. The result confirms the
scorecard is sensitive to all four dimensions.

## What's distinctive

Relative to other PQC scanners (as of 2026-05-17):

- The synthesis function (four orthogonal dimensions → single 0..100
  score with deterministic banding) is not present in any public
  PQC scanner.
- The library-consolidation metric depending on rule-pack convention
  (`_IMPORT_` / `_REQUIRE_` / `_USE_` / `_OPEN_` markers) is a
  cross-language portable signal that compounds in value as language
  coverage breadth grows.
- The hardcoded-key penalty is a structural-rigidity dimension; existing
  scanners treat hardcoded keys as a severity input only, not as a
  signal about migration cost.

The scorecard is the **first** of three companion algorithms described
in Builds #2 (cross-vertical confidence fusion) and #3 (blast-radius
graph). Together they form a coherent migration-readiness pipeline.
