<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->

# Cross-Vertical Crypto-Finding Fusion (Build #2b)

This package implements the algorithm that combines findings from N
independent detection channels (AST scanner, SBOM ingestor, future
TLS / cloud / runtime channels) into a single corroboration-weighted
finding stream with Bayesian confidence calibration.

## What's novel

The interesting part is **not** the inputs (those are `CryptoFinding` records
the scanner already produces). It is the **reconciliation
algorithm**, which becomes more precise as more detection channels
are added. Relix-Q already runs across:

| Channel       | Status (2026-06-10)                          |
|---------------|----------------------------------------------|
| AST source    | shipped — 31 programming languages           |
| Config / IaC  | shipped — 15 config/infra formats, plus the language-`any` fingerprints pack |
| SBOM          | shipped — `relixq scan deps` (Build #2a)     |
| TLS handshake | shipped — `relixq scan tls` (`tlsscanner`); emits canonical findings, not yet wired into fusion |
| Cloud KMS     | designed                            |
| Runtime trace | designed                            |

The fusion algorithm composes them all into the same Bayesian update
without per-channel adapter logic. Each new channel that ships
**strengthens** corroboration, because the breadth of independent
channels is what makes the fused confidence more robust.

## Conceptual model

Each detection channel produces zero or more findings. A finding is
characterised by `(algorithm_class, repository, channel)`. Two findings
from different channels are **corroborating** if they share
`(algorithm_class, repository)` — they are independent reports of the
same underlying crypto fact observed from different vantage points.

## Bayesian update

For an algorithm-class cluster with N corroborating channels, fused
confidence is computed by combining independent observations:

```
P(true) = 1 − Π_i (1 − P_i)
```

where `P_i` is the channel's per-finding confidence. The cap at 0.99
preserves an explicit-certainty marker (1.0 is reserved for human
review confirmation).

Not to be confused with the scanner's per-file hand-rolled promotion
(`scanner/promote.go`): that pass uses the same Bayesian combination
form (capped at 0.95) but corroborates weak detection-layer signals
**within a single file**, while fusion corroborates **across channels
at repository level** — the two are deliberately separate layers.

Examples:

| Channels firing                                    | Fused confidence |
|----------------------------------------------------|------------------|
| AST 0.85                                           | 0.85 (passthrough) |
| AST 0.85 + SBOM 0.70                               | 0.955            |
| AST 0.85 + SBOM 0.70 + TLS 0.95                    | 0.99 (capped)    |
| AST 0.85 + SBOM 0.70 + TLS 0.95 + Cloud 0.80       | 0.99 (capped)    |

## Why "algorithm_class" and not file-path?

Channels emit at different granularities. AST sees a source line in
`auth.py:42`. SBOM sees a single line in `requirements.txt`. TLS
sees a network endpoint. Cloud KMS sees a key ARN. There is no
natural file-path join key across channels.

The cross-channel join key is the **cryptographic primitive being
detected** — RSA, ECDSA, MD5, etc. — within the same repository. Two
reports of "RSA-related risk in repo X" from independent channels
corroborate each other regardless of which line numbers or endpoints
they point at.

## Algorithm class normalisation

Channels use different conventions:

| Channel  | Sample tag for RSA risk      |
|----------|------------------------------|
| AST      | `RSA-1024`, `RSA-2048`, `RSA-OAEP` |
| SBOM     | `RSA`                        |
| TLS      | `RSA_KEY_EXCHANGE` (future)  |
| Cloud    | `RSA_2048` (future)          |

`classKey()` canonicalises all of these to `RSA`. Without this step,
true corroborations look like non-matches. The canonicalisation:

1. Uppercase the input.
2. Filter generic catch-all tags (`TLS`, `CIPHER`, `HASH`, `HMAC`,
   `MAC`, `RNG`, `SIGNATURE`, `ANY`, `UNKNOWN`, `NA`) — they conflate
   too many primitives to be meaningful cluster keys.
3. Apply alias map (`3DES → DES`, `SHA-1 → SHA1`, etc.).
4. Strip variance suffixes: key-size (`-1024`, `-2048`, ...), curve
   (`-P256`, `-P384`, `-P521`, `-K1`), padding (`-OAEP`, `-PKCS1V15`,
   `-PSS`), digest (`-MD5`, `-SHA1`, ...).
5. Pass through recognised primary forms (`RSA`, `ECDSA`, `MD5`,
   `SHA256`, ML-KEM, ...).
6. Unknown / fixture-only / vertical-specific tags → drop to the
   passthrough path (single-channel cluster).

## Determinism

Output ordering is deterministic: by `CorroborationCount` desc, then
by `AlgorithmClass` asc. Two runs over the same inputs produce
byte-identical JSON. Critical for downstream consumers that compare
scorecards across runs.

## Cluster output shape

```go
type Cluster struct {
    AlgorithmClass     string           // "RSA"
    Channels           []string         // ["ast", "sbom"]
    CorroborationCount int              // len(Channels)
    FusedConfidence    float64          // Bayesian fusion result, ≤ 0.99
    Severity           Severity         // max severity across contributing findings
    Findings           []Finding        // every contributing record, for drill-down
}
```

## Edge cases

- **Single-channel passthrough.** If only one channel reports an
  algorithm class, the cluster's confidence is that channel's original
  value. Fusion is a no-op for unique observations.
- **Unclassified findings.** Findings without an extractable algorithm
  class (catch-all tags, vertical-specific algorithms not in the
  classKey table) flow through as single-finding clusters with a
  synthesised key `UNCLASSIFIED:<rule_id>`. They are preserved so the
  dashboard's total-findings count stays accurate.
- **Disagreement.** If channel A reports an algorithm class and
  channel B is silent on a class B normally detects, fusion treats
  this as single-channel passthrough — there is no "disagreement
  penalty" in v1. Future work (once the TLS / runtime channels are
  wired into fusion) will add an inverse update: AST reports RSA but
  the runtime channel never executes the RSA call site → confidence
  reduced.

## Demo result

Recorded run of an earlier build (which exposed
`-sbom` / `-fuse` flags; in this repo fusion is consumed as a library
by `../migrationplan`) against its own tree:

```
$ relixq-scan-code -path . -sbom /tmp/sbom.jsonl -fuse /tmp/fusion.json
scan complete         files_scanned=214 findings=1007
sbom ingest complete  findings=12
fusion                clusters=407  corroborated_clusters=3
```

**3 clusters were corroborated** — meaning the same primitive was
detected by both AST source-code scanning AND SBOM manifest analysis.
The top-ranked cluster:

```json
{
  "algorithm_class": "AES",
  "channels": ["ast", "sbom"],
  "corroboration_count": 2,
  "fused_confidence": 0.99,
  "severity": "high",
  "findings": [...]
}
```

The fused 0.99 confidence comes from combining AST's 0.95 confidence
on a CloudFormation `StorageEncrypted: false` rule with SBOM's 0.7
prior on the `golang.org/x/crypto` AES surface — independent
observations that compose via Bayes.

## What comes next

This algorithm is the **synthesis core** of the corroboration layer.
Build #3 (the blast-radius graph, `../graph`) is now shipped, and
`../migrationplan` joins `Cluster` records with per-finding impact
reports: a cluster with a high corroboration count lifts the work
item's priority score, so multi-channel corroboration weighs directly
into the migration plan.

Related synthesis layers:

- `../agility/README.md` — synthesis layer #1 (migration cost)
- `../sbom/README.md` — channel-N adapter pattern
- `../fusion/README.md` (this file) — synthesis layer #2 (corroboration calibration)
- `../graph/README.md` (Build #3) — synthesis layer #3 (transitive impact)

Together they form the cross-vertical Bayesian-fused
PQC-migration-readiness pipeline.
