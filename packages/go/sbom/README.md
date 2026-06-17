<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->

# SBOM Crypto-Dependency Ingest (Build #2a)

This package converts dependency manifests (`requirements.txt`,
`package.json`, `go.mod`, etc.) into the canonical `CryptoFinding`
schema by looking each package up against a static knowledge base of
crypto-relevant libraries. It powers `relixq scan deps` (the CLI runs
`sbom.Ingest` in-process — no scanner subprocess), and the output flows
into the cross-vertical fusion algorithm ([`../fusion`](../fusion/)) as
a **second independent detection channel** — the foundation of Build
#2's cross-channel corroboration.

## Why it exists

Build #2 (cross-vertical confidence calibration)
requires at least two independent detection channels. The static-code
scanner is channel 1 (already deployed across 31 programming languages
+ 15 config/infra formats, plus the language-`any` fingerprints pack).
The SBOM ingestor is channel 2 — it sees crypto risk from the manifest
side, independent of source code analysis.

Both channels emit `finding.Finding` records, so the fusion algorithm
treats them as equal first-class records. This is the *novelty*: the
same canonical schema lets channels of completely different observation
shapes (AST node vs. dependency manifest entry vs. TLS handshake vs.
cloud KMS API vs. runtime trace) participate in the same Bayesian
fusion without any per-channel adapter logic.

## Coverage (v1)

Three ecosystems, 35 curated packages (14 Python / 11 npm / 10 Go):

| Ecosystem  | Manifest formats supported                          |
|------------|-----------------------------------------------------|
| Python     | `requirements.txt`, `requirements-*.txt`, `Pipfile`, `pyproject.toml` (both PEP-621 and Poetry sections) |
| JavaScript | `package.json` (dependencies, devDependencies, peerDependencies, optionalDependencies) |
| Go         | `go.mod` (require single + block form, indirect deps included) |

Adding ecosystems is mechanical: drop a new parser into
`manifests.go`, add a route to `ParseManifest`, populate
`knowledgeBase` entries in `knowledge.go`. The fusion algorithm needs
no changes.

## Knowledge base shape

```go
type CryptoLib struct {
    PackageName string
    Ecosystem   Ecosystem    // python / javascript / go
    Algorithms  []string     // ["RSA", "ECDSA", "AES", ...]
    Severity    string
    Category    string
    Deprecated  bool         // bumps severity, tags message
    PQReady     bool         // marks library as a migration TARGET, not risk
    Notes       string       // free-text guidance shown in dashboard
}
```

The `Algorithms` field causes a **deliberate fan-out**: a library
covering RSA + ECDSA + AES + SHA-1 produces four findings (one per
primitive), so that fusion's Bayesian update can corroborate each
primitive independently against the AST channel. Without the fan-out,
fusion would have to learn the library's algorithm set at runtime —
defeating the deterministic-by-construction design.

## Algorithm

```
Ingest(repoRoot, scanJobID) []Finding:
    walk repoRoot:
        skip noisy dirs (node_modules, vendor, .venv, __pycache__)
        if file is a known manifest:
            deps = ParseManifest(file)
            for dep in deps:
                lib = Lookup(dep.Ecosystem, dep.PackageName)
                if lib != nil:
                    for algo in lib.Algorithms:
                        emit Finding {
                            RuleID:        "SBOM_<ECO>_<PKG>_<ALGO>"
                            Algorithm:     algo
                            FilePath:      dep.Manifest
                            LineNumber:    dep.LineNumber
                            Confidence:    0.7  # SBOM-only prior
                            QuantumSafety: PQReady ? quantum_safe
                                                   : algorithmQuantumSafety(algo)
                        }
```

`quantum_safety` is assigned **per algorithm**, not per library, via
`algorithmQuantumSafety()` in `knowledge.go` — the same three-tier
taxonomy the code rules use:

- MD5 / MD4 / MD2 / SHA-1 / RC4 / RC2 / single DES / RIPEMD →
  `classically_broken` (exploitable today, no quantum computer needed);
- 3DES / AES-128 / Blowfish → `grover_weakened` (Grover-tier symmetric
  margin loss);
- everything else (RSA, ECDSA, DH, X25519, ED25519, X509, TLS, SSH, …)
  → `vulnerable` (Shor-broken asymmetric / classical key exchange).

`PQReady` entries (e.g. Cloudflare CIRCL) override the whole fan-out to
`quantum_safe` and are messaged as **migration targets, not risks** —
a PQC library must never be risk-tagged.

The 0.7 baseline confidence reflects that a dependency being declared
doesn't prove the depending code actually uses every primitive the
library offers. Fusion ratchets this when AST corroborates — see
[`../fusion/README.md`](../fusion/README.md).

## Determinism

`Ingest()` is deterministic over manifest contents and the knowledge
base. The walk order is `filepath.WalkDir`'s lexical order; manifest
parsers emit deps in source order; per-dep fan-out iterates the
algorithm slice in declaration order. Two runs over the same repo
produce identical findings.

## Demo result

The CLI entry point is `relixq scan deps [path]`. Recorded run of the
earlier build (which exposed a `-sbom` flag on the
engine binary) against its own tree:

```
$ relixq-scan-code -path . -sbom /tmp/relixq-sbom.jsonl
sbom ingest complete  manifests_walked=ok  findings=12
```

The 12 findings came from that tree's `go.mod` —
`golang.org/x/crypto` (X25519 / ED25519 / SSH / ARGON2 / ...), plus
the `github.com/smacker/go-tree-sitter` reference. Each known-crypto
dependency produces one finding per primitive.

## Why this channel matters

This package alone is commodity work — manifest parsers and library
inventories are well-trodden. Its value lives in the **fusion**
algorithm (Build #2b) that consumes this channel jointly with the AST
channel. SBOM ingest is the load-bearing **second channel** that makes
cross-channel corroboration possible.

Two design points carry the weight:

1. The same canonical `CryptoFinding` schema is portable across
   completely different observation shapes (AST source location ↔
   manifest declaration), enabling cross-channel join keys.
2. The per-algorithm fan-out is a deliberate pre-processing step that
   makes per-primitive corroboration the join unit, not per-library
   corroboration. This matters because libraries cover multiple
   primitives and only some of them might be used by the depending
   code.
