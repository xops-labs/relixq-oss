<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# packages/go — the Relix-Q scanner engine and Go libraries

Go module `github.com/relix-q/relix-q`. This is the heart of the OSS scanner:
the walk → route → detect → score pipeline, the `relixq` CLI, the standalone
`relixq-scan-code` engine binary, and the analytics libraries. The `docker
compose` app shells the engine; the CLI and libraries are usable on their own.

```bash
# build the engine + CLI
go build -o relixq           ./cmd/relixq
go build -o relixq-scan-code ./cmd/relixq-scan-code

# scan a tree (regex floor + pure-Go AST; add CGO for tree-sitter)
./relixq-scan-code -path /repo -rules ./rules-community -output findings.jsonl
```

## Binaries (`cmd/`)

| Binary | Purpose |
|---|---|
| [`cmd/relixq`](cmd/relixq/) | The user-facing CLI: `scan`, `scan deps`, `scan tls`, `baseline`, `report`, `rules`, `login`, … Output as text / JSON / JSONL / **SARIF** / markdown / HTML. |
| [`cmd/relixq-scan-code`](cmd/relixq-scan-code/) | Standalone scan engine: walks a path, applies the rule packs, writes JSONL findings (optionally a Crypto-Agility Scorecard). The CLI and the OSS API both shell out to it. |

## Library packages

| Package | What it does |
|---|---|
| [`scanner/`](scanner/) | Per-job orchestrator: walk → language route → detect → emit. Routes `sshd_config` / `ssh_config` to the `ssh` rule pack and `.pem` / `.crt` / `.cer` / `.der` / `.key` to the x509 detector. Merges regex + AST findings, dedups by `(rule id, line)` preferring AST, honors `.relixqignore` + inline `relixq-ignore` (gitignore semantics, incl. dir-only patterns). Includes the `scanner/notebook` Jupyter preprocessor, plus two per-file post-detection passes: `promote.go` (multi-signal promotion — ≥2 distinct hand-rolled / crypto-fingerprint rules agreeing on an algorithm in one file fuse Bayesian-style into one high-severity `HANDROLLED_<ALG>_PROMOTED` finding, confidence capped 0.95) and `sentinel.go` (coverage sentinel — a known classical crypto-library import with **zero** recognized findings emits one informational `CRYPTO_API_UNMAPPED`; PQC libraries never trigger it). |
| [`rules/`](rules/) | YAML rule-pack loader + matcher (regex and AST detector kinds; the `layer` field). Rules may carry inline `examples` self-tests (`match` / `no_match`) validated by `TestRuleExamples`; `TestRuleExamplesRatchet` + `examples_baseline.txt` (frozen grandfather list) make examples mandatory for new regex rules. |
| [`finding/`](finding/) | The canonical `CryptoFinding` schema + JSONL writer, incl. the three-tier `quantum_safety` taxonomy (`vulnerable` / `grover_weakened` / `classically_broken`, plus `hybrid` / `quantum_safe` / `unknown`). |
| [`detectors/regex/`](detectors/regex/) | Regex detector backend (the recall floor across every language). |
| [`detectors/ast/`](detectors/ast/) | AST runner registry + interface. |
| [`detectors/{go,jsts,php}ast/`](detectors/) | Pure-Go AST runners (Go, JS/TS, PHP) — always active. |
| [`detectors/csharpast/`](detectors/csharpast/) | C# AST via the bundled `relixq-roslyn` .NET subprocess ([`detectors/csharpast/tools/relixq-roslyn/`](detectors/csharpast/tools/relixq-roslyn/)). Degrades to regex when the binary is absent. |
| [`detectors/pyast/`](detectors/pyast/) | Python AST runner driving a long-running Python subprocess (`relixq_python.py`, resolved via `RELIXQ_PYTHON_BIN` / `$PATH`). Present in-tree but deliberately **not registered** by the shipped binaries (no interpreter in the slim image) — Python rides the regex floor. Builds that blank-import it also unlock `.ipynb` scanning via `scanner/notebook`. |
| [`detectors/{c,cpp,java,rust,kotlin,swift,ruby,scala,julia}ast/`](detectors/) | Tree-sitter AST runners, gated on `//go:build cgo`. Active when built with `CGO_ENABLED=1` + a C toolchain (the shipped Docker image); compile to no-op stubs otherwise and fall back to regex. |
| [`detectors/x509/`](detectors/x509/) | X.509 certificate / key-file detector (`.pem` / `.crt` / `.cer` / `.der` / `.key`): parses PEM blocks + raw DER; a certificate yields **two** findings (public-key algorithm `X509_CERT_PUBKEY_*` and signature algorithm `X509_CERT_SIG_*`), plus CSR / private-key (CWE-798) / public-key findings. Snippets carry only the `-----BEGIN …-----` marker — never key material; unknown / PQC OIDs are never flagged. |
| [`suppression/`](suppression/) | `.relixqignore` (gitignore syntax, incl. dir-only `build/`-style patterns) + inline `relixq-ignore` directives. |
| [`enrich/`](enrich/) | overlay: merges an optional external rule-pack overlay's migration enrichment onto detection findings by rule id. No-op without an overlay. |
| [`tlsscanner/`](tlsscanner/) | TLS/certificate scanner — handshake + cert/protocol/cipher analysis (`relixq scan tls`). |
| [`sbom/`](sbom/) | Dependency-manifest → `CryptoFinding` adapter with an embedded crypto knowledge base (`relixq scan deps`). |
| [`agility/`](agility/) | Crypto-Agility Scorecard (0..100). |
| [`fusion/`](fusion/) | Bayesian cross-channel corroboration of findings. |
| [`graph/`](graph/) | Per-finding blast-radius via a file-dependency graph. |
| [`migrationplan/`](migrationplan/) | Deterministic synthesis of agility + fusion + graph into a prioritized migration plan. |
| [`blame/`](blame/) | Git-blame annotation for findings. |
| [`diffmode/`](diffmode/) | Changed-files resolution for `--diff` PR scans. |
| [`validationgate/`](validationgate/) | The scanner regression gate over the labeled ground-truth corpus (`../../fixtures/validation-corpus/`): `go test ./validationgate/...` runs the real scan + deps pipeline and enforces recall, zero false positives on PQC code, strict precision (every finding must map to ground truth), and the deps expectations. |

## Rule packs

- [`rules-community/`](rules-community/) — the OSS rule set: 725 rules across 47 language / config-format packs (incl. the `ssh` pack for `sshd_config` / `ssh_config` and the `fingerprints` pack — language `any`, run on every file — matching crypto magic constants: AES S-boxes, SHA-256 K/IV, SHA-1/MD5 IVs, RSA exponent, MODP / Curve25519 / secp256k1 primes), spanning the weak-crypto baseline plus the `crypto-api` **detection** layer (RSA / ECDSA / ECDH / DSA / Ed25519 / DH / JWT algorithms / …) with one-line PQC `recommendation`s on the core quantum-broken rules. Risk-tagged rules carry the three-tier `quantum_safety` value (`vulnerable` / `grover_weakened` / `classically_broken`), with severity parity across the Shor-broken families (ECC / DH / DSA = critical, same as RSA). Loaded by default.
- `rules-rulepack/` — an optional external migration **enrichment** overlay, when present. Gitignored and not part of this repo. Without it, findings are detection-complete (see [`enrich/`](enrich/)).

## AST: regex floor vs. full precision

A plain `go build` ships the **regex floor** plus the pure-Go AST detectors
(Go, JS/TS, PHP). **Full AST** — C# (Roslyn) and the tree-sitter languages —
activates when the engine is built with `CGO_ENABLED=1` and a C toolchain, with
`relixq-roslyn` published and discoverable (`RELIXQ_ROSLYN_BIN`). The
`apps/api/Dockerfile` image used by `docker compose up --build` does this, so
dashboard users get full AST with no host toolchain. The slim release scanner
image built from [`Dockerfile.scanner`](../../Dockerfile.scanner), the GitHub
Action, release archives, and a plain `go build` use the regex floor plus the
always-on pure-Go AST detectors (Go, JS/TS, PHP). AST is always additive over
the regex floor — it never errors when a runner is unavailable. A few
detections are AST-tier only (e.g. AES-128 key-size discrimination in Python)
and fire only when their AST runner is active.
