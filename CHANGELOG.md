# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-17

First public release of Relix-Q OSS — a self-hosted, open-source post-quantum
cryptography risk scanner.

### Scanner engine & CLI
- **`relixq` CLI and `relixq-scan-code` engine** — walk a path, route by language, and detect quantum-vulnerable and classically weak cryptography. Zero-config install layout: an extracted release archive scans with one command (the CLI resolves the engine and the bundled rules next to the executable; `RELIXQ_SCANNER_BIN` / `RELIXQ_RULE_DIR` / `--rules` override).
- **Code scanning** across **47 language / config-format rule packs (725 rules)** — RSA, ECDSA, ECDH, DSA, Ed25519, DH, JWT algorithms, MD5 / SHA-1 / RC4 / DES / 3DES, TLS 1.0/1.1, hardcoded keys, and more. A regex recall floor plus AST detectors for 13 languages (Go, C#, Java, JS/TS, Python, Rust, C/C++, Kotlin, Swift, PHP, Ruby, Scala, Julia); C# via a bundled `relixq-roslyn` subprocess.
- **Hand-rolled crypto detection** — a constant-fingerprint pack (AES S-boxes, SHA-256 constants, RSA / DH / curve primes) with multi-signal promotion: when ≥2 distinct signals agree on an algorithm in one file they fuse into a single high-severity `HANDROLLED_<ALG>_PROMOTED` finding. An unmapped-crypto coverage sentinel surfaces blind spots as informational `CRYPTO_API_UNMAPPED` findings (PQC libraries excluded).
- **X.509 certificate / key scanning** (`.pem` / `.crt` / `.cer` / `.der` / `.key`) — certificates flagged on both public-key and signature algorithm; CSRs, private keys (CWE-798), and public keys covered. **Config-layer crypto**: OpenSSH (`sshd_config` / `ssh_config`) and nginx. Snippets carry only the `-----BEGIN …-----` marker — never key material.
- **Dependency scanning** (`relixq scan deps`) over Python / JS / Go manifests via an embedded knowledge base, and **TLS endpoint scanning** (`relixq scan tls`) for classical certificate keys, weak protocols, SHA-1 signatures, and expiring / self-signed certs.
- **Three-tier `quantum_safety` taxonomy** — `vulnerable` (Shor-broken asymmetric), `grover_weakened` (AES-128 / 3DES-class symmetric), and `classically_broken` (MD5 / SHA-1 / RC4 / DES) — kept separable in JSON and SARIF.

### CI & output
- **SARIF 2.1.0** for GitHub Code Scanning — `security-severity`, classification tags (incl. CWE taxa and `pqc`), per-rule `help.markdown`, and stable `partialFingerprints`. JSON and HTML formats; `--severity-threshold` / `--exit-on` for CI gating.
- **Baselines** — `relixq baseline` records current findings to `.relixq-baseline.json`; `relixq scan --baseline <file>` reports only *new* findings (content-fingerprinted, resilient to line drift). Path/line suppression via `.relixqignore` and inline `// relixq-ignore`.
- **GitHub Action** (`github-action/`) wrapping `relixq scan` (`scan-type: code | deps | tls`) with SARIF output for `github/codeql-action/upload-sarif`, backed by a slim, cosign-signed GHCR scanner image.

### Releases
- **Downloadable releases** — pushing a `vX.Y.Z` tag publishes per-platform archives (Windows x64 `.zip`; Linux x64 / macOS x64 / macOS arm64 `.tar.gz`), `.deb` / `.rpm` packages, a Windows `.msi` (WiX), a SHA256 checksums file, and a GHCR image tagged `X.Y.Z` / `X.Y` / `latest` and signed with cosign (keyless) — all via GoReleaser. See [`docs/RELEASE.md`](docs/RELEASE.md).

### Self-hosted web app
- `docker compose up --build` brings up Postgres + a .NET 8 minimal API + a Next.js web UI on one network with no external dependencies.
- Local email/password auth (Argon2id hashing, opaque session tokens), project creation from the **bundled sample**, a **git repository** (optional access token for private repos), a **local path** (read-only mounted folder), or an **uploaded `.zip`** (zip-slip / zip-bomb guarded).
- Results view: a **risk-score gauge**, a **crypto-agility grade**, **files-scanned** and **per-algorithm** breakdowns, and a **findings table**. The demo image builds the engine with CGO for full AST precision and bundles the `relixq-roslyn` C# subprocess.

### Libraries
- Reusable OSS packages: `RelixQ.Contracts` (canonical wire DTO + JSON Schema), `RelixQ.Scoring` (deterministic 0..100 risk score), `RelixQ.Auth.Local` (Argon2id + zxcvbn + opaque tokens), `RelixQ.AI.BYOK` (Bring-Your-Own-Key LLM adapters), and `@relix-q/web-components` / `@relix-q/web-client`.
- Analysis libraries: `agility` (Crypto-Agility Scorecard), `fusion` (Bayesian cross-channel corroboration), `graph` (blast-radius graph), `sbom` (dependency-manifest ingest), and `migrationplan` (remediation planning).

### Quality
- Regression-gated by a labeled ground-truth corpus (`fixtures/validation-corpus/` + `packages/go/validationgate`) enforcing recall, **strict precision** (every finding maps to ground truth), and zero false positives on PQC code. Every rule carries inline `match` / `no_match` self-tests, mandatory for new regex rules via a one-way ratchet. The full Go test suite runs in CI before merge and release.

[Unreleased]: https://github.com/xops-labs/relixq-oss/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xops-labs/relixq-oss/releases/tag/v0.1.0
