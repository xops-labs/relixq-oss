<!-- Copyright 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Relix-Q OSS security design

> What the OSS scanner protects, what it intentionally does not protect, and the cryptographic primitives it relies on for its own operation.

## Threat model (OSS surface only)

The OSS surface is a **local single-tenant scanner**. It is not a multi-tenant SaaS. The threat model is bounded accordingly:

| Asset | Threat | Mitigation |
|---|---|---|
| Source code / dependency manifests being scanned | Confidentiality (the code and dependency scanners read everything in the target tree) | Scanner runs locally; nothing is sent off-host. CLI prints scan output to stdout / JSONL / SARIF on local disk. |
| Certificate / key files in the scanned tree (`.pem` / `.crt` / `.cer` / `.der` / `.key`) | Disclosure (the x509 detector parses certificate and key material) | Parsed in-memory only; findings report algorithm metadata, and the emitted snippet contains **only** the `-----BEGIN …-----` marker line — never key bytes. |
| TLS scan targets (`relixq scan tls`) | The TLS scanner makes outbound TLS connections | Connections are made **only** to the endpoints you pass (`--target` / `--targets`); it is observe-only — `InsecureSkipVerify` captures posture without trusting the peer or sending any payload — with per-connection timeouts and no spidering/enumeration. |
| Rule YAML files | Tampering (a malicious rule pack could mis-classify findings or trigger ReDoS) | Rule packs ship with the binary; consumers loading third-party packs should review them. ReDoS mitigations: all regex go through Go's RE2 (no backtracking). |
| Scan output | Integrity / disclosure | Output file written with default mode 0644 in the working directory. Wrap in tighter permissions if running on shared hosts. |

## What this scanner doesn't do

- It does **not** implement cryptographic primitives. It only **detects** uses of crypto in code, configuration (incl. SSH and nginx), certificate/key files, dependencies, and TLS endpoints.
- The code and dependency scanners read only **local files** — no network. The TLS scanner (`relixq scan tls`) opens outbound connections, but **only** to the endpoints you explicitly pass, observe-only, and makes no other network calls. There is no scanning of targets you did not name.
- It does **not** modify the code it scans. Output is text / JSONL / JSON / SARIF / markdown / HTML.
- It does **not** include any "phone-home" telemetry or background update checks. Explicit commands such as `relixq self-update`, `relixq rules update`, `relixq doctor`, and `relixq scan tls` make network calls only when you run them and only to the configured/referenced endpoints.

## Cryptographic primitives the scanner uses for its own operation

Relix-Q itself uses cryptography for these internal purposes:

| Use case | Algorithm | Library | Why |
|---|---|---|---|
| TLS to the relixq server (CLI `login`/`submit`) | TLS 1.3 with PQC-hybrid where supported by the server | Go `crypto/tls` (stdlib) | Standard transport security |
| TLS endpoint probing (`scan tls`) | observes the negotiated protocol/cipher and the peer certificate; secures no data of its own | Go `crypto/tls` + `crypto/x509` (stdlib) | Read cert key algorithm, TLS version, and cipher to flag weak / quantum-vulnerable transport |
| At-rest certificate-file scanning (x509 detector in the code scan) | parses PEM/DER structure only; performs no cryptographic operations and never uses the key material | Go `crypto/x509` + `encoding/pem` (stdlib), `golang.org/x/crypto/ssh` for OpenSSH keys | Identify public-key and signature algorithms in `.pem` / `.crt` / `.cer` / `.der` / `.key` files |
| Future: scan result signing | Ed25519 detached signatures | Go `crypto/ed25519` | Tamper-evident scan history |
| Future: rule pack signature verification | minisign / age signatures | external libs (pinned) | Allow community rule pack distribution with provenance |

We do **not** implement crypto. We rely on Go's standard library and well-known third-party libraries.

## Crypto agility for Relix-Q itself

Per the project's own thesis, Relix-Q must itself be crypto-agile. The OSS surface enforces this through:

- All TLS via Go's stdlib `crypto/tls` — no custom TLS stack, no downgrade knobs exposed (TLS 1.3-only enforcement for CLI↔server traffic is a design target; the as-built CLI uses stdlib defaults)
- No custom crypto code; all primitives via stdlib or audited libraries
- Hybrid PQC TLS: built on Go ≥ 1.24, TLS 1.3 connections negotiate the X25519MLKEM768 hybrid key exchange by default where the server supports it

## Supply chain

- All Go dependencies are pinned to a specific version in `go.mod` and verified by `go.sum`.
- No closed-source binaries: the C# AST subprocess (`relixq-roslyn`) is built from source in-repo (`packages/go/detectors/csharpast/tools/relixq-roslyn`, Apache-2.0, on Microsoft's MIT-licensed Roslyn) by the Docker build.
- As-built PR/main CI: `.github/workflows/ci.yml` runs the Go test suite (`go test ./...`), the .NET API build, the npm package builds, the web production build, and a production-dependency npm audit at high-or-higher severity. The Go suite includes the scanner's quality gates: the labeled ground-truth validation gate (`packages/go/validationgate`) and the per-rule `match`/`no_match` example self-tests with their one-way ratchet.
- As-built release CI: `.github/workflows/release.yml` reruns the Go test suite before publishing release artifacts.
- Image publishing: `.github/workflows/relixq-image.yml` builds and publishes the slim main-branch scanner image to GHCR; release images are built by the release workflow and signed keyless with cosign.
- Planned, not yet wired: CycloneDX SBOMs, CodeQL / Dependabot / dependency-review / license-compatibility / gitleaks PR checks.

## Reporting issues

See [`SECURITY.md`](SECURITY.md).
