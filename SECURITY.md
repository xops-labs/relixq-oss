<!-- Copyright 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security policy

## Reporting a vulnerability

Relix-Q is a cryptographic security tool. We take security reports seriously and respond promptly.

**Do not file a public GitHub issue** for security vulnerabilities. Instead, use one of:

1. **Preferred:** GitHub's [private vulnerability reporting](https://github.com/xops-labs/relixq-oss/security/advisories/new)
2. **Email:** `security@relixq.dev` (PGP key fingerprint not yet published)
3. **Backup:** open a [GitHub Security Advisory](https://github.com/xops-labs/relixq-oss/security/advisories/new) directly

## What to include

- A clear description of the vulnerability and its impact
- Steps to reproduce
- The version affected (commit SHA if possible)
- Any proof-of-concept code or test inputs
- Your name and how you'd like to be credited (or anonymous)

## Our commitment

| | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Initial triage | within 7 days |
| Fix or coordinated mitigation | within 90 days for critical, longer for lower severity |
| Public disclosure | coordinated with reporter; default 90-day window |

## Scope

In scope:

- The Relix-Q scanner engine and rule packs (`packages/go/scanner`, `packages/go/rules`, `packages/go/rules-community`, `packages/go/detectors`)
- The `relixq` CLI, the `relixq-scan-code` engine binary, and the bundled `relixq-roslyn` C# AST subprocess (`packages/go/detectors/csharpast/tools/relixq-roslyn`)
- The dependency scanner (`relixq scan deps`) and the TLS scanner (`relixq scan tls`, `packages/go/tlsscanner`)
- The docker-compose demo app (`apps/api`, `apps/web`) and the libraries under `packages/dotnet` / `packages/npm`
- Any code path that handles untrusted input (scan-target files, certificate/key files, dependency manifests, rule YAML, TLS handshake data, uploaded `.zip` archives)

Out of scope:

- Vulnerabilities in third-party dependencies (report upstream; we'll track)
- Social engineering of maintainers
- Physical attacks against contributor hardware
- Findings the scanner reports about other people's code (those are features, not vulnerabilities)

## Hall of fame

Reporters of valid vulnerabilities will be credited in the release notes of the fix and listed here.

## Supported versions

| Version | Supported |
|---|---|
| 0.x | Yes (pre-1.0; latest minor only) |

After v1.0 ships, the most recent two minor versions will receive security patches.

## CVE assignment

We are working toward becoming a CVE Numbering Authority. Until then, valid vulnerabilities receive CVEs via the MITRE root CNA or the GitHub Security Advisories database.
