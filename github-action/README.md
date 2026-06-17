# Relix-Q PQC Scan — GitHub Action

Scan a repository's **code**, its **dependencies**, or live **TLS endpoints**
for quantum-vulnerable cryptography, and emit SARIF that GitHub Code Scanning
renders as inline pull-request annotations.

## Usage

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF (PR annotations)

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: relixq
        uses: xops-labs/relixq-oss/github-action@v0.3.0   # pin to a release tag
        with:
          scan-type: code
          severity-threshold: medium
          # fail-on: high
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.relixq.outputs.sarif }}
```

A full multi-job example (code + deps) is in
[`docs/ci-examples/github.yml`](../docs/ci-examples/github.yml).

## Inputs

| Input | Default | Description |
|---|---|---|
| `scan-type` | `code` | `code`, `deps`, or `tls`. |
| `path` | `.` | Path to scan (`code`/`deps`). |
| `target` | — | For `tls`: one or more `host[:port]`, space-separated. |
| `format` | `sarif` | Output format (`sarif` for Code Scanning). |
| `output` | `relixq.sarif` | Output file path. |
| `severity-threshold` | `medium` | Drop findings below this severity. |
| `fail-on` | — | Fail the job if a finding meets/exceeds this severity. Empty = report-only. |
| `baseline` | — | Baseline file; report only findings absent from it. |

## Outputs

| Output | Description |
|---|---|
| `sarif` | Path to the SARIF file produced. Always set — even when `fail-on` fails the job — so an `if: always()` upload step still posts annotations. |

## How it works

The Action runs the released slim scanner image
(`ghcr.io/xops-labs/relixq:<version>`, published to GHCR by the
[release workflow](../.github/workflows/release.yml) from
[`Dockerfile.scanner`](../Dockerfile.scanner) on every `vX.Y.Z` tag and
signed with cosign). That image ships the regex floor plus the pure-Go AST
detectors (Go, JS/TS); full AST (C# Roslyn + tree-sitter) is available in the
`docker compose` app image. Findings flow through the same
`--severity-threshold` / `--baseline` / `--exit-on` pipeline as the `relixq`
CLI.

> **Note:** `action.yml` pins the image to the release version matching the
> Action's own tag, so `github-action@v0.3.0` runs scanner image `0.3.0` - no
> local build, and reproducible CI as long as you pin the `uses:` ref to a tag.
