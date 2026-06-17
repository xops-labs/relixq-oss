# Releasing Relix-Q Community

Releases are fully automated in GitHub Actions — no local build steps. Pushing
a `vX.Y.Z` tag runs [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which:

1. **Tests** — `go test ./...` in `packages/go`, including the validation gate
   (`validationgate`, recall/precision against the labeled corpus).
2. **GoReleaser** ([`.goreleaser.yaml`](../.goreleaser.yaml)) — cross-compiles
   `relixq` + `relixq-scan-code` (CGO off), bundles them with the community
   rules into per-platform archives, builds `.deb`/`.rpm`, writes the SHA256
   checksums file, and creates the GitHub Release with all assets attached.
3. **Scanner image** — builds `Dockerfile.scanner` and pushes it to GHCR
   tagged `X.Y.Z`, `X.Y`, `sha-<short>`, and `latest` (non-prerelease tags
   only), then signs the image with cosign (keyless, GitHub OIDC).
4. **Windows MSI** — builds both `.exe`s on a Windows runner, stages them with
   the rules, compiles [`packaging/windows/relixq.wxs`](../packaging/windows/relixq.wxs)
   with the WiX .NET tool, Authenticode-signs when secrets are configured, and
   uploads `relixq_<version>_windows_amd64.msi` + a `.sha256` sidecar to the
   release.

Continuous (non-release) image builds still happen on every push to `main`
via [`.github/workflows/relixq-image.yml`](../.github/workflows/relixq-image.yml),
tagged `main` + `sha-<short>`. `latest` always points at the latest release.

## Cutting a release

```bash
# 1. Release prep (on main, via PR like any other change):
#    - CHANGELOG.md: move [Unreleased] entries under the new version heading
#    - github-action/action.yml: bump the image pin to the version you are
#      about to tag (e.g. ghcr.io/xops-labs/relixq:0.1.0) so
#      github-action@v0.1.0 runs scanner image 0.1.0
# 2. Tag and push:
git tag v0.1.0
git push origin v0.1.0
# 3. Watch the Release workflow; the GitHub Release appears when it finishes.
```

Prereleases work too: `v0.4.0-rc1` produces all artifacts but does **not**
move the `latest` image tag (and the MSI uses the numeric `0.4.0` as its
internal ProductVersion, since MSI versions cannot carry prerelease labels).

Dry-run locally (build everything, publish nothing):

```bash
goreleaser release --snapshot --clean   # artifacts land in dist/
```

## Artifact naming

| Artifact | Name |
|---|---|
| Windows portable | `relixq_<version>_windows_amd64.zip` |
| Windows installer | `relixq_<version>_windows_amd64.msi` (+ `.msi.sha256`) |
| Linux | `relixq_<version>_linux_amd64.tar.gz` |
| macOS (Intel) | `relixq_<version>_darwin_amd64.tar.gz` |
| macOS (Apple Silicon) | `relixq_<version>_darwin_arm64.tar.gz` |
| Debian/Ubuntu package | `relixq_<version>_amd64.deb` |
| RHEL/Fedora package | `relixq-<version>-1.x86_64.rpm` |
| Checksums | `relixq_<version>_checksums.txt` (SHA256, covers all GoReleaser artifacts) |
| Container image | `ghcr.io/xops-labs/relixq:{<version>, <major>.<minor>, latest, sha-<short>}` |

Each archive contains `relixq`, `relixq-scan-code`, `LICENSE`, and `rules/`
(the community rule pack). The CLI finds the scanner binary next to itself and
the bundled `rules/` folder automatically — extract and run, no environment
variables needed. The `.deb`/`.rpm` install to `/usr/bin` with rules at
`/usr/share/relixq/rules` (also auto-discovered).

## Verifying downloads

```bash
# Archives / packages — listed in the checksums file:
sha256sum -c relixq_<version>_checksums.txt --ignore-missing

# MSI — sidecar checksum:
# (PowerShell) (Get-FileHash relixq_<version>_windows_amd64.msi).Hash

# Container image — cosign keyless signature:
cosign verify ghcr.io/xops-labs/relixq:<version> \
  --certificate-identity-regexp 'https://github.com/xops-labs/relixq-oss/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## GitHub secrets

| Secret | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | built-in | Release creation, asset upload, GHCR push, cosign OIDC. Nothing to configure. |
| `WINDOWS_SIGNING_CERT_PFX_BASE64` | optional | Base64-encoded `.pfx` Authenticode code-signing certificate. When set, the workflow signs `relixq.exe`, `relixq-scan-code.exe`, and the MSI (SHA256 digest + RFC 3161 timestamp). When absent, the MSI ships unsigned and the workflow logs a notice — it never fakes a signature. |
| `WINDOWS_SIGNING_CERT_PASSWORD` | optional | Password for the `.pfx` above. |

Encode a certificate for the secret with:
`[Convert]::ToBase64String([IO.File]::ReadAllBytes('cert.pfx'))` (PowerShell).

## Signing status and plan

| Surface | Status |
|---|---|
| **Containers (cosign)** | ✅ Implemented. Release images are signed keyless via GitHub OIDC; verify with the `cosign verify` command above. |
| **Windows (Authenticode)** | 🔧 Wired, needs a certificate. The signing steps exist in `release.yml` and activate automatically once the two secrets above are set (an OV/EV code-signing cert from a CA such as DigiCert/Sectigo, or Azure Trusted Signing — for the latter, swap the `signtool /f` steps for the `azure/trusted-signing-action`). Until then SmartScreen will warn on the unsigned MSI; the `.sha256` sidecar is the integrity check. |
| **macOS (notarization)** | 📋 Planned, not implemented. Requires an Apple Developer ID Application certificate + an App Store Connect API key. Plan: add a `darwin-sign` job on `macos-latest` that downloads the two darwin archives, signs the binaries with `codesign --options runtime`, submits with `xcrun notarytool submit --wait`, re-packages, re-uploads, and regenerates the checksum entries. Until then Gatekeeper quarantines downloaded binaries — `xattr -d com.apple.quarantine relixq relixq-scan-code` after extracting. |

Nothing in the pipeline pretends to be signed when it is not: unsigned
artifacts ship unsigned, with checksums as the baseline integrity mechanism.
