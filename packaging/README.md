# Packaging

How Relix-Q is distributed to end users.

| What | Where | Audience |
|---|---|---|
| **Web dashboard** | Source checkout: `docker compose up --build`; website quickstart scripts may fetch a compose file that points at prebuilt images | Most users - the full UI |
| **CLI scanner** | Windows MSI (`packaging/windows`), Chocolatey, winget | Terminal / CI use |

## Web dashboard - install scripts

In this repo, `docker-compose.yml` is source-build oriented: it builds the API
and web images locally from `apps/api/Dockerfile` and `apps/web/Dockerfile`.

The one-command quickstart scripts live in the **website** repo at
`public/install.ps1` and `public/install.sh` (served from
`https://relixq-website.vercel.app/install.ps1` and `/install.sh`). They detect
Docker, then download the website-provided compose file and start the stack; if
Docker is missing they point the user at the install (they do **not** force a
Docker Desktop install, which needs a reboot + GUI first-run on Windows/macOS).

```powershell
irm https://relixq-website.vercel.app/install.ps1 | iex      # Windows
```
```sh
curl -fsSL https://relixq-website.vercel.app/install.sh | sh  # macOS / Linux
```

## CLI — Chocolatey (`packaging/chocolatey`)

The package downloads the official MSI (mirrored on the website) and installs it
silently. The checksum is pinned in `tools/chocolateyinstall.ps1`. Uninstall is
handled by Chocolatey's MSI auto-uninstaller (no uninstall script needed).

**Build & test locally:**
```powershell
cd packaging/chocolatey
choco pack
choco install relixq -s . -y          # install from the local .nupkg
relixq version
```

**Publish (GA):** requires a chocolatey.org account + API key, and goes through
moderation (the MSI URL must stay publicly reachable).
```powershell
choco apikey --key <KEY> --source https://push.chocolatey.org/
choco push relixq.0.1.0.nupkg --source https://push.chocolatey.org/
```

## CLI — winget (`packaging/winget`)

Three manifests (version / installer / locale) for `RelixQ.RelixQ`, pinned to
the MSI's `ProductCode` and SHA256.

**Validate & test locally:**
```powershell
winget validate --manifest packaging/winget
winget install --manifest packaging/winget
```

**Publish (GA):** open a PR to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) placing the
three files under `manifests/r/RelixQ/RelixQ/0.1.0/` (or use `wingetcreate`).
Goes through automated + human moderation; the installer URL must be public.

## Before publishing publicly — confirm these

- **License.** The project is Apache-2.0 — the LICENSE file, every source
  header, the nuspec, `tools/LICENSE.txt`, and the winget `License` field all
  agree. (Settled 2026-06-15.)
- **Canonical download URL.** These point at the website mirror. Once the OSS
  releases are public, switch to the GitHub release asset URL.
- **PackageIdentifier.** `RelixQ.RelixQ` is a sensible default; adjust if you
  want a different publisher/package split before the first winget submission.
- **Bump version** in all four manifests on each release (nuspec `version`;
  winget `PackageVersion`, `InstallerUrl`, `InstallerSha256`, `ProductCode`).
