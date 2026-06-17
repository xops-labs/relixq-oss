# Windows installer (MSI)

`relixq.wxs` is WiX v4+ authoring for the Relix-Q Community MSI. The release
workflow (`.github/workflows/release.yml`, `msi` job) builds it on a Windows
runner with the [`wix` .NET tool](https://www.nuget.org/packages/wix):

1. Builds `relixq.exe` and `relixq-scan-code.exe` with the same version
   ldflags GoReleaser uses.
2. Stages them with `LICENSE.txt` and `rules\` (a copy of
   `packages/go/rules-community`) into one folder.
3. `wix build relixq.wxs -arch x64 -d StageDir=<stage> -d Version=<x.y.z>`.
4. Optionally Authenticode-signs the binaries and the MSI when signing
   secrets are configured (see `docs/RELEASE.md`), then uploads the MSI and
   its `.sha256` sidecar to the GitHub Release.

The MSI installs to `C:\Program Files\Relix-Q`, appends that folder to the
machine `PATH` (removed on uninstall), and supports in-place upgrades via the
permanent `UpgradeCode` — do not change that GUID.

Local build (needs Go and the .NET SDK):

```powershell
go build -o stage\relixq.exe ./packages/go/cmd/relixq
go build -o stage\relixq-scan-code.exe ./packages/go/cmd/relixq-scan-code
Copy-Item packages\go\rules-community stage\rules -Recurse
Copy-Item LICENSE stage\LICENSE.txt
dotnet tool install --global wix --version "6.*"   # v7 adds an OSMF EULA gate; stay on v6
# StageDir must be absolute — WiX resolves relative bind paths against the
# .wxs file's directory, not your working directory.
wix build packaging\windows\relixq.wxs -arch x64 -wx -d "StageDir=$PWD\stage" -d Version=0.0.1 -o relixq-test.msi
```
