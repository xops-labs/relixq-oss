# Development guide

This guide is for contributors cloning Relix-Q OSS to build, test, or modify the
project locally.

## Fresh clone checklist

```bash
git clone https://github.com/xops-labs/relixq-oss.git
cd relixq-oss

# Full web UI demo
docker compose up --build

# CI-equivalent checks
cd packages/go && go test ./...
cd ../..
dotnet build apps/api/RelixQ.OssApi.csproj --configuration Release
npm ci
npm audit --omit=dev --audit-level=high
npm run build:packages
npm run build:web
```

## Toolchains

| Area | Toolchain |
|---|---|
| Scanner / CLI | Go version from `packages/go/go.mod` |
| API / .NET packages | .NET 8 SDK |
| Web / npm packages | Node.js from `package.json` engines, npm lockfile |
| Full web UI | Docker + Docker Compose |
| Full local AST outside Docker | Optional C toolchain with `CGO_ENABLED=1` |

## Common workflows

### Run the web UI stack

```bash
docker compose up --build
```

Open http://localhost:47000, sign up, create a project, and scan the bundled
sample.

### Build the scanner directly

```bash
cd packages/go
go build -o bin/relixq ./cmd/relixq
go build -o bin/relixq-scan-code ./cmd/relixq-scan-code
bin/relixq scan ../../fixtures/sample-vulnerable --rules ./rules-community
```

### Build the API

```bash
dotnet build apps/api/RelixQ.OssApi.csproj --configuration Release
```

### Build TypeScript packages and web app

```bash
npm ci
npm run build:packages
npm run build:web
```

Build packages before the web app. The web app consumes the built workspace
package output.

## Validation corpus

The scanner gate lives under `packages/go/validationgate` and grades
`fixtures/validation-corpus/expected-findings.yaml`.

Use it when changing rules, detectors, scanner output, dependency scanning, or
TLS/certificate behavior:

```bash
cd packages/go
go test ./validationgate/... -run TestCorpus -count=1
go test ./...
```

Never weaken an expected finding just to make a test pass. The manifest is the
spec; the implementation should move toward it.

## Generated files

Do not commit generated folders:

- `node_modules/`
- `apps/web/.next/`
- `packages/npm/*/dist/`
- `bin/`
- `obj/`
- scanner output such as `findings.jsonl`

## Public repo hygiene

Before opening a pull request:

- Run the checks above or explain what was blocked.
- Redact secrets, private paths, and real key material from logs/screenshots.
- Keep docs and implementation aligned.
- Add fixtures for behavior changes that affect scanner claims.
