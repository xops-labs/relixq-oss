# Contributing to Relix-Q OSS

Thanks for helping improve open, practical post-quantum cryptography discovery.
For governance and maintainer roles, see [GOVERNANCE.md](GOVERNANCE.md) and
[MAINTAINERS.md](MAINTAINERS.md). For questions and support channels, see
[SUPPORT.md](SUPPORT.md). For private security reports, see
[SECURITY.md](SECURITY.md); do not open public issues for vulnerabilities.

## Code of conduct

This project follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By participating,
you agree to keep discussions respectful, evidence-based, and welcoming.

## Prerequisites

| Requirement | Source of truth | Notes |
|---|---|---|
| Docker + Compose | Current stable | Needed for the full web UI stack. |
| Go | `packages/go/go.mod` | Needed for scanner and CLI work. |
| .NET SDK | .NET 8 | Needed for `apps/api` and `packages/dotnet`. |
| Node.js | `package.json` engines | Needed for the web app and npm packages. |
| npm | Lockfile-driven | Use `npm ci` in clean clones and CI. |

Optional: a C toolchain plus `CGO_ENABLED=1` for local tree-sitter AST builds.
The Docker Compose API image already builds the scanner with CGO for full AST.

## Getting started

```bash
git clone https://github.com/xops-labs/relixq-oss.git
cd relixq-oss

# Full UI demo
docker compose up --build

# Local verification, matching CI
cd packages/go && go test ./...
cd ../..
dotnet build apps/api/RelixQ.OssApi.csproj --configuration Release
npm ci
npm audit --omit=dev --audit-level=high
npm run build:packages
npm run build:web
```

Generated folders such as `node_modules/`, `.next/`, `dist/`, `bin/`, and
`obj/` are ignored and should not be committed.

## Project layout

```text
apps/api/                 ASP.NET API: auth, projects, scans, scoring
apps/web/                 Next.js web UI
packages/go/              Scanner engine, CLI, dependency/TLS scanners, rules
packages/dotnet/          Shared .NET libraries
packages/npm/             Shared React components and JS client
fixtures/                 Demo targets and validation corpus
github-action/            GitHub Action wrapper for CI scanning
docs/                     Release, configuration, deployment, architecture, troubleshooting
packaging/                Windows/Chocolatey/winget packaging
```

## Branches and pull requests

- Fork the repo and open pull requests against `main`.
- Keep branches focused and short-lived.
- Use descriptive branch names such as `fix/scan-upload-error`,
  `feat/rule-pack-tests`, or `docs/troubleshooting-compose`.
- Fill in [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).
- Include the exact validation commands you ran, or explain why a command could
  not be run.

Larger changes should start with an issue or discussion before implementation.
See [GOVERNANCE.md](GOVERNANCE.md) for the lightweight RFC process.

## Verification checklist

Before asking for review, run the commands relevant to your change:

```bash
cd packages/go
go test ./...

cd ../..
dotnet build apps/api/RelixQ.OssApi.csproj --configuration Release
npm ci
npm audit --omit=dev --audit-level=high
npm run build:packages
npm run build:web
```

For scanner rules or detector changes, update the rule examples and the
validation corpus when needed. `packages/go/validationgate` is the source of
truth for recall, precision, and forbidden false positives.

## Good first contribution areas

- Documentation and troubleshooting improvements from real setup attempts.
- Rule examples and validation-corpus coverage for languages already supported.
- CI, packaging, and release hardening.
- Web UI clarity for scan results and exports.
- Scanner false-positive reductions with fixtures.

## Do not commit

- `.env`, `.env.local`, access tokens, provider API keys, or private git tokens.
- Real private keys or certificates.
- External rule-pack overlay content under `rules-rulepack/`.
- Logs, screenshots, or reports containing private source paths or credentials.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
