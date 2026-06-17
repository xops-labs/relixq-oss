# Architecture

Relix-Q OSS has two primary user paths:

1. A CLI/scanner path for local use, release downloads, Docker scanner images,
   and GitHub Action CI scans.
2. A self-hosted Docker Compose web UI for interactive project scans and export.

## Runtime components

```text
browser
  |
  v
apps/web (Next.js)
  |
  v
apps/api (.NET minimal API)
  |
  +--> Postgres
  |
  +--> relixq-scan-code (Go scanner engine)
```

The stack is single-tenant and self-hosted. It does not send source code,
findings, telemetry, or API keys to any external service.

## Scanner engine

`packages/go` contains:

- `cmd/relixq`: user-facing CLI wrapper.
- `cmd/relixq-scan-code`: scanner engine binary.
- `rules-community`: OSS rule pack loaded by default.
- Detectors for regex, pure-Go AST, CGO tree-sitter AST, C# Roslyn, x509,
  dependency manifests, TLS endpoints, suppressions, baselines, fusion, graph,
  and migration-plan helpers.

Release archives and the GitHub Action's published scanner image are built
CGO-off: regex floor plus pure-Go Go/JS/TS/PHP AST. The Docker Compose API image
builds with CGO and includes C# Roslyn for fuller local UI scans.

## API and persistence

`apps/api` owns:

- Local email/password signup and login.
- Project source definitions: sample, git, local path, upload.
- Scan runs and finding persistence.
- Risk scoring via `RelixQ.Scoring`.
- Export endpoints for JSON, SARIF, Markdown, and HTML.

Uploaded archives are kept in a Docker volume so projects can be rescanned.
Local path scans are restricted to the read-only `/scan` mount.

## Web app

`apps/web` is a Next.js app that:

- Forwards the session cookie to the API from server-side helpers.
- Uses `@relix-q/web-components` for shared tables, badges, cards, and score
  visuals.
- Provides project creation, scan execution, results exploration, and export
  links.

## Shared packages

- `packages/dotnet/RelixQ.Contracts`: canonical scanner finding schema.
- `packages/dotnet/RelixQ.Scoring`: deterministic risk scoring.
- `packages/dotnet/RelixQ.Auth.Local`: local auth primitives.
- `packages/dotnet/RelixQ.AI.BYOK`: standalone BYOK LLM adapter library; not
  wired into the OSS app endpoints.
- `packages/npm/web-components`: reusable React rendering package.
- `packages/npm/web-client`: typed JavaScript client for current OSS API DTOs
  plus scanner-output schemas.

## Validation and CI

PR/main CI runs Go tests, .NET API build, npm package builds, the web production
build, and a production-dependency npm audit at high-or-higher severity.

The Go test suite includes the validation corpus gate, which checks recall,
strict precision, forbidden false positives, dependency expectations, and rule
example tests.

## Scope boundaries

The OSS repository includes single-tenant scanning, scoring, exports, release
artifacts, and the web UI. Some surfaces are intentionally out of scope:
multi-tenant orchestration, SSO/RLS, hosted governance, runtime telemetry,
hosted LLM explanation routing, and the migration-enrichment overlay content.
