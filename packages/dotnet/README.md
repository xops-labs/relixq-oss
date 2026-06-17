<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# packages/dotnet — Relix-Q .NET libraries

The .NET libraries the OSS API (`apps/api`) consumes, each published as a
standalone NuGet package. Every package is its own csproj; there is no umbrella
project. They take plain options objects (not `IOptions<T>`) so a self-host can
wire them with no DI container or framework.

## Package inventory

| Package | What it provides |
|---|---|
| [`RelixQ.Scoring`](RelixQ.Scoring/) | Deterministic 0..100 risk score (basic). Pure-function library. |
| [`RelixQ.Contracts`](RelixQ.Contracts/) | The canonical `CryptoFinding` wire DTO + scoring events + embedded JSON Schema. |
| [`RelixQ.Auth.Local`](RelixQ.Auth.Local/) | Local-credential primitives (subset): Argon2id hash + zxcvbn strength + opaque-token mint/hash + email-format check. |
| [`RelixQ.AI.BYOK`](RelixQ.AI.BYOK/) | Bring-Your-Own-Key LLM adapters (BYOK subset): `ILlmProvider` + OpenAI + Anthropic + cost estimator + env-key resolver. |

## Consumption pattern

Constructors take POCO options directly, not `IOptions<T>`, so the packages have
zero dependency on `Microsoft.Extensions.Options` or any DI container. With a DI
container you wrap via a factory; without one you just `new` them:

```csharp
// no framework needed
var hasher = new Argon2idPasswordHasher(new Argon2Options());
var provider = new OpenAiProvider(httpClient, new OpenAiOptions(), NullLogger<OpenAiProvider>.Instance);
```

The same pattern applies to `AnthropicProvider` and
`ZxcvbnPasswordStrengthValidator`. `apps/api` consumes the packages via project
references in this repo.

## What's NOT here (out of scope for these packages)

These are intentionally out of scope for the OSS packages:

- Rich-domain risk-scoring (aggregate root + status transitions + persistence), ingest/rescoring orchestration, the HTTP API surface, and the dashboard API DTOs / events.
- Full auth: OIDC / SAML / WebAuthn / MFA / SCIM / row-level-security enforcement.
- Hosted AI providers (`AzureOpenAiProvider`, `BedrockProvider`, `VertexProvider`), the provider router, response caches, the migration-plan generator, and per-org budget persistence.
