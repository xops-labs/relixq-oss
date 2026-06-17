<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# RelixQ.AI.BYOK

Bring-Your-Own-Key LLM provider adapters. The user supplies an API key; this package hands it to the provider's HTTP API and forwards the response in a normalized shape. No hosted-provider integrations, no Redis cache, no router, no migration-plan generator — those are out of scope for this package.

## What's in this package

| Type | Purpose |
|---|---|
| `LlmProviderKind` | Canonical enum tagging every adapter (BYOK and hosted provider kinds). Lives in OSS because it is part of the contract every adapter declares. |
| `ILlmProvider` | Single provider adapter: `Kind` / `Name` / `SupportsTier(tier)` plus the one completion method, `CompleteJsonAsync(LlmRequest, ct) -> Task<LlmResult>`. |
| `LlmRequest` / `LlmResult` | Wire shapes — system+user message, model tier, max tokens, JSON-mode hint; result has the JSON string, model id, input/output tokens, USD cost estimate. |
| `LlmProviderUnavailableException` | Thrown when a provider can't satisfy the request (auth, model, transport). A provider router can catch this to fail over. |
| `OpenAiProvider` + `OpenAiOptions` | api.openai.com chat completions adapter using `response_format: json_object`. Reads `OPENAI_API_KEY` first, falls back to `Options.ApiKey`. |
| `AnthropicProvider` + `AnthropicOptions` | api.anthropic.com Messages API adapter. JSON mode achieved by augmenting the system prompt (Messages API has no `response_format`). Reads `ANTHROPIC_API_KEY` first, falls back to `Options.ApiKey`. |
| `CostCalculator` | Pure per-1k-token cost estimator covering OpenAI, Claude, Gemini model name prefixes. Used by every adapter for budget bookkeeping. |
| `EnvKeyResolver` | Centralised "env first, config fallback, throw if neither" rule so every adapter resolves keys the same way. |

## Consumer pattern

```csharp
using RelixQ.AI.BYOK;
using Microsoft.Extensions.Logging.Abstractions;

var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
var provider = new OpenAiProvider(http, new OpenAiOptions(), NullLogger<OpenAiProvider>.Instance);
// OPENAI_API_KEY is read from the environment at construction time.

var result = await provider.CompleteJsonAsync(new LlmRequest
{
    SystemMessage = "You explain crypto findings.",
    UserMessage   = "Explain CWE-327 in two sentences.",
    ModelTier     = "small",
    MaxOutputTokens = 200,
}, CancellationToken.None);

Console.WriteLine($"{result.Model} ({result.InputTokens}+{result.OutputTokens} tok, ${result.CostUsd}): {result.Json}");
```

Anthropic adapter has the same shape — instantiate `AnthropicProvider`, set `ANTHROPIC_API_KEY`, and the JSON-mode prompt augmentation is applied automatically.

## Consuming it

This package is a standalone OSS adapter library. The current `apps/api` demo stack does not wire LLM explanations into its endpoints or read `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`; hosts that want BYOK explanations instantiate the providers directly as shown above. Hosted-provider integrations, a provider router, response caches, and budget persistence are out of scope for this package.

Constructors take POCO options directly (not `IOptions<T>`) so the package has zero dependency on `Microsoft.Extensions.Options` or any DI container. A DI host wires the factory:

```csharp
services.Configure<OpenAiOptions>(config.GetSection(OpenAiOptions.SectionName));
services.AddHttpClient<OpenAiProvider>(c => c.Timeout = TimeSpan.FromSeconds(30))
    .AddTypedClient<OpenAiProvider>((http, sp) => new OpenAiProvider(
        http,
        sp.GetRequiredService<IOptions<OpenAiOptions>>().Value,
        sp.GetRequiredService<ILogger<OpenAiProvider>>()));
services.AddSingleton<ILlmProvider>(sp => sp.GetRequiredService<OpenAiProvider>());
```

## Out of scope for this package

- `AzureOpenAiProvider` — Azure OpenAI deployment adapter with per-tier deployment maps
- `BedrockProvider` — AWS Bedrock adapter
- `VertexProvider` — GCP Vertex adapter
- `LlmRouter` + `CircuitBreaker` — per-provider preference, circuit breaking, failover (the BYOK adapters plug into such a router via the shared `ILlmProvider` contract)
- Per-org provider routing, tenant-scoped overrides
- Redis-backed response cache (`RedisExplanationCache`, etc.)
- LLM-driven migration-plan generator (vertical-context-aware)
- Cost telemetry, per-org budget caps and rate limiting (`DbBudgetTracker` uses the OSS `CostCalculator` but the persistence layer is out of scope here)
- Prompt template library (`FilePromptLibrary`)
