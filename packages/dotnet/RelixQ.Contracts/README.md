<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# RelixQ.Contracts

Canonical cross-service wire DTOs + JSON Schema for the Relix-Q platform. Pure data contracts; no runtime behavior, no DI, no DB.

## What's in this package

- `CryptoFinding` — canonical wire shape for one finding emitted by Relix-Q scanners. Mirrors the Go-side `finding.Finding` struct one-for-one so a finding written by the Go scanner deserializes into this DTO without manual mapping.
- `Events/Events.cs` — cross-service event payloads:
  - `ScoringEvent` (abstract base)
  - `FindingCreatedEvent` / `FindingUpdatedEvent` / `FindingResolvedEvent`
- `schemas/CryptoFinding.json` — JSON Schema for `CryptoFinding`, embedded into the assembly as the resource `RelixQ.Contracts.Schemas.CryptoFinding.json` so consumers can validate inbound payloads without an out-of-band file. `quantum_safety` is the six-value enum `vulnerable` / `grover_weakened` / `classically_broken` / `hybrid` / `quantum_safe` / `unknown`; `severity` is `info` / `low` / `medium` / `high` / `critical`.

## Consumer pattern

Read findings off the wire:

```csharp
using System.Text.Json;
using RelixQ.Contracts;

var opts = new JsonSerializerOptions(JsonSerializerDefaults.Web);
foreach (var line in File.ReadLines("findings.jsonl"))
{
    var finding = JsonSerializer.Deserialize<CryptoFinding>(line, opts)!;
    // ... handle finding
}
```

Load the embedded JSON Schema:

```csharp
using var stream = typeof(CryptoFinding).Assembly
    .GetManifestResourceStream("RelixQ.Contracts.Schemas.CryptoFinding.json")!;
using var reader = new StreamReader(stream);
var schemaJson = reader.ReadToEnd();
```

Publish a scoring event:

```csharp
using RelixQ.Contracts.Events;

await bus.PublishAsync(new FindingCreatedEvent
{
    FindingId = finding.FindingId,
    OrganizationId = orgId,
    ProjectId = projectId,
    RuleId = finding.RuleId,
    RiskScore = 86,
    RiskLevel = "critical",
    Ts = DateTimeOffset.UtcNow,
});
```

## Consuming it

`apps/api` references this package directly; it also publishes to NuGet as a standalone package, and its embedded JSON Schema is mirrored by the `@relix-q/web-client` zod schemas so a finding has one shape across Go, C#, and TypeScript.

Naming note: this package's `CryptoFinding` is the **wire DTO** — the persisted aggregate root with status transitions and enrichment context is maintained separately as `Relixq.RiskScoring.Domain.CryptoFinding` and is out of scope here. Consumers that need both alias the OSS DTO via `using CryptoFindingDto = RelixQ.Contracts.CryptoFinding;` so the Domain entity stays unqualified in the call site.

## Out of scope for this package

- `IngestRequest` / `IngestResponse` — internal scoring API kickoff (out of scope here)
- `AggregateBucketResponse` / `FindingResponse` / `ScoreResponse` / `ScoreTrendPoint` / `PRDeltaResponse` / `PatchFindingRequest` — API response shapes for the dashboard (out of scope here)
- `ScoreUpdatedEvent` / `PRRiskDeltaEvent` — score-snapshot and PR-gating events (out of scope here); both derive from `RelixQ.Contracts.Events.ScoringEvent`
