<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# RelixQ.Scoring

Pure scoring formula library implementing the basic deterministic 0..100 risk score. No DI, no host, no DB — just `IScoringFormula.Score(ScoringInputs) → ScoringResult`.

## What's in this package

- `IScoringFormula` / `IScoringFormulaRegistry` — pluggable formula interface + registry
- `ScoringFormulaV1` — the v1 weighted-sum formula. Pure, idempotent, deterministic. Two-tier quantum handling: `GroverWeakened` caps the algorithm-risk factor at 6 (halved security margin, not a break), `ClassicallyBroken` floors it at 7 (exploitable today).
- `ScoringInputs` / `ScoringResult` — immutable record inputs and result
- `Enums.cs` — value-type enums (`RiskLevel`, `Severity`, `QuantumSafety`, `Environment`, `Exposure`, `DataSensitivity`, `BusinessCriticality`, `RuntimeActivity`) with int values matching the persisted Domain enums one-for-one. `QuantumSafety` carries the full six-value wire taxonomy: `Vulnerable`, `Hybrid`, `QuantumSafe`, `Unknown`, `GroverWeakened`, `ClassicallyBroken`.

## Consumer pattern

```csharp
var formula = new ScoringFormulaV1();
var inputs = new ScoringInputs(
    Algorithm: "RSA",
    UsageType: "key_exchange",
    QuantumSafety: QuantumSafety.Vulnerable,
    Severity: Severity.High,
    KeySize: 1024,
    Environment: Environment.Production,
    Exposure: Exposure.Public,
    DataSensitivity: DataSensitivity.Regulated,
    BusinessCriticality: BusinessCriticality.Critical,
    RuntimeActivity: RuntimeActivity.Active,
    ComplianceTags: ["PCI"],
    CompensatingControls: [],
    HasActiveException: false);

ScoringResult result = formula.Score(inputs);
// result.Score == 86, result.Level == RiskLevel.Critical, result.FormulaVersion == "v1"
```

## Consuming it

`apps/api` references this library directly; it also publishes to NuGet as a standalone package. The scorer is a pure function over `ScoringInputs` — no DI container required. Mapping a richer finding model down to `ScoringInputs` is the caller's job: the rich-domain aggregate and enrichment are maintained separately, while this package keeps the deterministic scorer.

## Out of scope for this package

- Domain aggregate `CryptoFinding` with status transitions, persistence behavior, audit fields
- `FindingContext` with enrichment fields populated by the ContextEnricher
- DB persistence, message bus integration, HTTP API surface
- Per-org rule overrides, custom-rule editor outputs
- Multi-formula version routing beyond the simple registry
