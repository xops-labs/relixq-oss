// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Scoring;

/// <summary>
/// Pure inputs to the scoring formula. Constructed by callers (mapping
/// translators or OSS consumers) and handed to IScoringFormula. Immutable
/// record so golden tests can describe a scenario as a single literal.
/// </summary>
public sealed record ScoringInputs(
    string Algorithm,
    string? UsageType,
    QuantumSafety QuantumSafety,
    Severity Severity,
    int? KeySize,
    Environment Environment,
    Exposure Exposure,
    DataSensitivity DataSensitivity,
    BusinessCriticality BusinessCriticality,
    RuntimeActivity RuntimeActivity,
    IReadOnlyList<string> ComplianceTags,
    IReadOnlyList<string> CompensatingControls,
    bool HasActiveException);

public sealed record ScoringResult(int Score, RiskLevel Level, string FormulaVersion);
