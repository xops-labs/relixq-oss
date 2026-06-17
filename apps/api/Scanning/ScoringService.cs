// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using RelixQ.Contracts;
using RelixQ.Scoring;

namespace RelixQ.OssApi.Scanning;

/// <summary>
/// Bridges a scanner <see cref="CryptoFinding"/> to the OSS
/// <see cref="ScoringFormulaV1"/> (RelixQ.Scoring, basic). The OSS
/// self-host has no per-project enrichment context, so non-finding factors use
/// conservative production defaults — the score is driven by the algorithm,
/// usage, severity, key size, and quantum safety carried on the finding itself.
/// </summary>
public sealed class ScoringService
{
    private readonly ScoringFormulaV1 _formula = new();

    public ScoringResult Score(CryptoFinding f)
    {
        var inputs = new ScoringInputs(
            Algorithm: f.Algorithm ?? "unknown",
            UsageType: f.UsageType,
            QuantumSafety: ParseQuantumSafety(f.QuantumSafety),
            Severity: ParseSeverity(f.Severity),
            KeySize: f.KeySize,
            Environment: RelixQ.Scoring.Environment.Production,
            Exposure: Exposure.Internal,
            DataSensitivity: DataSensitivity.Confidential,
            BusinessCriticality: BusinessCriticality.High,
            RuntimeActivity: RuntimeActivity.Unknown,
            ComplianceTags: Array.Empty<string>(),
            CompensatingControls: Array.Empty<string>(),
            HasActiveException: false);

        return _formula.Score(inputs);
    }

    public static RiskLevel LevelForScore(int score) => ScoringFormulaV1.ToRiskLevel(score);

    private static QuantumSafety ParseQuantumSafety(string? s) => (s ?? "").ToLowerInvariant() switch
    {
        "vulnerable" => QuantumSafety.Vulnerable,
        "grover_weakened" or "groverweakened" => QuantumSafety.GroverWeakened,
        "classically_broken" or "classicallybroken" => QuantumSafety.ClassicallyBroken,
        "hybrid" => QuantumSafety.Hybrid,
        "quantumsafe" or "quantum_safe" or "safe" => QuantumSafety.QuantumSafe,
        _ => QuantumSafety.Unknown,
    };

    private static Severity ParseSeverity(string? s) => (s ?? "").ToLowerInvariant() switch
    {
        "info" => Severity.Info,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.Medium,
    };
}
