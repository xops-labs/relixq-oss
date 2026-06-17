// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Scoring;

/// <summary>
/// Implementation of the v1 formula. Pure, deterministic,
/// idempotent. Score factors live in <see cref="ScoringWeights"/>; coefficients
/// in <see cref="ScoringCoefficients"/>. Tests pin behavior via golden cases.
/// </summary>
public sealed class ScoringFormulaV1 : IScoringFormula
{
    public string Version => "v1";

    public ScoringResult Score(ScoringInputs i)
    {
        if (i.HasActiveException)
        {
            // Active exception zeroes the score per §5.1 (AE = -15 weighted x1.0
            // is enough to drop most findings to 'safe', but the LLD wants an
            // explicit suppression — we model that here.).
            return new ScoringResult(0, RiskLevel.Safe, Version);
        }

        var ar = AlgorithmRisk(i.Algorithm, i.QuantumSafety, i.KeySize);
        var uc = UsageCriticality(i.UsageType);
        var ew = ExposureWeight(i.Exposure);
        var ds = DataSensitivityWeight(i.DataSensitivity);
        var envW = EnvironmentWeight(i.Environment);
        var bc = BusinessCriticalityWeight(i.BusinessCriticality);
        var ra = RuntimeActivityWeight(i.RuntimeActivity);
        var cr = ComplianceRelevance(i.ComplianceTags);
        var cc = CompensatingControlsCredit(i.CompensatingControls);

        var raw =
              (ar   * ScoringCoefficients.AR)
            + (uc   * ScoringCoefficients.UC)
            + (ew   * ScoringCoefficients.EW)
            + (ds   * ScoringCoefficients.DS)
            + (envW * ScoringCoefficients.EnvW)
            + (bc   * ScoringCoefficients.BC)
            + (ra   * ScoringCoefficients.RA)
            + (cr   * ScoringCoefficients.CR)
            - (cc   * ScoringCoefficients.CC);

        var score = (int)Math.Clamp(Math.Round(raw, MidpointRounding.AwayFromZero), 0, 100);
        return new ScoringResult(score, ToRiskLevel(score), Version);
    }

    public static RiskLevel ToRiskLevel(int score) => score switch
    {
        >= 90 => RiskLevel.Severe,
        >= 75 => RiskLevel.Critical,
        >= 55 => RiskLevel.High,
        >= 35 => RiskLevel.Medium,
        >= 15 => RiskLevel.Low,
        _ => RiskLevel.Safe,
    };

    private static int AlgorithmRisk(string algorithm, QuantumSafety quantum, int? keySize)
    {
        var baseRisk = (algorithm ?? "").ToUpperInvariant() switch
        {
            "MD5" => 9,
            "SHA1" => 7,
            "RC4" => 9,
            "DES" or "3DES" => 8,
            "RSA" => 8,
            "DSA" => 8,
            "ECC" or "ECDSA" or "ECDH" => 8,
            "AES" => 4,
            "AES-CBC" => 5,
            "AES-ECB" => 7,
            "TLS" => 6,
            _ => 5,
        };

        // Below-NIST RSA key sizes raise the risk.
        if (string.Equals(algorithm, "RSA", StringComparison.OrdinalIgnoreCase) && keySize is { } k && k < 2048)
            baseRisk = Math.Min(10, baseRisk + 2);

        // Quantum-safe primitives cap at low risk.
        if (quantum == QuantumSafety.QuantumSafe) baseRisk = Math.Min(baseRisk, 2);
        if (quantum == QuantumSafety.Hybrid) baseRisk = Math.Min(baseRisk, 5);

        // Two-tier taxonomy: Grover-weakened symmetric strength is a moderate,
        // deferred risk (halved security margin, not a break) — cap below the
        // Shor-broken tier. Classically broken primitives (MD5/SHA-1/RC4/DES)
        // are exploitable today: keep a high classical floor so the
        // algorithm-driven risk is never diluted.
        if (quantum == QuantumSafety.GroverWeakened) baseRisk = Math.Min(baseRisk, 6);
        if (quantum == QuantumSafety.ClassicallyBroken) baseRisk = Math.Max(baseRisk, 7);

        return baseRisk;
    }

    private static int UsageCriticality(string? usage) => (usage ?? "").ToLowerInvariant() switch
    {
        "key_exchange" => 9,
        "signing" => 8,
        "encryption" => 7,
        "tls_config" => 7,
        "key_storage" or "key_generation" => 8,
        "hashing" => 5,
        "test_helper" => 2,
        _ => 5,
    };

    private static int ExposureWeight(Exposure e) => e switch
    {
        Exposure.Public => 10,
        Exposure.Partner => 8,
        Exposure.Internal => 5,
        Exposure.DevOnly => 2,
        _ => 5,
    };

    private static int DataSensitivityWeight(DataSensitivity d) => d switch
    {
        DataSensitivity.Regulated => 10,
        DataSensitivity.Confidential => 7,
        DataSensitivity.Internal => 4,
        DataSensitivity.Public => 1,
        _ => 4,
    };

    private static int EnvironmentWeight(Environment e) => e switch
    {
        Environment.Production => 10,
        Environment.Staging => 6,
        Environment.Dev => 3,
        Environment.Test => 1,
        _ => 5,
    };

    private static int BusinessCriticalityWeight(BusinessCriticality b) => b switch
    {
        BusinessCriticality.Critical => 10,
        BusinessCriticality.High => 7,
        BusinessCriticality.Medium => 4,
        BusinessCriticality.Low => 2,
        _ => 4,
    };

    private static int RuntimeActivityWeight(RuntimeActivity r) => r switch
    {
        RuntimeActivity.Active => 10,
        RuntimeActivity.Inactive => 2,
        _ => 5,
    };

    private static int ComplianceRelevance(IReadOnlyList<string> tags)
    {
        if (tags is null || tags.Count == 0) return 0;
        foreach (var t in tags)
        {
            switch (t.ToUpperInvariant())
            {
                case "PCI": case "PCI-DSS":
                case "HIPAA":
                case "FEDRAMP":
                case "SOC2":
                    return 8;
            }
        }
        return 0;
    }

    private static int CompensatingControlsCredit(IReadOnlyList<string> controls)
    {
        if (controls is null || controls.Count == 0) return 0;
        var credit = 0;
        foreach (var c in controls)
        {
            credit += c.ToLowerInvariant() switch
            {
                "hsm" => 3,
                "vault" => 2,
                "key_rotation" => 1,
                _ => 0,
            };
        }
        return Math.Min(credit, 6);
    }
}

internal static class ScoringCoefficients
{
    // Coefficients applied to each factor before clamping.
    public const double AR   = 1.0;
    public const double UC   = 1.2;
    public const double EW   = 1.5;
    public const double DS   = 1.3;
    public const double EnvW = 1.4;
    public const double BC   = 1.0;
    public const double RA   = 0.8;
    public const double CR   = 0.6;
    public const double CC   = 1.0;
}

/// <summary>Marker for the documented weight tables — referenced by tests.</summary>
internal static class ScoringWeights
{
    public const string FormulaVersion = "v1";
}
