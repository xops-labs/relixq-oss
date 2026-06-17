// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Scoring;

// Value-type enums consumed by the scoring formula. Underlying int values
// match the persisted Domain enums one-for-one so an (int) cast bridges
// the two namespaces — see the ScoringInputsFactory in the risk-scoring
// service.

public enum RiskLevel
{
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    Severe = 5,
}

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum QuantumSafety
{
    Vulnerable = 0,
    Hybrid = 1,
    QuantumSafe = 2,
    Unknown = 3,
    // Two-tier quantum-risk taxonomy (wire values "grover_weakened" /
    // "classically_broken"). Appended after Unknown so existing int values
    // stay aligned with the persisted Domain enum.
    GroverWeakened = 4,
    ClassicallyBroken = 5,
}

public enum Environment
{
    Unknown = 0,
    Test = 1,
    Dev = 2,
    Staging = 3,
    Production = 4,
}

public enum Exposure
{
    Unknown = 0,
    DevOnly = 1,
    Internal = 2,
    Partner = 3,
    Public = 4,
}

public enum DataSensitivity
{
    Unknown = 0,
    Public = 1,
    Internal = 2,
    Confidential = 3,
    Regulated = 4,
}

public enum BusinessCriticality
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum RuntimeActivity
{
    Unknown = 0,
    Inactive = 1,
    Active = 2,
}
