// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Scoring;

/// <summary>
/// Pluggable scoring formula. Multiple versions co-exist for backward-compat
/// audit; the active formula is selected by version string.
/// </summary>
public interface IScoringFormula
{
    string Version { get; }
    ScoringResult Score(ScoringInputs inputs);
}

public interface IScoringFormulaRegistry
{
    IScoringFormula Active { get; }
    IScoringFormula Get(string version);
}
