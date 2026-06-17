// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Scoring;

public sealed class ScoringFormulaRegistry : IScoringFormulaRegistry
{
    private readonly Dictionary<string, IScoringFormula> _versions;

    public ScoringFormulaRegistry(IEnumerable<IScoringFormula> formulas)
    {
        _versions = formulas.ToDictionary(f => f.Version, StringComparer.OrdinalIgnoreCase);
        if (!_versions.TryGetValue("v1", out var active))
            throw new InvalidOperationException("v1 formula must be registered");
        Active = active;
    }

    public IScoringFormula Active { get; }

    public IScoringFormula Get(string version)
    {
        if (string.IsNullOrEmpty(version)) return Active;
        return _versions.TryGetValue(version, out var f) ? f : Active;
    }
}
