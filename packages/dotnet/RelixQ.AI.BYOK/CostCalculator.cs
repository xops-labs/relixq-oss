// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.AI.BYOK;

/// <summary>
/// Approximate per-1k-token costs in USD. Numbers are conservative ceilings —
/// actual provider invoices remain authoritative; this is an in-process
/// estimator used to enforce per-org budget caps in real time. Public so both
/// BYOK and hosted-provider adapters can reuse the table.
/// </summary>
public static class CostCalculator
{
    private static readonly (string Match, decimal InputPer1k, decimal OutputPer1k)[] Table =
    [
        ("gpt-4o-mini", 0.000150m, 0.000600m),
        ("gpt-4o",      0.002500m, 0.010000m),
        ("gpt-4.1",     0.002000m, 0.008000m),
        ("gpt-3.5",     0.000500m, 0.001500m),
        ("claude-haiku",0.000250m, 0.001250m),
        ("claude-sonnet",0.003000m,0.015000m),
        ("claude-opus", 0.015000m, 0.075000m),
        ("gemini-1.5-flash", 0.000075m, 0.000300m),
        ("gemini-1.5-pro",   0.001250m, 0.005000m),
    ];

    public static decimal Estimate(string model, int inputTokens, int outputTokens)
    {
        var lower = (model ?? string.Empty).ToLowerInvariant();
        foreach (var (match, ip, op) in Table)
        {
            if (lower.Contains(match, StringComparison.Ordinal))
                return decimal.Round((inputTokens / 1000m * ip) + (outputTokens / 1000m * op), 6);
        }
        // Unknown model — fall back to a conservative mid-range estimate so we
        // still charge the budget rather than letting a stranger run free.
        return decimal.Round((inputTokens / 1000m * 0.001m) + (outputTokens / 1000m * 0.003m), 6);
    }
}
