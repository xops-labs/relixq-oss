// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Contracts;

/// <summary>
/// Canonical wire DTO for crypto findings emitted by Relix-Q scanners.
/// One JSONL row per match; mirrors the Go-side
/// finding.Finding struct in packages/go/finding/finding.go. JSON property
/// names are snake_case to match the scanner output without manual mapping.
/// </summary>
/// <remarks>
/// The persisted aggregate root with status transitions, audit fields, and
/// enrichment context is maintained separately as
/// Relixq.RiskScoring.Domain.CryptoFinding and is out of scope here. This DTO
/// is the immutable wire shape only.
/// </remarks>
public sealed class CryptoFinding
{
    public string FindingId { get; set; } = string.Empty;
    public string ScanJobId { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string Language { get; set; } = string.Empty;
    public string? Algorithm { get; set; }
    public string? UsageType { get; set; }
    public string? QuantumSafety { get; set; }
    public string Severity { get; set; } = "medium";
    public int? KeySize { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public int? Column { get; set; }
    public string? Snippet { get; set; }
    public List<string>? SnippetContext { get; set; }
    public double Confidence { get; set; }
    public string? Category { get; set; }
    public string? Message { get; set; }
    public string? Recommendation { get; set; }
    public List<string>? References { get; set; }
    public List<int>? Cwe { get; set; }
    public string? GitBlameAuthor { get; set; }
    public string? GitBlameCommit { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public string? DeltaState { get; set; }
}
