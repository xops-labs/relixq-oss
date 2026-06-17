// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
namespace RelixQ.OssApi.Domain;

/// <summary>A registered local-auth user. Single shared workspace (no tenancy).</summary>
public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string PasswordAlgoId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>An opaque bearer session. The raw token is in the cookie / Authorization
/// header; only its SHA-256 hash is stored, so a DB leak can't be replayed.</summary>
public class Session
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string TokenHash { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; } = DateTimeOffset.UtcNow.AddDays(7);
}

/// <summary>A scan target: a bundled sample, a git URL, or a path under the mounted local root.</summary>
public class Project
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Slug { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SourceKind { get; set; } = "sample"; // "sample" | "git" | "local" | "upload"
    public string SourceValue { get; set; } = string.Empty; // sample id | git URL | local subpath | upload id
    /// <summary>Optional access token for private git sources. Stored for re-scans; never
    /// returned by the API (see <c>ProjectDto.HasToken</c>) and redacted from logs/errors.</summary>
    public string? SourceToken { get; set; }
    public Guid OwnerId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>One scan execution against a project.</summary>
public class ScanRun
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProjectId { get; set; }
    public string Status { get; set; } = "running"; // running | succeeded | failed
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAt { get; set; }
    public int FindingCount { get; set; }
    public int? Score { get; set; }          // 0..100 worst-finding aggregate
    public string? ScoreLevel { get; set; }  // Safe..Severe
    public int? AgilityScore { get; set; }   // 0..100 crypto-agility (optional)
    public string? AgilityGrade { get; set; }
    public int? FilesScanned { get; set; }     // engine scan summary: scanned file count
    public string? LanguagesJson { get; set; } // engine scan summary: {"python": 12, ...}
    public string? Error { get; set; }
}

/// <summary>A persisted, scored finding row (flattened from the scanner CryptoFinding).</summary>
public class FindingRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ScanRunId { get; set; }
    public Guid ProjectId { get; set; }
    public string RuleId { get; set; } = string.Empty;
    public string Language { get; set; } = string.Empty;
    public string? Algorithm { get; set; }
    public string? UsageType { get; set; }
    public string? QuantumSafety { get; set; }
    public string Severity { get; set; } = "medium";
    public int? KeySize { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public string? Snippet { get; set; }
    public string? Category { get; set; }
    public string? Message { get; set; }
    public string? Recommendation { get; set; }
    public int Score { get; set; }
    public string ScoreLevel { get; set; } = "Safe";
}
