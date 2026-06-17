// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using RelixQ.OssApi.Domain;

namespace RelixQ.OssApi;

// ---- Auth ----
public record SignupRequest(string Email, string Password, string? DisplayName);
public record LoginRequest(string Email, string Password);
public record AuthResponse(UserDto User, string Token);
public record UserDto(string Id, string Email, string DisplayName)
{
    public static UserDto From(User u) => new(u.Id.ToString(), u.Email, u.DisplayName);
}

// ---- Projects ----
// Token is inbound-only (private git sources); it is never echoed back — responses
// expose HasToken instead so a credential can't be read out of the API.
public record ProjectSourceDto(string Kind, string Value, string? Token = null);
public record CreateProjectRequest(string Name, string? Slug, string? Description, ProjectSourceDto Source);
public record ProjectDto(
    string Id, string Slug, string Name, string Description,
    ProjectSourceDto Source, bool HasToken, string CreatedAt,
    ScanRunDto? LatestScan)
{
    public static ProjectDto From(Project p, ScanRun? latest) => new(
        p.Id.ToString(), p.Slug, p.Name, p.Description,
        new ProjectSourceDto(p.SourceKind, p.SourceValue),
        !string.IsNullOrEmpty(p.SourceToken),
        p.CreatedAt.ToString("o"),
        latest is null ? null : ScanRunDto.From(latest));
}

// ---- Scans ----
public record ScanRunDto(
    string Id, string ProjectId, string Status,
    string StartedAt, string? CompletedAt,
    int FindingCount, int? Score, string? ScoreLevel,
    int? AgilityScore, string? AgilityGrade,
    int? FilesScanned, Dictionary<string, int>? Languages, string? Error)
{
    public static ScanRunDto From(ScanRun s) => new(
        s.Id.ToString(), s.ProjectId.ToString(), s.Status,
        s.StartedAt.ToString("o"), s.CompletedAt?.ToString("o"),
        s.FindingCount, s.Score, s.ScoreLevel,
        s.AgilityScore, s.AgilityGrade,
        s.FilesScanned, ParseLanguages(s.LanguagesJson), s.Error);

    private static Dictionary<string, int>? ParseLanguages(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, int>>(json);
        }
        catch (System.Text.Json.JsonException) { return null; }
    }
}

public record FindingDto(
    string Id, string RuleId, string Language, string? Algorithm,
    string Severity, string FilePath, int LineNumber, string? Snippet,
    string? Category, string? Message, string? Recommendation,
    int Score, string ScoreLevel)
{
    public static FindingDto From(FindingRecord f) => new(
        f.Id.ToString(), f.RuleId, f.Language, f.Algorithm,
        f.Severity, f.FilePath, f.LineNumber, f.Snippet,
        f.Category, f.Message, f.Recommendation, f.Score, f.ScoreLevel);
}
