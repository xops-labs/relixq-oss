// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RelixQ.OssApi.Auth;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Domain;

namespace RelixQ.OssApi.Endpoints;

/// <summary>
/// Report export for the web portal: the latest succeeded scan's findings as
/// JSON, SARIF 2.1.0, Markdown, or a standalone HTML report. Mirrors the
/// formats the relixq CLI emits so portal users get the same artifacts.
/// </summary>
public static class ExportEndpoints
{
    private const string GithubUrl = "https://github.com/xops-labs/relixq-oss";

    private static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static void MapExportEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/projects/{id}/export", async (
            string id, string? format, HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null)
                return Results.Json(new { error = "unauthenticated" }, statusCode: StatusCodes.Status401Unauthorized);
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();

            var project = await db.Projects.AsNoTracking().FirstOrDefaultAsync(p => p.Id == pid, ct);
            if (project is null) return Results.NotFound();

            var scan = await db.ScanRuns.AsNoTracking()
                .Where(s => s.ProjectId == pid && s.Status == "succeeded")
                .OrderByDescending(s => s.StartedAt)
                .FirstOrDefaultAsync(ct);
            if (scan is null) return Results.BadRequest(new { error = "no_succeeded_scan" });

            var findings = await db.Findings.AsNoTracking()
                .Where(f => f.ScanRunId == scan.Id)
                .OrderByDescending(f => f.Score)
                .ToListAsync(ct);

            var fmt = (format ?? "json").Trim().ToLowerInvariant();
            return fmt switch
            {
                "json" => Download(Json(project, scan, findings), "application/json", $"{project.Slug}-findings.json"),
                "sarif" => Download(Sarif(project, scan, findings), "application/sarif+json", $"{project.Slug}-findings.sarif"),
                "markdown" or "md" => Download(Markdown(project, scan, findings), "text/markdown", $"{project.Slug}-findings.md"),
                "html" => Download(Html(project, scan, findings), "text/html", $"{project.Slug}-findings.html"),
                _ => Results.BadRequest(new { error = "invalid_format", supported = new[] { "json", "sarif", "markdown", "html" } }),
            };
        });
    }

    private static IResult Download(string content, string contentType, string fileName) =>
        Results.File(Encoding.UTF8.GetBytes(content), $"{contentType}; charset=utf-8", fileName);

    // ---- JSON --------------------------------------------------------------

    private static string Json(Project p, ScanRun s, List<FindingRecord> findings)
    {
        var doc = new
        {
            tool = new { name = "Relix-Q OSS", informationUri = GithubUrl },
            project = new { id = p.Id, slug = p.Slug, name = p.Name, sourceKind = p.SourceKind },
            scan = new
            {
                id = s.Id,
                startedAt = s.StartedAt,
                completedAt = s.CompletedAt,
                riskScore = s.Score,
                scoreLevel = s.ScoreLevel,
                agilityScore = s.AgilityScore,
                agilityGrade = s.AgilityGrade,
                filesScanned = s.FilesScanned,
                findingCount = findings.Count,
            },
            findings = findings.Select(f => new
            {
                id = f.Id,
                ruleId = f.RuleId,
                language = f.Language,
                algorithm = f.Algorithm,
                severity = f.Severity,
                filePath = f.FilePath,
                lineNumber = f.LineNumber,
                // A single minified vendor line can be megabytes; cap it so the
                // export stays a report, not a source dump.
                snippet = Truncate(f.Snippet, 400),
                category = f.Category,
                message = f.Message,
                recommendation = f.Recommendation,
                score = f.Score,
                scoreLevel = f.ScoreLevel,
            }),
        };
        return JsonSerializer.Serialize(doc, Pretty);
    }

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max] + "…";

    // ---- SARIF 2.1.0 -------------------------------------------------------

    private static string Sarif(Project p, ScanRun s, List<FindingRecord> findings)
    {
        var ruleIds = findings.Select(f => f.RuleId).Distinct().ToList();
        var ruleIndex = ruleIds.Select((r, i) => (r, i)).ToDictionary(x => x.r, x => x.i);

        var rules = ruleIds.Select(rid =>
        {
            var sample = findings.First(f => f.RuleId == rid);
            return new
            {
                id = rid,
                shortDescription = new { text = sample.Message ?? $"{sample.Algorithm ?? "Weak crypto"} usage detected" },
                help = sample.Recommendation is null ? null : new { text = sample.Recommendation },
                properties = new { algorithm = sample.Algorithm, category = sample.Category },
            };
        });

        var results = findings.Select(f => new
        {
            ruleId = f.RuleId,
            ruleIndex = ruleIndex[f.RuleId],
            level = f.Severity switch
            {
                "critical" or "high" => "error",
                "medium" => "warning",
                _ => "note",
            },
            message = new { text = f.Message ?? $"{f.Algorithm ?? "Weak crypto"} usage ({f.RuleId})" },
            locations = new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = f.FilePath.Replace('\\', '/') },
                        region = new { startLine = Math.Max(1, f.LineNumber) },
                    },
                },
            },
            properties = new
            {
                severity = f.Severity,
                algorithm = f.Algorithm,
                riskScore = f.Score,
                scoreLevel = f.ScoreLevel,
                language = f.Language,
                category = f.Category,
            },
        });

        var doc = new Dictionary<string, object?>
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new object[]
            {
                new
                {
                    tool = new { driver = new { name = "Relix-Q OSS", informationUri = GithubUrl, rules } },
                    results,
                    properties = new
                    {
                        project = p.Name,
                        scanId = s.Id,
                        riskScore = s.Score,
                        agilityScore = s.AgilityScore,
                        agilityGrade = s.AgilityGrade,
                    },
                },
            },
        };
        return JsonSerializer.Serialize(doc, Pretty);
    }

    // ---- Markdown ----------------------------------------------------------

    private static string Markdown(Project p, ScanRun s, List<FindingRecord> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Relix-Q findings — {p.Name}");
        sb.AppendLine();
        sb.AppendLine($"Scan `{s.Id}` · started {s.StartedAt:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine();
        sb.AppendLine(
            $"**Risk score:** {s.Score?.ToString() ?? "—"} ({s.ScoreLevel ?? "n/a"}) · " +
            $"**Crypto agility:** {s.AgilityScore?.ToString() ?? "—"} ({s.AgilityGrade ?? "n/a"}) · " +
            $"**Findings:** {findings.Count} · **Files scanned:** {s.FilesScanned?.ToString() ?? "—"}");
        sb.AppendLine();
        sb.AppendLine(SeverityLine(findings));
        sb.AppendLine();
        sb.AppendLine("| Severity | Algorithm | Location | Risk | Rule |");
        sb.AppendLine("|---|---|---|---:|---|");
        foreach (var f in findings)
        {
            var location = MdEscape($"{f.FilePath}:{f.LineNumber}");
            sb.AppendLine($"| {f.Severity} | {MdEscape(f.Algorithm ?? "—")} | `{location}` | {f.Score} | {MdEscape(f.RuleId)} |");
        }
        sb.AppendLine();
        sb.AppendLine($"Generated by [Relix-Q OSS]({GithubUrl}).");
        return sb.ToString();
    }

    private static string MdEscape(string s) => s.Replace("|", "\\|");

    private static string SeverityLine(List<FindingRecord> findings)
    {
        var order = new[] { "critical", "high", "medium", "low", "info" };
        var parts = order
            .Select(sev => (sev, n: findings.Count(f => f.Severity == sev)))
            .Where(x => x.n > 0)
            .Select(x => $"{x.sev} {x.n}");
        return string.Join(" · ", parts);
    }

    // ---- HTML --------------------------------------------------------------

    private static string Html(Project p, ScanRun s, List<FindingRecord> findings)
    {
        static string H(string? v) => WebUtility.HtmlEncode(v ?? "—");

        var rows = new StringBuilder();
        foreach (var f in findings)
        {
            rows.Append("<tr>")
                .Append($"<td><span class=\"sev sev-{H(f.Severity)}\">{H(f.Severity)}</span></td>")
                .Append($"<td class=\"mono\">{H(f.Algorithm)}</td>")
                .Append($"<td class=\"mono small\">{H($"{f.FilePath}:{f.LineNumber}")}</td>")
                .Append($"<td class=\"mono right\">{f.Score}</td>")
                .Append($"<td class=\"mono small\">{H(f.RuleId)}</td>")
                .AppendLine("</tr>");
        }

        return $$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Relix-Q findings — {{H(p.Name)}}</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; color: #0f172a; margin: 2rem auto; max-width: 72rem; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  .meta { color: #475569; margin-bottom: 1.5rem; }
  .stats { display: flex; gap: 2rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }
  .stat b { font-size: 1.4rem; font-family: ui-monospace, monospace; display: block; }
  .stat span { color: #64748b; font-size: .8rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; color: #64748b; }
  .mono { font-family: ui-monospace, monospace; font-size: .82rem; }
  .small { color: #475569; word-break: break-all; }
  .right { text-align: right; }
  .sev { border-radius: 6px; padding: .1rem .5rem; font-size: .75rem; font-weight: 500; }
  .sev-critical { background: #fee2e2; color: #b91c1c; }
  .sev-high { background: #ffedd5; color: #c2410c; }
  .sev-medium { background: #fef3c7; color: #b45309; }
  .sev-low { background: #e0f2fe; color: #0369a1; }
  .sev-info { background: #f1f5f9; color: #475569; }
  footer { margin-top: 1.5rem; color: #64748b; font-size: .8rem; }
</style>
</head>
<body>
<h1>Relix-Q findings — {{H(p.Name)}}</h1>
<p class="meta">Scan <span class="mono">{{s.Id}}</span> · started {{s.StartedAt:yyyy-MM-dd HH:mm}} UTC · {{H(SeverityLine(findings))}}</p>
<div class="stats">
  <div class="stat"><b>{{H(s.Score?.ToString())}}</b><span>risk score ({{H(s.ScoreLevel)}})</span></div>
  <div class="stat"><b>{{H(s.AgilityScore?.ToString())}}</b><span>crypto agility ({{H(s.AgilityGrade)}})</span></div>
  <div class="stat"><b>{{findings.Count}}</b><span>findings</span></div>
  <div class="stat"><b>{{H(s.FilesScanned?.ToString())}}</b><span>files scanned</span></div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Algorithm</th><th>Location</th><th>Risk</th><th>Rule</th></tr></thead>
  <tbody>
{{rows}}  </tbody>
</table>
<footer>Generated by <a href="{{GithubUrl}}">Relix-Q OSS</a>.</footer>
</body>
</html>
""";
    }
}
