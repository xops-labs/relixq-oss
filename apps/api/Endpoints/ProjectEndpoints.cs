// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using System.Text;
using Microsoft.EntityFrameworkCore;
using RelixQ.OssApi.Auth;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Domain;
using RelixQ.OssApi.Scanning;

namespace RelixQ.OssApi.Endpoints;

public static class ProjectEndpoints
{
    public static void MapProjectEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/projects");

        // List all projects in the shared workspace (newest first), each with its latest scan.
        g.MapGet("", async (HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();

            var projects = await db.Projects.AsNoTracking()
                .OrderByDescending(p => p.CreatedAt).ToListAsync(ct);

            var dtos = new List<ProjectDto>(projects.Count);
            foreach (var p in projects)
                dtos.Add(ProjectDto.From(p, await LatestScan(db, p.Id, ct)));
            return Results.Ok(dtos);
        });

        g.MapGet("/{id}", async (string id, HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();

            var p = await db.Projects.AsNoTracking().FirstOrDefaultAsync(x => x.Id == pid, ct);
            return p is null ? Results.NotFound() : Results.Ok(ProjectDto.From(p, await LatestScan(db, p.Id, ct)));
        });

        g.MapPost("", async (CreateProjectRequest req, HttpContext ctx, AppDbContext db, ScanOptions opts, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();

            var name = (req.Name ?? "").Trim();
            if (name.Length == 0) return Results.BadRequest(new { error = "name_required" });

            var kind = (req.Source?.Kind ?? "sample").Trim().ToLowerInvariant();
            var value = (req.Source?.Value ?? "").Trim();
            var token = string.IsNullOrWhiteSpace(req.Source?.Token) ? null : req.Source!.Token!.Trim();
            if (kind is not ("sample" or "git" or "local" or "upload"))
                return Results.BadRequest(new { error = "invalid_source_kind" });
            if (kind == "git" && !value.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return Results.BadRequest(new { error = "git_url_required" });
            if (kind == "sample" && value.Length == 0) value = "sample-vulnerable";
            if (kind == "local")
            {
                value = value.Replace('\\', '/').Trim('/');           // normalize; "" = scan the whole mounted root
                if (value.Split('/').Any(seg => seg == ".."))         // no traversal out of the mounted root
                    return Results.BadRequest(new { error = "invalid_local_path" });
            }
            if (kind == "upload")
            {
                if (!Guid.TryParseExact(value, "N", out var uid) ||
                    !File.Exists(Path.Combine(opts.UploadsDir, $"{uid:N}.zip")))
                    return Results.BadRequest(new { error = "upload_not_found" });
            }
            if (kind != "git") token = null;                          // tokens only make sense for git

            var slug = string.IsNullOrWhiteSpace(req.Slug) ? Slugify(name) : Slugify(req.Slug!);
            if (slug.Length == 0) slug = "project";
            if (await db.Projects.AnyAsync(p => p.Slug == slug, ct))
                return Results.Conflict(new { error = "slug_taken" });

            var project = new Project
            {
                Slug = slug,
                Name = name,
                Description = (req.Description ?? "").Trim(),
                SourceKind = kind,
                SourceValue = value,
                SourceToken = token,
                OwnerId = user.Id,
            };
            db.Projects.Add(project);
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/v1/projects/{project.Id}", ProjectDto.From(project, null));
        });

        // Delete a project and everything derived from it: findings, scan runs,
        // and — when no other project references the same archive — the uploaded
        // zip. Refused while a scan is running so the runner never writes results
        // for a project that no longer exists.
        g.MapDelete("/{id}", async (string id, HttpContext ctx, AppDbContext db, ScanOptions opts, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();

            var p = await db.Projects.FirstOrDefaultAsync(x => x.Id == pid, ct);
            if (p is null) return Results.NotFound();

            if (await db.ScanRuns.AnyAsync(s => s.ProjectId == pid && s.Status == "running", ct))
                return Results.Conflict(new { error = "scan_in_progress" });

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Findings.Where(f => f.ProjectId == pid).ExecuteDeleteAsync(ct);
            await db.ScanRuns.Where(s => s.ProjectId == pid).ExecuteDeleteAsync(ct);
            db.Projects.Remove(p);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);

            if (string.Equals(p.SourceKind, "upload", StringComparison.OrdinalIgnoreCase) &&
                Guid.TryParseExact(p.SourceValue.Trim(), "N", out var uploadId) &&
                !await db.Projects.AnyAsync(
                    x => x.SourceKind == "upload" && x.SourceValue == p.SourceValue, ct))
            {
                var zip = Path.Combine(opts.UploadsDir, $"{uploadId:N}.zip");
                try { if (File.Exists(zip)) File.Delete(zip); }
                catch { /* best effort — an orphaned archive is harmless */ }
            }

            return Results.NoContent();
        });
    }

    private static async Task<ScanRun?> LatestScan(AppDbContext db, Guid projectId, CancellationToken ct) =>
        await db.ScanRuns.AsNoTracking()
            .Where(s => s.ProjectId == projectId)
            .OrderByDescending(s => s.StartedAt)
            .FirstOrDefaultAsync(ct);

    private static IResult Unauth() =>
        Results.Json(new { error = "unauthenticated" }, statusCode: StatusCodes.Status401Unauthorized);

    private static string Slugify(string s)
    {
        var sb = new StringBuilder(s.Length);
        var prevDash = false;
        foreach (var ch in s.Trim().ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(ch)) { sb.Append(ch); prevDash = false; }
            else if (!prevDash && sb.Length > 0) { sb.Append('-'); prevDash = true; }
        }
        return sb.ToString().Trim('-');
    }
}
