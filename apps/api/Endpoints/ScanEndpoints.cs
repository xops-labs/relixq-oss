// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using Microsoft.EntityFrameworkCore;
using RelixQ.OssApi.Auth;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Domain;
using RelixQ.OssApi.Scanning;

namespace RelixQ.OssApi.Endpoints;

public static class ScanEndpoints
{
    public static void MapScanEndpoints(this IEndpointRouteBuilder app)
    {
        // Trigger a scan: create the ScanRun, then run it in a background DI scope.
        app.MapPost("/api/v1/projects/{id}/scans", async (
            string id, HttpContext ctx, AppDbContext db, IServiceScopeFactory scopes, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();
            if (!await db.Projects.AnyAsync(p => p.Id == pid, ct)) return Results.NotFound();

            var scan = new ScanRun { ProjectId = pid, Status = "running" };
            db.ScanRuns.Add(scan);
            await db.SaveChangesAsync(ct);

            // Fire-and-forget; the client polls GET /scans/{id}. New scope so the
            // runner gets its own DbContext independent of this request's scope.
            _ = Task.Run(async () =>
            {
                using var scope = scopes.CreateScope();
                var runner = scope.ServiceProvider.GetRequiredService<ScanRunner>();
                await runner.ExecuteAsync(scan.Id);
            }, CancellationToken.None);

            return Results.Accepted($"/api/v1/scans/{scan.Id}", ScanRunDto.From(scan));
        });

        app.MapGet("/api/v1/projects/{id}/scans", async (
            string id, HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();

            var scans = await db.ScanRuns.AsNoTracking()
                .Where(s => s.ProjectId == pid)
                .OrderByDescending(s => s.StartedAt)
                .Take(50)
                .ToListAsync(ct);
            return Results.Ok(scans.Select(ScanRunDto.From));
        });

        app.MapGet("/api/v1/scans/{scanId}", async (
            string scanId, HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(scanId, out var sid)) return Results.NotFound();

            var scan = await db.ScanRuns.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sid, ct);
            return scan is null ? Results.NotFound() : Results.Ok(ScanRunDto.From(scan));
        });

        // Findings for a project — defaults to the latest scan, or ?scanId=.
        app.MapGet("/api/v1/projects/{id}/findings", async (
            string id, string? scanId, HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();

            Guid? sid = null;
            if (!string.IsNullOrEmpty(scanId) && Guid.TryParse(scanId, out var parsed)) sid = parsed;
            sid ??= (await db.ScanRuns.AsNoTracking()
                .Where(s => s.ProjectId == pid && s.Status == "succeeded")
                .OrderByDescending(s => s.StartedAt)
                .Select(s => (Guid?)s.Id)
                .FirstOrDefaultAsync(ct));

            if (sid is null) return Results.Ok(Array.Empty<FindingDto>());

            var findings = await db.Findings.AsNoTracking()
                .Where(f => f.ScanRunId == sid)
                .OrderByDescending(f => f.Score)
                .ToListAsync(ct);
            return Results.Ok(findings.Select(FindingDto.From));
        });

        // Latest project score (worst-finding aggregate + agility).
        app.MapGet("/api/v1/scores/projects/{id}", async (
            string id, HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null) return Unauth();
            if (!Guid.TryParse(id, out var pid)) return Results.NotFound();

            var scan = await db.ScanRuns.AsNoTracking()
                .Where(s => s.ProjectId == pid && s.Status == "succeeded")
                .OrderByDescending(s => s.StartedAt)
                .FirstOrDefaultAsync(ct);
            return scan is null
                ? Results.Ok(new { score = (int?)null, level = (string?)null, findingCount = 0 })
                : Results.Ok(new
                {
                    score = scan.Score,
                    level = scan.ScoreLevel,
                    findingCount = scan.FindingCount,
                    agilityScore = scan.AgilityScore,
                    agilityGrade = scan.AgilityGrade,
                    scanId = scan.Id.ToString(),
                });
        });
    }

    private static IResult Unauth() =>
        Results.Json(new { error = "unauthenticated" }, statusCode: StatusCodes.Status401Unauthorized);
}
