// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using RelixQ.OssApi.Auth;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Scanning;

namespace RelixQ.OssApi.Endpoints;

public static class UploadEndpoints
{
    public static void MapUploadEndpoints(this IEndpointRouteBuilder app)
    {
        // Receive a source archive (.zip) and stash it for a later "upload" project.
        // Returns an opaque uploadId the client passes as the project's source value.
        app.MapPost("/api/v1/uploads", async (
            HttpRequest request, HttpContext ctx, AppDbContext db, ScanOptions opts, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            if (user is null)
                return Results.Json(new { error = "unauthenticated" }, statusCode: StatusCodes.Status401Unauthorized);

            if (!request.HasFormContentType)
                return Results.BadRequest(new { error = "expected_multipart" });

            var form = await request.ReadFormAsync(ct);
            var file = form.Files.GetFile("file") ?? form.Files.FirstOrDefault();
            if (file is null || file.Length == 0)
                return Results.BadRequest(new { error = "file_required" });
            if (!file.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                return Results.BadRequest(new { error = "zip_required" });

            Directory.CreateDirectory(opts.UploadsDir);
            var uploadId = Guid.NewGuid();
            var dest = Path.Combine(opts.UploadsDir, $"{uploadId:N}.zip");
            await using (var fs = File.Create(dest))
                await file.CopyToAsync(fs, ct);

            return Results.Ok(new { uploadId = uploadId.ToString("N") });
        });
    }
}
