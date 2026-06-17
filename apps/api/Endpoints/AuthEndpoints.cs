// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using Microsoft.EntityFrameworkCore;
using RelixQ.Auth.Local;
using RelixQ.OssApi.Auth;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Domain;

namespace RelixQ.OssApi.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/auth");

        g.MapPost("/signup", async (
            SignupRequest req, HttpContext ctx, AppDbContext db,
            IPasswordHasher hasher, IPasswordStrengthValidator strength, CancellationToken ct) =>
        {
            var email = (req.Email ?? "").Trim().ToLowerInvariant();
            if (!EmailFormatHelper.IsLikelyEmail(email))
                return Results.BadRequest(new { error = "invalid_email" });

            var pwd = req.Password ?? "";
            var eval = strength.Evaluate(pwd, [email, req.DisplayName ?? ""]);
            if (!eval.Acceptable)
                return Results.BadRequest(new { error = "weak_password", feedback = eval.Feedback });

            if (await db.Users.AnyAsync(u => u.Email == email, ct))
                return Results.Conflict(new { error = "email_taken" });

            var (hash, algoId) = hasher.Hash(pwd);
            var user = new User
            {
                Email = email,
                DisplayName = string.IsNullOrWhiteSpace(req.DisplayName) ? email.Split('@')[0] : req.DisplayName!.Trim(),
                PasswordHash = hash,
                PasswordAlgoId = algoId,
            };
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);

            var token = await Sessions.IssueAsync(db, user.Id, ct);
            Sessions.SetCookie(ctx, token);
            return Results.Ok(new AuthResponse(UserDto.From(user), token));
        });

        g.MapPost("/login", async (
            LoginRequest req, HttpContext ctx, AppDbContext db, IPasswordHasher hasher, CancellationToken ct) =>
        {
            var email = (req.Email ?? "").Trim().ToLowerInvariant();
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
            if (user is null || !hasher.Verify(req.Password ?? "", user.PasswordHash))
                return Results.Json(new { error = "invalid_credentials" }, statusCode: StatusCodes.Status401Unauthorized);

            var token = await Sessions.IssueAsync(db, user.Id, ct);
            Sessions.SetCookie(ctx, token);
            return Results.Ok(new AuthResponse(UserDto.From(user), token));
        });

        g.MapPost("/logout", async (HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            await Sessions.ClearAsync(ctx, db, ct);
            return Results.Ok(new { ok = true });
        });

        g.MapGet("/me", async (HttpContext ctx, AppDbContext db, CancellationToken ct) =>
        {
            var user = await Sessions.ResolveAsync(ctx, db, ct);
            return user is null
                ? Results.Json(new { error = "unauthenticated" }, statusCode: StatusCodes.Status401Unauthorized)
                : Results.Ok(UserDto.From(user));
        });
    }
}
