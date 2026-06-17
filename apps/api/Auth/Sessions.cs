// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using Microsoft.EntityFrameworkCore;
using RelixQ.Auth.Local;
using RelixQ.OssApi.Data;
using RelixQ.OssApi.Domain;

namespace RelixQ.OssApi.Auth;

/// <summary>
/// Opaque-bearer session helpers. The raw token travels in the
/// <c>relixq_session</c> cookie or an <c>Authorization: Bearer</c> header; only
/// its SHA-256 hash (via <see cref="TokenPrimitives"/>) is stored at rest.
/// </summary>
public static class Sessions
{
    public const string CookieName = "relixq_session";

    /// <summary>Mints a session for the user, persists its hash, and returns the raw token.</summary>
    public static async Task<string> IssueAsync(AppDbContext db, Guid userId, CancellationToken ct)
    {
        var (raw, hash) = TokenPrimitives.GenerateOpaqueToken();
        db.Sessions.Add(new Session { TokenHash = hash, UserId = userId });
        await db.SaveChangesAsync(ct);
        return raw;
    }

    public static void SetCookie(HttpContext ctx, string rawToken)
    {
        ctx.Response.Cookies.Append(CookieName, rawToken, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps,
            Path = "/",
            Expires = DateTimeOffset.UtcNow.AddDays(7),
        });
    }

    public static async Task ClearAsync(HttpContext ctx, AppDbContext db, CancellationToken ct)
    {
        var raw = ExtractToken(ctx);
        if (raw is not null)
        {
            var hash = TokenPrimitives.HashToken(raw);
            await db.Sessions.Where(s => s.TokenHash == hash).ExecuteDeleteAsync(ct);
        }
        ctx.Response.Cookies.Delete(CookieName);
    }

    public static string? ExtractToken(HttpContext ctx)
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var t = auth["Bearer ".Length..].Trim();
            if (!string.IsNullOrEmpty(t)) return t;
        }
        if (ctx.Request.Cookies.TryGetValue(CookieName, out var c) && !string.IsNullOrEmpty(c)) return c;
        return null;
    }

    /// <summary>Resolves the current user from the request, or null if unauthenticated.</summary>
    public static async Task<User?> ResolveAsync(HttpContext ctx, AppDbContext db, CancellationToken ct)
    {
        var raw = ExtractToken(ctx);
        if (raw is null) return null;
        var hash = TokenPrimitives.HashToken(raw);
        var session = await db.Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.TokenHash == hash, ct);
        if (session is null || session.ExpiresAt < DateTimeOffset.UtcNow) return null;
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == session.UserId, ct);
    }
}
