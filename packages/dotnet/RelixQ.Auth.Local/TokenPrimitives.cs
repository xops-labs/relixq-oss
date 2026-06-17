// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
using System.Security.Cryptography;
using System.Text;

namespace RelixQ.Auth.Local;

/// <summary>
/// Pure helpers for email-verification, password-reset, and similar opaque
/// bearer tokens used by local-credential auth flows.
///
/// Convention: mint an N-byte token with <see cref="GenerateOpaqueToken"/>;
/// keep the raw form to embed in the outbound URL and persist
/// <see cref="HashToken"/> at rest so a database leak can't be replayed.
/// </summary>
public static class TokenPrimitives
{
    /// <summary>
    /// Mints a random URL-safe bearer token plus its at-rest SHA-256 hash.
    /// </summary>
    /// <param name="byteCount">Entropy in bytes. 32 (256 bits) is the standard.</param>
    /// <returns>(raw, hash) — embed raw in the URL, persist hash in the DB.</returns>
    public static (string Raw, string Hash) GenerateOpaqueToken(int byteCount = 32)
    {
        if (byteCount <= 0) throw new ArgumentOutOfRangeException(nameof(byteCount));

        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        var raw = Base64UrlEncode(bytes);
        return (raw, HashToken(raw));
    }

    /// <summary>
    /// SHA-256 hash of the UTF-8 bytes of <paramref name="raw"/>, lowercase hex.
    /// Deterministic, suitable for indexed lookup at rest.
    /// </summary>
    public static string HashToken(string raw)
    {
        var bytes = Encoding.UTF8.GetBytes(raw);
        var digest = SHA256.HashData(bytes);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Base64-URL (RFC 4648 §5) encoding with no padding. Pure helper.
    /// </summary>
    public static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
