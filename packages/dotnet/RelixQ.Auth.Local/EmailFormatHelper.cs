// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Auth.Local;

/// <summary>
/// Pure email-format check. Deliberately cheap and lenient — the bar is "looks
/// like an email", not "RFC 5321 compliant". The real validation is the
/// round-trip verification email; this gate just keeps obviously-broken input
/// out of the signup / invite pipelines.
/// </summary>
public static class EmailFormatHelper
{
    public static bool IsLikelyEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        var trimmed = email.Trim();
        var at = trimmed.IndexOf('@');
        return at > 0 && at < trimmed.Length - 1 && trimmed.IndexOf('.', at) > at;
    }
}
