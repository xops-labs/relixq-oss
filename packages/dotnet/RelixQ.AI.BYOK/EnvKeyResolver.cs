// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.AI.BYOK;

/// <summary>
/// Resolves a BYOK API key with the canonical Relix-Q precedence:
///   1. Environment variable
///   2. Inline configuration value (e.g. read from appsettings.json)
///   3. Throw — never silently fall through.
///
/// Centralising this rule keeps every adapter consistent and gives a single
/// failure surface to test against. The env variable is canonical because it
/// is the easiest secret store to manage in containers and CI.
/// </summary>
public static class EnvKeyResolver
{
    /// <summary>
    /// Returns the first non-empty value among the named environment variable
    /// and the inline fallback. Throws <see cref="InvalidOperationException"/>
    /// if both are empty.
    /// </summary>
    public static string Resolve(string envVarName, string? configFallback, string providerLabel)
    {
        var fromEnv = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
        if (!string.IsNullOrWhiteSpace(configFallback)) return configFallback;

        throw new InvalidOperationException(
            $"No API key for {providerLabel}: set {envVarName} or supply the value via configuration.");
    }

    /// <summary>
    /// Non-throwing variant: returns the resolved key or <c>null</c> when both
    /// sources are empty. Use this when the adapter has to advertise
    /// <c>SupportsTier == false</c> instead of throwing on construction.
    /// </summary>
    public static string? TryResolve(string envVarName, string? configFallback)
    {
        var fromEnv = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
        if (!string.IsNullOrWhiteSpace(configFallback)) return configFallback;
        return null;
    }
}
