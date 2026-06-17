// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Auth.Local;

public interface IPasswordStrengthValidator
{
    /// <summary>
    /// Validates that the password meets the configured strength threshold
    /// (length plus a structural/entropy score).
    /// </summary>
    PasswordStrengthResult Evaluate(string password, IEnumerable<string>? userInputs = null);
}

public sealed record PasswordStrengthResult(bool Acceptable, int Score, string? Feedback);
