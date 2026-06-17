// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
using Zxcvbn;

namespace RelixQ.Auth.Local;

/// <summary>
/// Password strength validator backed by zxcvbn-cs. Combines a minimum length
/// gate with a minimum zxcvbn score (0..4); both must pass for the password
/// to be accepted.
/// </summary>
public sealed class ZxcvbnPasswordStrengthValidator : IPasswordStrengthValidator
{
    private readonly PasswordStrengthOptions _opts;

    public ZxcvbnPasswordStrengthValidator(PasswordStrengthOptions opts) => _opts = opts;

    public PasswordStrengthResult Evaluate(string password, IEnumerable<string>? userInputs = null)
    {
        if (string.IsNullOrEmpty(password))
            return new PasswordStrengthResult(false, 0, "Password is required.");

        if (password.Length < _opts.MinLength)
            return new PasswordStrengthResult(false, 0,
                $"Password must be at least {_opts.MinLength} characters.");

        var result = Core.EvaluatePassword(password, userInputs?.ToArray());
        var feedback = string.IsNullOrWhiteSpace(result.Feedback?.Warning)
            ? result.Feedback?.Suggestions?.FirstOrDefault()
            : result.Feedback?.Warning;

        return new PasswordStrengthResult(
            Acceptable: result.Score >= _opts.MinScore,
            Score: result.Score,
            Feedback: feedback);
    }
}
