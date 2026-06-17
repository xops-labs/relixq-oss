// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Auth.Local;

public sealed class PasswordStrengthOptions
{
    public int MinLength { get; set; } = 12;
    public int MinScore { get; set; } = 3;
}
