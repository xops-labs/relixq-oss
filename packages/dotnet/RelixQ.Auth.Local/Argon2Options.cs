// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Auth.Local;

/// <summary>
/// Argon2id tuning parameters. Defaults match the production target
/// (64 MiB memory, 3 iterations, 4-way parallelism, 16-byte salt, 32-byte hash).
/// Tests should override with cheaper values so each call stays in the tens of
/// milliseconds.
/// </summary>
public sealed class Argon2Options
{
    /// <summary>Memory in KiB. Default 65536 = 64 MiB.</summary>
    public int MemoryKiB { get; set; } = 65536;

    public int Iterations { get; set; } = 3;
    public int Parallelism { get; set; } = 4;
    public int SaltBytes { get; set; } = 16;
    public int HashBytes { get; set; } = 32;
}
