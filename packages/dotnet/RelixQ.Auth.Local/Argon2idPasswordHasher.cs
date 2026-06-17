// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace RelixQ.Auth.Local;

/// <summary>
/// Argon2id password hasher with a self-describing string format:
///   argon2id$v=19$m={mem},t={iter},p={par}${saltB64}${hashB64}
/// The format encodes the parameters so <see cref="NeedsRehash"/> can detect
/// "below target" hashes on next login and the caller can rehash without
/// ever storing plaintext.
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    private const string AlgoPrefix = "argon2id";
    private const int Version = 19;

    private readonly Argon2Options _opts;

    public Argon2idPasswordHasher(Argon2Options opts) => _opts = opts;

    public (string Hash, string AlgoId) Hash(string password)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("Password required", nameof(password));

        var salt = new byte[_opts.SaltBytes];
        RandomNumberGenerator.Fill(salt);

        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = _opts.Parallelism,
            Iterations = _opts.Iterations,
            MemorySize = _opts.MemoryKiB,
        };
        var hashBytes = argon.GetBytes(_opts.HashBytes);

        var algoId = BuildAlgoId(_opts.MemoryKiB, _opts.Iterations, _opts.Parallelism);
        var encoded = $"{algoId}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hashBytes)}";
        return (encoded, algoId);
    }

    public bool Verify(string password, string hash)
    {
        if (string.IsNullOrEmpty(hash)) return false;

        var parts = hash.Split('$');
        // Expected: ["argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
        if (parts.Length != 5) return false;
        if (parts[0] != AlgoPrefix) return false;
        if (!parts[1].StartsWith("v=", StringComparison.Ordinal)) return false;

        var paramSection = parts[2];
        if (!TryParseParams(paramSection, out var mem, out var iter, out var par)) return false;

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[3]);
            expected = Convert.FromBase64String(parts[4]);
        }
        catch (FormatException)
        {
            return false;
        }

        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = par,
            Iterations = iter,
            MemorySize = mem,
        };
        var actual = argon.GetBytes(expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public bool NeedsRehash(string algoId)
    {
        if (string.IsNullOrEmpty(algoId)) return true;
        if (!algoId.StartsWith(AlgoPrefix, StringComparison.Ordinal)) return true;

        var parts = algoId.Split('$');
        if (parts.Length < 3) return true;
        if (!TryParseParams(parts[2], out var mem, out var iter, out var par)) return true;

        return mem < _opts.MemoryKiB
            || iter < _opts.Iterations
            || par < _opts.Parallelism;
    }

    private static string BuildAlgoId(int mem, int iter, int par) =>
        $"{AlgoPrefix}$v={Version}$m={mem},t={iter},p={par}";

    private static bool TryParseParams(string s, out int mem, out int iter, out int par)
    {
        mem = iter = par = 0;
        foreach (var kv in s.Split(','))
        {
            var eq = kv.IndexOf('=');
            if (eq <= 0) return false;
            var key = kv[..eq];
            var val = kv[(eq + 1)..];
            if (!int.TryParse(val, out var n)) return false;
            switch (key)
            {
                case "m": mem = n; break;
                case "t": iter = n; break;
                case "p": par = n; break;
            }
        }
        return mem > 0 && iter > 0 && par > 0;
    }
}
