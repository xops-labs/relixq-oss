// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Auth.Local;

/// <summary>
/// Password hasher with parameter rotation support. Stored hashes encode the
/// algorithm + parameters so they're upgradeable on next login.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes a plaintext password using current target parameters.
    /// </summary>
    /// <returns>(hash, algoId) where algoId encodes the algorithm and parameters
    /// (e.g. "argon2id$v=19$m=65536,t=3,p=4").</returns>
    (string Hash, string AlgoId) Hash(string password);

    /// <summary>
    /// Verifies a password against a stored hash. Constant-time.
    /// </summary>
    bool Verify(string password, string hash);

    /// <summary>
    /// True if the stored params are weaker than the current target — caller should rehash.
    /// </summary>
    bool NeedsRehash(string algoId);
}
