<!-- Copyright (c) 2026 Yasvanth Udayakumar -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- See LICENSE in the repository root for full terms. -->
# RelixQ.Auth.Local

local-credential primitives — pure functions over inputs. No persistence, no HTTP, no DI container. Designed so an OSS self-host wires the same building blocks a full auth service would use, just without the SAML / OIDC / MFA / RLS surface.

## What's in this package

| Type | Purpose |
|---|---|
| `IPasswordHasher` | Hash, verify, and rotate-detect for password hashes |
| `Argon2idPasswordHasher` + `Argon2Options` | Argon2id implementation with self-describing hash string (`argon2id$v=19$m=...,t=...,p=...$salt$hash`) so params upgrade safely on next login |
| `IPasswordStrengthValidator` + `PasswordStrengthResult` | Pre-hash strength gate |
| `ZxcvbnPasswordStrengthValidator` + `PasswordStrengthOptions` | zxcvbn-cs implementation: min-length floor plus score floor (0..4) |
| `TokenPrimitives` | `GenerateOpaqueToken(int)` mints a random URL-safe bearer + matching SHA-256 hash at rest; `HashToken(string)` is the deterministic lookup hash |
| `EmailFormatHelper` | Cheap "looks like an email" check — the real validation is the round-trip verification email |

## Consumer pattern

```csharp
using RelixQ.Auth.Local;

// Hash on signup
IPasswordHasher hasher = new Argon2idPasswordHasher(new Argon2Options());
var (encoded, algoId) = hasher.Hash(plaintext);
// store encoded + algoId on the user row

// Verify on login
if (!hasher.Verify(plaintext, user.PasswordHash))
{
    return LoginOutcome.InvalidCredentials();
}
if (hasher.NeedsRehash(user.PasswordAlgo))
{
    var (newHash, newAlgo) = hasher.Hash(plaintext);
    user.SetPassword(newHash, newAlgo);
}

// Pre-hash strength check
IPasswordStrengthValidator strength = new ZxcvbnPasswordStrengthValidator(new PasswordStrengthOptions());
var s = strength.Evaluate(plaintext, [email, displayName]);
if (!s.Acceptable) return SignupOutcome.WeakPassword(s.Feedback);

// Mint a verification token; persist the hash, embed the raw form in the email URL
var (raw, hash) = TokenPrimitives.GenerateOpaqueToken();
db.EmailVerificationTokens.Add(EmailVerificationToken.Issue(user.UserId, hash, ...));
var url = template.Replace("{token}", Uri.EscapeDataString(raw));
```

## Consuming it

`apps/api` references this package directly for local email/password auth; it also publishes to NuGet as a standalone package. The full auth surface (OIDC / SAML / WebAuthn / MFA / SCIM / RLS) is out of scope for this package.

Constructors take the plain options class directly (not `IOptions<T>`) so the package has zero dependency on `Microsoft.Extensions.Options` or any DI container. A DI host wraps the options binding:

```csharp
services.Configure<Argon2Options>(config.GetSection("Argon2"));
services.AddSingleton<IPasswordHasher>(sp =>
    new Argon2idPasswordHasher(sp.GetRequiredService<IOptions<Argon2Options>>().Value));
```

## Out of scope for this package

- OIDC / SAML / WebAuthn integration
- MFA (TOTP, WebAuthn, recovery codes)
- API key issuance
- Device-code flow
- Refresh-token rotation, session management
- Tenant isolation enforcement (RLS), SCIM provisioning
- Email transport (this package mints the token; the caller sends the email)
- Persistence and lifecycle of `EmailVerificationToken` / `PasswordResetToken` entities (those stay in `Relixq.Auth.Domain`)
