# validation-corpus

The **labeled ground-truth corpus** behind RelixQ's scanner regression gate
(`packages/go/validationgate`, test `TestCorpus`): every file here is graded
instance-by-instance against `expected-findings.yaml`, and the gate fails the Go
test run on any miss, mislabel, or spurious flag. The PR/main CI workflow and
the release workflow both run that test suite.

**Every source file here is intentionally vulnerable.** Do not copy any of this
code into a real project, and do not "fix" the files — weakening a fixture
silently weakens the gate.

## Synthetic key material

`src/python/embedded_key.py` contains an inline `RSA PRIVATE KEY` marker with no
private-key body, and `certs/` contains certificate files. All of it is
**synthetic, throwaway, non-functional test material** generated solely for this
corpus. It protects nothing, is deployed nowhere, and exists only to grade the
scanner's hardcoded-key and certificate detectors without publishing usable
secret material. The two certs are self-signed (RSA-2048 /
sha256WithRSAEncryption and P-256 / ecdsa-with-SHA256) so the x509 detector can
be graded on both the public-key and the signature algorithm.

## Layout

| Path | Purpose |
|---|---|
| `src/{python,go,js,java,csharp}/` | Quantum-vulnerable API usage per language (bucket A), Grover-weakened symmetric crypto (bucket B), classically broken hashes/ciphers (bucket L), and PQC/AES-256 code that must NOT be flagged (bucket C) |
| `src/python/handrolled.py`, `src/python/handrolled_aes.py`, `src/go/handrolled_dh.go`, `src/js/handrolled_sha256.js` | Hand-rolled crypto with zero library imports: textbook RSA, AES S-box tables, an RFC 3526 MODP prime + big.Int modexp, and a SHA-256 K/IV table. Grades the constant-fingerprint pack (`rules-community/fingerprints`) and the file-level multi-signal promotion pass (`HANDROLLED_<ALG>_PROMOTED`, scanner `promote.go`) |
| `src/python/unmapped_lib.py` | Coverage-sentinel proof (bucket S): imports M2Crypto through an EVP API surface no rule recognizes; the scanner must emit exactly one info-level `CRYPTO_API_UNMAPPED` finding on the import line (scanner `sentinel.go`) instead of staying silent |
| `config/nginx.conf`, `config/sshd_config` | Config-layer crypto: cipher suites, host keys, KEX — plus the `ssl_protocols TLSv1.2 TLSv1.3` false-positive regression line |
| `certs/server-rsa.pem`, `certs/server-ecdsa.pem` | At-rest certificate scanning (x509 detector) |
| `vendor/legacylib/sign.py` | Pins the walker's vendored-dir exclusion policy (`policy_excluded` — not gated) |
| `requirements.txt`, `package.json`, `go.mod` | Dependency-scan (`pkg/sbom`) ground truth, incl. must-not-flag packages (liboqs-python, requests, express, cloudflare/circl) |
| `expected-findings.yaml` | The ground-truth manifest the gate loads |
| `.relixqignore` | Excludes the manifest/README from the scan itself and shadows `.gitignore` so the git-only `!vendor/` re-include never changes scan behavior |

## How the manifest works

`expected-findings.yaml` has four sections; the gate enforces them as four
subtests of `TestCorpus`:

1. **`instances` — recall.** Each entry is one crypto instance that must be
   matched by at least one finding: same file, algorithm in the accepted set
   (case-insensitive; punctuation folded so `AES-128 == AES128`;
   `3DES/TripleDES/DESede` are synonyms), line within ±2 when `line` is set
   (`line: null` = file-level), severity and `quantum_safety` within the
   accepted sets. `tier: floor` entries are always gated; `tier: ast` entries
   are asserted only when an AST runner for the file's language is registered
   in the test binary, and are logged as skipped otherwise. The optional
   `rule_id_prefix` separates instances that share file+algorithm (cert
   public-key vs signature findings).
2. **`forbidden` — no false positives.** No risk-tagged finding
   (`vulnerable`, `grover_weakened`, `classically_broken`) may appear at these
   locations. An optional `allow` block tolerates narrowly-scoped findings
   (e.g. a `hybrid`-tagged info/low note on `X25519MLKEM768`).
3. **`policy_excluded` — documented walker policy.** Files the scanner skips
   by design (vendored code). Not gated in either direction.
4. **`deps` — dependency-scan ground truth.** Per-package algorithm sets that
   must be flagged, and packages that must produce zero risk-tagged findings.

The gate additionally enforces **strict precision**: every finding the code
scan emits over this corpus must map to some instance by file+algorithm
(line-tolerant first, then file-level fallback), be tolerated by a `forbidden`
`allow` block, or sit in a `policy_excluded` file — anything else is reported
as an EXTRA and fails the test.

Bucket B/L instances encode the three-tier taxonomy (`grover_weakened`,
`classically_broken`) **strictly**. The rule packs now emit those values, so
any regression back to the old conflated `vulnerable` tagging shows up as a
MISMATCH and fails the gate.

Bucket S instances are **informational coverage sentinels**: a file that
imports a known classical crypto library but in which no rule recognizes any
API must yield exactly one `CRYPTO_API_UNMAPPED` finding (severity `info`,
`quantum_safety: unknown`). They participate in recall and precision like any
other instance and do not loosen the risk-tag `forbidden` semantics — a
sentinel finding is never risk-tagged.

## Adding an instance

1. Add the vulnerable (or must-not-flag) code to a corpus file — keep each
   instance on its own line, with stable surrounding context (the gate
   matches at ±2 lines).
2. Add an `instances` entry (next free id in its bucket: `A32`, `B11`, `L6`,
   `S2`) or a `forbidden` entry for bucket-C material. Encode the *correct*
   target labels, not whatever the rules happen to emit today.
3. If the new code legitimately produces extra findings on neighboring lines
   (an import plus a call site, say), either cover them with their own
   instances or place them so they fall inside an existing instance's
   file+algorithm map — the precision check must stay clean.
4. Run `go test ./validationgate/... -run TestCorpus -count=1` from
   `packages/go` and confirm the gate reports exactly the delta you expect
   (a new MISS until the rule lands is normal; a new EXTRA is not).
5. Never relabel an instance just to make the gate green — the manifest is
   the spec, the rules are the implementation.

## Module / workspace isolation

`go.mod` here declares `module example.com/corpus` purely as scan input. The
corpus sits outside `packages/go`, no `go.work` exists, and the repo root has
no `go.mod`, so Go tooling never builds it. Likewise `package.json` is not
matched by the npm workspace globs in the root `package.json`
(`packages/npm/*`, `apps/web`).
