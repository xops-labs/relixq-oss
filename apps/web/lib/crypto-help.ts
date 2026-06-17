// Algorithm-family knowledge base: why a family is flagged, how to migrate,
// and the relevant NIST standards. Single source of truth for the per-finding
// explanation panel and the /help page. Plain data — safe to import from both
// server and client components.

export interface NistRef {
  /** Full label, used on the help page. */
  label: string;
  /** Compact label for the inline standards line in the finding panel. */
  short: string;
  url: string;
}

export const KEM: NistRef = {
  label: 'FIPS 203 — ML-KEM (post-quantum key encapsulation)',
  short: 'FIPS 203 (ML-KEM)',
  url: 'https://csrc.nist.gov/pubs/fips/203/final',
};
export const SIG: NistRef = {
  label: 'FIPS 204 — ML-DSA (post-quantum digital signatures)',
  short: 'FIPS 204 (ML-DSA)',
  url: 'https://csrc.nist.gov/pubs/fips/204/final',
};
export const SLH: NistRef = {
  label: 'FIPS 205 — SLH-DSA (stateless hash-based signatures)',
  short: 'FIPS 205 (SLH-DSA)',
  url: 'https://csrc.nist.gov/pubs/fips/205/final',
};
export const TRANSITIONS: NistRef = {
  label: 'NIST SP 800-131A Rev. 2 — transitioning cryptographic algorithms',
  short: 'SP 800-131A',
  url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
};
export const SHA2: NistRef = {
  label: 'FIPS 180-4 — Secure Hash Standard (SHA-2)',
  short: 'FIPS 180-4 (SHA-2)',
  url: 'https://csrc.nist.gov/pubs/fips/180-4/upd1/final',
};
export const SHA3: NistRef = {
  label: 'FIPS 202 — SHA-3 Standard',
  short: 'FIPS 202 (SHA-3)',
  url: 'https://csrc.nist.gov/pubs/fips/202/final',
};
export const GCM: NistRef = {
  label: 'NIST SP 800-38D — AES-GCM authenticated encryption',
  short: 'SP 800-38D (AES-GCM)',
  url: 'https://csrc.nist.gov/pubs/sp/800/38/d/final',
};
export const PQC: NistRef = {
  label: 'NIST Post-Quantum Cryptography project',
  short: 'NIST PQC project',
  url: 'https://csrc.nist.gov/projects/post-quantum-cryptography',
};

export type ThreatModel = 'Shor-broken' | 'Classical' | 'Grover-weakened';

export interface CryptoFamily {
  /** Display name for the help-page cards. */
  name: string;
  /** Which attack class makes the family weak; shown as a badge. */
  threat: ThreatModel;
  /** Representative algorithm tags, for the help-page cards. */
  examples: string;
  /** Tested against the uppercased algorithm tag of a finding. */
  match: RegExp;
  why: string;
  fix: string;
  refs: NistRef[];
}

// Order matters: first match wins.
export const CRYPTO_FAMILIES: CryptoFamily[] = [
  {
    name: 'Key agreement',
    threat: 'Shor-broken',
    examples: 'ECDH, DH, X25519, X448',
    match: /ECDH|DIFFIE|^DH\b|X25519|X448/,
    why: 'Key agreement based on (elliptic-curve) discrete logarithms. Shor’s algorithm on a cryptographically relevant quantum computer recovers the shared secret, so traffic recorded today can be decrypted later ("harvest now, decrypt later").',
    fix: 'Migrate key establishment to ML-KEM (FIPS 203). During transition, use a hybrid scheme such as X25519MLKEM768 so security never drops below the classical baseline.',
    refs: [KEM, PQC, TRANSITIONS],
  },
  {
    name: 'Digital signatures',
    threat: 'Shor-broken',
    examples: 'ECDSA, DSA, EdDSA, Ed25519',
    match: /ECDSA|EDDSA|ED25519|ED448|^DSA\b/,
    why: 'Digital signatures based on (elliptic-curve) discrete logarithms. A cryptographically relevant quantum computer running Shor’s algorithm can forge signatures, breaking authenticity of anything signed with this key.',
    fix: 'Migrate signatures to ML-DSA (FIPS 204); SLH-DSA (FIPS 205) is a conservative hash-based alternative for firmware and long-lived roots of trust.',
    refs: [SIG, SLH, PQC],
  },
  {
    name: 'RSA',
    threat: 'Shor-broken',
    examples: 'RSA encryption, signatures, key transport',
    match: /RSA/,
    why: 'RSA’s security rests on integer factoring, which Shor’s algorithm solves efficiently on a quantum computer. Both RSA encryption (harvest-now-decrypt-later) and RSA signatures (future forgery) are affected.',
    fix: 'Replace RSA key transport with ML-KEM (FIPS 203) and RSA signatures with ML-DSA (FIPS 204). Inventory certificate chains and TLS configurations that pin RSA keys.',
    refs: [KEM, SIG, TRANSITIONS],
  },
  {
    name: 'Broken hashes',
    threat: 'Classical',
    examples: 'MD5, MD4, SHA-1',
    match: /MD5|MD4|\bSHA-?1\b/,
    why: 'This hash is classically broken — practical collision attacks exist on today’s hardware, no quantum computer required. It must not be used for signatures, certificates, or integrity protection.',
    fix: 'Use SHA-256 or stronger (SHA-2 family, FIPS 180-4) or SHA-3 (FIPS 202). For password storage use a dedicated KDF (e.g. PBKDF2, scrypt, Argon2) instead of a bare hash.',
    refs: [TRANSITIONS, SHA2, SHA3],
  },
  {
    name: 'Deprecated ciphers',
    threat: 'Classical',
    examples: 'DES, 3DES, RC4, RC2, Blowfish',
    match: /3DES|TDEA|TRIPLE|\bDES\b|RC4|RC2|BLOWFISH/,
    why: 'This cipher is deprecated or disallowed by NIST for protecting data — small block/key sizes make it exploitable with classical attacks today.',
    fix: 'Replace with AES-256 in an authenticated mode (AES-GCM, SP 800-38D). AES-256 also retains a comfortable margin against Grover’s quantum search.',
    refs: [TRANSITIONS, GCM],
  },
  {
    name: 'Symmetric ciphers',
    threat: 'Grover-weakened',
    examples: 'AES-128, ChaCha20, Camellia',
    match: /AES|CHACHA|CAMELLIA/,
    why: 'Symmetric ciphers are weakened (not broken) by quantum computers: Grover’s algorithm halves the effective key strength, and unauthenticated modes (ECB/CBC) carry classical risks regardless.',
    fix: 'Prefer AES-256 over AES-128 for long-lived data, and always use an authenticated mode such as AES-GCM (SP 800-38D).',
    refs: [GCM, TRANSITIONS],
  },
];

export const DEFAULT_FAMILY: Pick<CryptoFamily, 'name' | 'why' | 'fix' | 'refs'> = {
  name: 'Other weak crypto',
  why: 'This cryptographic usage matched a community rule for weak or quantum-vulnerable cryptography.',
  fix: 'Review the call site and migrate to a NIST-approved, quantum-resistant primitive appropriate for this usage.',
  refs: [PQC, TRANSITIONS],
};

export function familyFor(algorithm: string | null) {
  const tag = (algorithm ?? '').toUpperCase();
  return CRYPTO_FAMILIES.find((f) => f.match.test(tag)) ?? DEFAULT_FAMILY;
}
