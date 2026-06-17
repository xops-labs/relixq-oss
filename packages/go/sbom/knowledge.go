// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package sbom converts dependency manifests (requirements.txt,
// package.json, go.mod, etc.) into the canonical CryptoFinding schema by
// looking each package up in a static knowledge base of crypto-relevant
// libraries. The output flows into the cross-vertical fusion algorithm
// (internal/fusion) as a second independent detection channel — the
// foundation of Build #2's cross-channel corroboration.
//
// Coverage in v1 is intentionally narrow: three ecosystems (Python,
// JavaScript/Node, Go) and the ~40 most-deployed crypto-relevant
// packages within each. Adding ecosystems is mechanical (one parser
// per manifest format) and the knowledge base is a flat slice so
// rule-pack-style YAML migration is straightforward when the corpus
// outgrows in-code definition.
package sbom

import "github.com/relix-q/relix-q/finding"

// Ecosystem identifies which package-manager universe a CryptoLib
// entry belongs to. Used both for routing (which parser produces it)
// and for the fused-finding language tag.
type Ecosystem string

const (
	EcosystemPython     Ecosystem = "python"
	EcosystemJavaScript Ecosystem = "javascript"
	EcosystemGo         Ecosystem = "go"
)

// CryptoLib is one entry in the knowledge base. The fields are chosen
// so that an SBOM-derived Finding can be populated directly:
//
//   - PackageName / Ecosystem: identity (joins to manifest entries)
//   - Algorithms: discrete algorithm tags emitted as multiple findings
//     when one library covers several primitives (e.g. cryptography
//     covers RSA + ECDSA + AES + ...)
//   - Severity / Category: copied into the finding so downstream
//     consumers (fusion, scoring, dashboard) treat the SBOM finding
//     equivalently to an AST finding
//   - Deprecated: bumps severity and tags the finding for prioritisation
//   - PQReady: future-state filter — libraries already shipping PQC
//     primitives are migration-target candidates, not risks
type CryptoLib struct {
	PackageName string
	Ecosystem   Ecosystem
	Algorithms  []string
	Severity    string // info | low | medium | high | critical
	Category    string
	Deprecated  bool
	PQReady     bool
	Notes       string
}

// knowledgeBase is the static crypto-library corpus. Curated from the
// most commonly-deployed packages in each ecosystem (top-200 download
// rank on PyPI / npm / pkg.go.dev as of mid-2026, filtered to crypto-
// relevant). Each entry that names a primitive in Algorithms causes one
// finding to be emitted per dependency hit, so that fusion can join
// each primitive to AST findings independently.
//
// Maintenance note: this is intentionally in-code, not YAML, for v1.
// The deliberate trade-off is that adding entries requires a code
// review, which is correct for crypto-claim data — a misclassified
// "PQReady=true" entry would silently suppress real risks.
var knowledgeBase = []CryptoLib{
	// ============================================================
	// Python (PyPI)
	// ============================================================
	{
		PackageName: "cryptography",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "ECDSA", "AES", "SHA-256", "SHA-1", "HMAC", "X509"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "pyca/cryptography — comprehensive; PQC primitives from 45.x. Audit version pin.",
	},
	{
		PackageName: "pycrypto",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "DES", "3DES", "RC4", "MD5", "SHA-1"},
		Severity:    "high",
		Category:    "crypto-dependency",
		Deprecated:  true,
		Notes:       "pycrypto — UNMAINTAINED since 2013; known unfixed CVEs. Migrate to pycryptodome or cryptography.",
	},
	{
		PackageName: "pycryptodome",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "ECDSA", "AES", "DES", "3DES", "RC4", "MD5", "SHA-1", "SHA-256"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "pycrypto fork; still exposes DES/RC4/MD5 — audit call sites.",
	},
	{
		PackageName: "pycryptodomex",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "ECDSA", "AES", "DES", "3DES", "RC4", "MD5", "SHA-1", "SHA-256"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "pycryptodome under a sibling namespace; same audit applies.",
	},
	{
		PackageName: "m2crypto",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "DES", "3DES", "RC4", "MD5", "SHA-1"},
		Severity:    "high",
		Category:    "crypto-dependency",
		Deprecated:  true,
		Notes:       "M2Crypto — sparse maintenance; legacy OpenSSL bindings. Migrate to cryptography.",
	},
	{
		PackageName: "pyOpenSSL",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "X509", "TLS"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "pyOpenSSL — thin OpenSSL wrapper; algorithm strength depends on OpenSSL build.",
	},
	{
		PackageName: "ecdsa",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"ECDSA"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "pure-Python ECDSA — quantum-vulnerable; migration target.",
	},
	{
		PackageName: "rsa",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "pure-Python RSA — quantum-vulnerable; migration target.",
	},
	{
		PackageName: "bcrypt",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"BCRYPT"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "bcrypt — password hashing; not quantum-relevant but flag for completeness.",
	},
	{
		PackageName: "passlib",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"BCRYPT", "ARGON2", "PBKDF2"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "passlib — password hashing meta-library.",
	},
	{
		PackageName: "paramiko",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "DSA", "ECDSA", "SSH"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "paramiko — SSH client/server; uses cryptography under the hood.",
	},
	{
		PackageName: "pynacl",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"X25519", "ED25519", "POLY1305", "CHACHA20"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "PyNaCl — libsodium bindings; quantum-vulnerable curves but well-built. Audit for hybrid migration.",
	},
	{
		PackageName: "jwt",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "JWT — uses RSA/ECDSA for asymmetric token sigs; PQC migration target.",
	},
	{
		PackageName: "pyjwt",
		Ecosystem:   EcosystemPython,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "PyJWT — same shape as jwt; PQC migration target.",
	},

	// ============================================================
	// JavaScript / Node (npm)
	// ============================================================
	{
		PackageName: "crypto-js",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"AES", "DES", "3DES", "RC4", "MD5", "SHA-1", "SHA-256"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "CryptoJS — ships weak primitives by default (MD5/SHA-1/RC4/DES); audit call sites.",
	},
	{
		PackageName: "node-rsa",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"RSA"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "node-rsa — pure RSA; quantum-vulnerable; migration target.",
	},
	{
		PackageName: "jsonwebtoken",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "jsonwebtoken — JWT impl using node:crypto under the hood.",
	},
	{
		PackageName: "jose",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"RSA", "ECDSA", "ED25519", "AES"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "jose — JOSE primitives; broad coverage; flag for inventory.",
	},
	{
		PackageName: "bcryptjs",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"BCRYPT"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "bcryptjs — pure-JS bcrypt; password hashing only.",
	},
	{
		PackageName: "bcrypt",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"BCRYPT"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "bcrypt — native bindings; password hashing only.",
	},
	{
		PackageName: "node-forge",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"RSA", "AES", "DES", "3DES", "RC4", "MD5", "SHA-1", "X509"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "node-forge — broad crypto; includes weak primitives by default.",
	},
	{
		PackageName: "sjcl",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"AES", "SHA-256", "HMAC"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "Stanford JS Crypto Library — minimal; mainly AES/SHA-2.",
	},
	{
		PackageName: "elliptic",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"ECDSA", "ED25519"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "elliptic — pure-JS EC; quantum-vulnerable curves; migration target.",
	},
	{
		PackageName: "secp256k1",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"ECDSA"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "secp256k1 — Bitcoin/Ethereum curve; quantum-vulnerable; migration target.",
	},
	{
		PackageName: "tweetnacl",
		Ecosystem:   EcosystemJavaScript,
		Algorithms:  []string{"X25519", "ED25519", "POLY1305", "CHACHA20"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "TweetNaCl — small NaCl port; flag for hybrid-migration planning.",
	},

	// ============================================================
	// Go (go.mod imports)
	// ============================================================
	{
		PackageName: "golang.org/x/crypto",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"AES", "CHACHA20", "POLY1305", "X25519", "ED25519", "SSH", "ARGON2"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "golang.org/x/crypto — broad; quantum-vulnerable curves; standard for Go crypto.",
	},
	{
		PackageName: "github.com/aead/poly1305",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"POLY1305"},
		Severity:    "info",
		Category:    "crypto-dependency",
	},
	{
		PackageName: "github.com/btcsuite/btcd",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"ECDSA"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "btcsuite/btcd — Bitcoin curve secp256k1; quantum-vulnerable.",
	},
	{
		PackageName: "github.com/dgrijalva/jwt-go",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "high",
		Category:    "crypto-dependency",
		Deprecated:  true,
		Notes:       "dgrijalva/jwt-go — DEPRECATED, owner archived. Use golang-jwt/jwt or github.com/golang-jwt/jwt.",
	},
	{
		PackageName: "github.com/golang-jwt/jwt",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "medium",
		Category:    "crypto-dependency",
		Notes:       "golang-jwt/jwt — successor to dgrijalva; PQC migration target.",
	},
	{
		PackageName: "github.com/golang-jwt/jwt/v4",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "medium",
		Category:    "crypto-dependency",
	},
	{
		PackageName: "github.com/golang-jwt/jwt/v5",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"RSA", "ECDSA", "HMAC"},
		Severity:    "medium",
		Category:    "crypto-dependency",
	},
	{
		PackageName: "github.com/cloudflare/circl",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"ML-KEM", "ML-DSA", "SLH-DSA", "ECDSA", "ED25519"},
		Severity:    "info",
		Category:    "crypto-dependency",
		PQReady:     true,
		Notes:       "Cloudflare CIRCL — ships ML-KEM, ML-DSA. Recommended PQC migration target for Go.",
	},
	{
		PackageName: "filippo.io/age",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"X25519", "CHACHA20", "POLY1305"},
		Severity:    "info",
		Category:    "crypto-dependency",
		Notes:       "filippo.io/age — file encryption tool; quantum-vulnerable curves.",
	},
	{
		PackageName: "github.com/minio/sha256-simd",
		Ecosystem:   EcosystemGo,
		Algorithms:  []string{"SHA-256"},
		Severity:    "info",
		Category:    "crypto-dependency",
	},
}

// algorithmQuantumSafety maps a knowledge-base algorithm tag to the two-tier
// quantum-risk taxonomy used by code rules (see finding.QuantumSafety):
//
//   - classically broken primitives (MD5, SHA-1, RC4, single DES) →
//     classically_broken: exploitable today, no quantum computer required;
//   - Grover-tier symmetric strength (3DES, AES-128) → grover_weakened;
//   - everything else (RSA, ECDSA, DH, X25519, ED25519, X509, TLS, SSH, …) →
//     vulnerable (Shor-broken asymmetric / classical key exchange).
//
// PQ-ready libraries override this with quantum_safe at the call site.
func algorithmQuantumSafety(algo string) finding.QuantumSafety {
	switch lower(algo) {
	case "md5", "md4", "md2", "sha-1", "sha1", "rc4", "rc2", "des", "ripemd", "ripemd160", "ripemd-160":
		return finding.ClassicallyBroken
	case "3des", "tripledes", "desede", "aes-128", "aes128", "blowfish":
		return finding.GroverWeakened
	default:
		return finding.QuantumVulnerable
	}
}

// lookupKey is the case-folded (ecosystem, package-name) join key.
type lookupKey struct {
	Ecosystem   Ecosystem
	PackageName string
}

// libsByKey is built once at init to make Lookup() O(1). The map is
// keyed on (ecosystem, lowercased-name) to match the convention used by
// all three supported package managers — PyPI / npm / Go module paths
// are all case-folded by their respective installers.
var libsByKey = func() map[lookupKey]*CryptoLib {
	m := make(map[lookupKey]*CryptoLib, len(knowledgeBase))
	for i := range knowledgeBase {
		lib := &knowledgeBase[i]
		m[lookupKey{Ecosystem: lib.Ecosystem, PackageName: lower(lib.PackageName)}] = lib
	}
	return m
}()

// Lookup returns the knowledge-base entry for (ecosystem, package),
// or nil if the package is not crypto-relevant. The return is a
// pointer so callers can detect known vs unknown packages without an
// extra ok flag — unknown packages legitimately exist in any manifest
// and should not trigger a finding at all.
func Lookup(ecosystem Ecosystem, packageName string) *CryptoLib {
	return libsByKey[lookupKey{Ecosystem: ecosystem, PackageName: lower(packageName)}]
}

// lower is a tiny ASCII-only fold; package names in all three
// ecosystems are restricted to ASCII so a full Unicode case fold is
// overkill.
func lower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
