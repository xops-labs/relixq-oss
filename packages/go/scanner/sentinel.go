// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// The "unmapped crypto" coverage sentinel: when a file demonstrably uses a
// known CLASSICAL crypto library but the entire detection stack (regex floor,
// AST precision layer, multi-signal promotion) recognized NOTHING in it, the
// scanner must say so instead of staying silent. This pass converts unknown
// coverage gaps into one visible, informational CRYPTO_API_UNMAPPED finding
// per file — "the crypto inventory for this file may be incomplete" — so
// missing rules surface as findings, not as silence.
//
// The knowledge table below is import/usage oriented and deliberately coarse:
// it only needs to prove "a crypto library is in play here", never to name an
// algorithm. PQC libraries (liboqs, circl, Kyber/ML-KEM, Dilithium/ML-DSA,
// pqcrypto, …) must NEVER trigger the sentinel: a matched line that also
// matches a PQC-exclusion pattern is skipped.
//
// Hooked in scanFile (scanner.go) AFTER all detection: a file with ANY
// finding never receives a sentinel, and the x509 branch (which parses cert
// material directly) is not covered. One sentinel max per file — the first
// matching import line wins.
package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"

	"github.com/relix-q/relix-q/finding"
)

const (
	// sentinelRuleID is the synthetic rule id; the validation-corpus manifest
	// references it via rule_id_prefix, so treat it as a public contract.
	sentinelRuleID   = "CRYPTO_API_UNMAPPED"
	sentinelCategory = "coverage-sentinel"

	// The sentinel proves "a crypto library is in play", never which
	// algorithm — so every classification field is the honest "unknown".
	sentinelAlgorithm = "UNKNOWN"
	sentinelUsageType = "unknown"

	// sentinelConfidence reflects exactly what is known: a crypto import with
	// zero recognized API usage is a coin-flip between an unmapped API and an
	// unused import.
	sentinelConfidence = 0.5

	sentinelRecommendation = "Review the file manually and report unrecognized crypto APIs so detection rules can be added."
)

// sentinelPQCExclusion suppresses the sentinel on any matched line that
// mentions a post-quantum library or primitive. PQC usage the rules don't map
// is NOT a classical-crypto coverage gap, and flagging PQC code is a
// product-credibility bug (compare the corpus forbidden entry for pqc.py).
// liboqs/oqs, cloudflare/circl, Kyber / ML-KEM, Dilithium / ML-DSA, SPHINCS+
// and the pqcrypto crate family are all excluded.
var sentinelPQCExclusion = regexp.MustCompile(
	`(?i)\b(?:lib)?oqs\b|\bcircl\b|kyber|dilithium|pqcrypto|ml[_-]?kem|ml[_-]?dsa|sphincs`)

// sentinelPattern is one knowledge-table row: a line-based import/usage
// regex for a known classical crypto library in one language. When the regex
// has capture groups, the first non-empty group names the library in the
// finding message; libName is the fallback. Per-entry exclusions extend the
// global PQC exclusion (both apply to the whole matched line).
type sentinelPattern struct {
	language   string
	libName    string
	re         *regexp.Regexp
	exclusions []*regexp.Regexp
}

// match reports whether the line matches this entry, returning the library
// name (first non-empty capture group, else libName) and the 1-based column
// of the match start.
func (p *sentinelPattern) match(line string) (lib string, column int, ok bool) {
	m := p.re.FindStringSubmatchIndex(line)
	if m == nil {
		return "", 0, false
	}
	lib = p.libName
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 && m[2*g+1] > m[2*g] {
			lib = line[m[2*g]:m[2*g+1]]
			break
		}
	}
	return lib, m[0] + 1, true
}

// JS/TS share one module system, so the same two patterns serve both
// languages: the node builtin (require/import of `crypto` / `node:crypto`)
// and the well-known classical crypto packages.
const (
	jsNodeCryptoPattern = `require\(\s*['"](?:node:)?(crypto)['"]\s*\)|from\s+['"](?:node:)?(crypto)['"]`
	jsCryptoPkgPattern  = `require\(\s*['"](jsonwebtoken|node-forge|elliptic|jsrsasign|crypto-js|node-rsa)['"]\s*\)|from\s+['"](jsonwebtoken|node-forge|elliptic|jsrsasign|crypto-js|node-rsa)['"]`
)

// sentinelKB is the per-language knowledge table of KNOWN CLASSICAL crypto
// library import/usage patterns. Extending coverage = appending a row.
// Keep entries import-shaped and word-bounded: a false sentinel on a file
// with no crypto at all would erode trust in the real ones.
var sentinelKB = []sentinelPattern{
	// Python: stdlib-adjacent and third-party classical crypto packages. The
	// short names (rsa, ecdsa, jwt, jose) are word-bounded so `import
	// rsa_helper` or `import jwtools` never match. `Crypto` covers both
	// PyCrypto and the PyCryptodome drop-in namespace; `Cryptodome` covers
	// the pycryptodomex flavor.
	{language: string(LangPython), libName: "python-crypto",
		re: regexp.MustCompile(`^\s*(?:from|import)\s+(cryptography|Cryptodome|Crypto|M2Crypto|OpenSSL|nacl|paramiko|pycryptodome|rsa|ecdsa|jwt|jose)\b`)},

	// JavaScript / TypeScript.
	{language: string(LangJavaScript), libName: "crypto", re: regexp.MustCompile(jsNodeCryptoPattern)},
	{language: string(LangJavaScript), libName: "js-crypto-package", re: regexp.MustCompile(jsCryptoPkgPattern)},
	{language: string(LangTypeScript), libName: "crypto", re: regexp.MustCompile(jsNodeCryptoPattern)},
	{language: string(LangTypeScript), libName: "js-crypto-package", re: regexp.MustCompile(jsCryptoPkgPattern)},

	// Java: JCA/JCE and BouncyCastle imports.
	{language: string(LangJava), libName: "java-crypto",
		re: regexp.MustCompile(`^\s*import\s+(?:static\s+)?(java\.security|javax\.crypto|org\.bouncycastle)\b`)},

	// Go: stdlib crypto/* and golang.org/x/crypto/* import paths. The PQC
	// exclusion keeps the Go 1.24+ stdlib `crypto/mlkem` from triggering.
	{language: string(LangGo), libName: "crypto",
		re: regexp.MustCompile(`"((?:golang\.org/x/)?crypto)/`)},

	// C#: .NET crypto namespace and BouncyCastle (using line or qualified use).
	{language: string(LangCSharp), libName: "System.Security.Cryptography",
		re: regexp.MustCompile(`^\s*using\s+(System\.Security\.Cryptography)\b`)},
	{language: string(LangCSharp), libName: "Org.BouncyCastle",
		re: regexp.MustCompile(`\b(Org\.BouncyCastle)\b`)},

	// Ruby / PHP / Rust.
	{language: string(LangRuby), libName: "openssl",
		re: regexp.MustCompile(`require\s+['"](openssl)['"]`)},
	{language: string(LangPHP), libName: "openssl",
		re: regexp.MustCompile(`\b(openssl)_[a-z0-9_]+`)},
	{language: string(LangPHP), libName: "phpseclib",
		re: regexp.MustCompile(`\b(phpseclib)\b`)},
	{language: string(LangRust), libName: "rust-crypto-crate",
		re: regexp.MustCompile(`\buse\s+(ring|openssl|rsa|aes|sha2)::`)},
}

// sentinelHit is the first (and only) knowledge-table match in a file.
type sentinelHit struct {
	Library string
	Line    int // 1-based
	Column  int // 1-based, match start (same convention as the regex detector)
	Snippet string
}

// detectUnmappedCrypto scans src line-by-line against the knowledge table
// for the given language. First match wins (lines outer, table order inner);
// matches on lines that also mention a PQC library are skipped. The caller
// (scanFile) guarantees the zero-findings precondition.
func detectUnmappedCrypto(language string, src []byte) (sentinelHit, bool) {
	var entries []*sentinelPattern
	for i := range sentinelKB {
		if sentinelKB[i].language == language {
			entries = append(entries, &sentinelKB[i])
		}
	}
	if len(entries) == 0 || !sentinelProbablyText(src) {
		return sentinelHit{}, false
	}

	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, e := range entries {
			lib, col, ok := e.match(line)
			if !ok {
				continue
			}
			if sentinelPQCExclusion.MatchString(line) || matchesAnyPattern(e.exclusions, line) {
				continue // PQC libraries must never trigger the sentinel
			}
			return sentinelHit{Library: lib, Line: lineNo, Column: col, Snippet: line}, true
		}
	}
	return sentinelHit{}, false
}

func matchesAnyPattern(res []*regexp.Regexp, line string) bool {
	for _, re := range res {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// sentinelProbablyText mirrors the regex detector's binary sniff: a NUL byte
// in the first 8 KiB strongly suggests binary content.
func sentinelProbablyText(buf []byte) bool {
	limit := len(buf)
	if limit > 8192 {
		limit = 8192
	}
	return bytes.IndexByte(buf[:limit], 0) < 0
}

// sentinelToFinding renders a hit as the canonical informational finding.
// Everything unknowable stays "unknown" — the sentinel reports a coverage
// gap, not a vulnerability, so it must never carry a risk-tagged
// quantum_safety value (the validation gate's forbidden semantics depend on
// that).
func sentinelToFinding(scanJobID, relPath, language string, h sentinelHit) *finding.Finding {
	return &finding.Finding{
		ScanJobID:     scanJobID,
		RuleID:        sentinelRuleID,
		Language:      language,
		Algorithm:     sentinelAlgorithm,
		UsageType:     sentinelUsageType,
		QuantumSafety: finding.QuantumUnknown,
		Severity:      finding.SeverityInfo,
		FilePath:      relPath,
		LineNumber:    h.Line,
		Column:        h.Column,
		Snippet:       h.Snippet,
		Confidence:    sentinelConfidence,
		Category:      sentinelCategory,
		Message: fmt.Sprintf(
			"File imports crypto library %q but no specific crypto API was recognized — possible scanner coverage gap; the crypto inventory for this file may be incomplete.",
			h.Library),
		Recommendation: sentinelRecommendation,
	}
}
