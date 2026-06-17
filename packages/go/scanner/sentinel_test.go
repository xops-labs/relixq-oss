// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
)

// TestDetectUnmappedCrypto_table exercises the knowledge table directly:
// classical imports match (with the right library name, line, and column),
// PQC imports and non-crypto code never match, and the first matching import
// wins.
func TestDetectUnmappedCrypto_table(t *testing.T) {
	cases := []struct {
		name     string
		language Language
		src      string
		wantHit  bool
		wantLib  string
		wantLine int
	}{
		{
			name:     "python M2Crypto import",
			language: LangPython,
			src:      "\"\"\"doc\"\"\"\nfrom M2Crypto import EVP\n\nmd = EVP.MessageDigest('ripemd160')\n",
			wantHit:  true, wantLib: "M2Crypto", wantLine: 2,
		},
		{
			name:     "python short name rsa word-bounded",
			language: LangPython,
			src:      "import rsa\n",
			wantHit:  true, wantLib: "rsa", wantLine: 1,
		},
		{
			name:     "python rsa_helper must not match",
			language: LangPython,
			src:      "import rsa_helper\nimport jwtools\n",
			wantHit:  false,
		},
		{
			name:     "python non-crypto imports",
			language: LangPython,
			src:      "import os\nimport requests\n\nprint('hello')\n",
			wantHit:  false,
		},
		{
			name:     "python PQC-only import (oqs not in KB)",
			language: LangPython,
			src:      "import oqs\nwith oqs.KeyEncapsulation('ML-KEM-768') as kem:\n    pass\n",
			wantHit:  false,
		},
		{
			name:     "python classical-looking import excluded by PQC token on the line",
			language: LangPython,
			src:      "from Crypto import kyber_bindings\n",
			wantHit:  false,
		},
		{
			name:     "python first match wins",
			language: LangPython,
			src:      "import os\nimport jwt\nfrom Crypto.Cipher import AES\n",
			wantHit:  true, wantLib: "jwt", wantLine: 2,
		},
		{
			name:     "go stdlib crypto import",
			language: LangGo,
			src:      "package main\n\nimport (\n\t\"fmt\"\n\t\"crypto/rsa\"\n)\n",
			wantHit:  true, wantLib: "crypto", wantLine: 5,
		},
		{
			name:     "go x/crypto import",
			language: LangGo,
			src:      "package main\n\nimport \"golang.org/x/crypto/ssh\"\n",
			wantHit:  true, wantLib: "golang.org/x/crypto", wantLine: 3,
		},
		{
			name:     "go stdlib PQC crypto/mlkem excluded",
			language: LangGo,
			src:      "package main\n\nimport \"crypto/mlkem\"\n",
			wantHit:  false,
		},
		{
			name:     "go circl excluded",
			language: LangGo,
			src:      "package main\n\nimport \"github.com/cloudflare/circl/kem/kyber/kyber768\"\n",
			wantHit:  false,
		},
		{
			name:     "js require node:crypto",
			language: LangJavaScript,
			src:      "const c = require('node:crypto');\n",
			wantHit:  true, wantLib: "crypto", wantLine: 1,
		},
		{
			name:     "js esm import jsonwebtoken",
			language: LangJavaScript,
			src:      "import jwt from 'jsonwebtoken';\n",
			wantHit:  true, wantLib: "jsonwebtoken", wantLine: 1,
		},
		{
			name:     "ts from crypto",
			language: LangTypeScript,
			src:      "import { createHash } from \"crypto\";\n",
			wantHit:  true, wantLib: "crypto", wantLine: 1,
		},
		{
			name:     "java javax.crypto import",
			language: LangJava,
			src:      "package x;\n\nimport javax.crypto.Cipher;\n",
			wantHit:  true, wantLib: "javax.crypto", wantLine: 3,
		},
		{
			name:     "csharp using System.Security.Cryptography",
			language: LangCSharp,
			src:      "using System.Security.Cryptography;\n",
			wantHit:  true, wantLib: "System.Security.Cryptography", wantLine: 1,
		},
		{
			name:     "ruby require openssl",
			language: LangRuby,
			src:      "require 'openssl'\n",
			wantHit:  true, wantLib: "openssl", wantLine: 1,
		},
		{
			name:     "php openssl_ function",
			language: LangPHP,
			src:      "<?php\n$x = openssl_encrypt($d, 'aes-128-cbc', $k);\n",
			wantHit:  true, wantLib: "openssl", wantLine: 2,
		},
		{
			name:     "rust use rsa crate",
			language: LangRust,
			src:      "use rsa::RsaPrivateKey;\n",
			wantHit:  true, wantLib: "rsa", wantLine: 1,
		},
		{
			name:     "language without KB entries",
			language: LangPerl,
			src:      "use Crypt::OpenSSL::RSA;\n",
			wantHit:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := detectUnmappedCrypto(string(tc.language), []byte(tc.src))
			if ok != tc.wantHit {
				t.Fatalf("detectUnmappedCrypto hit=%v, want %v (hit=%+v)", ok, tc.wantHit, hit)
			}
			if !ok {
				return
			}
			if hit.Library != tc.wantLib {
				t.Errorf("library = %q, want %q", hit.Library, tc.wantLib)
			}
			if hit.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", hit.Line, tc.wantLine)
			}
			if hit.Column < 1 {
				t.Errorf("column = %d, want >= 1", hit.Column)
			}
			if hit.Snippet == "" {
				t.Errorf("snippet is empty")
			}
		})
	}
}

// sentinelTestPack returns a minimal python rule pack: one rule that can
// never match (so the sentinel path is reachable — scanFile skips languages
// with zero applicable rules) and one real md5 rule for the
// "existing finding suppresses the sentinel" case.
func sentinelTestPack(t *testing.T) *rules.Pack {
	t.Helper()
	loaded, err := rules.LoadBytes([]byte(`
- id: PY_NEVER_MATCHES
  language: python
  severity: low
  algorithm: NONE
  detector: { type: regex, pattern: '\bRELIXQ_SENTINEL_TEST_NEVER_MATCHES\b' }
- id: PY_MD5_TEST
  language: python
  severity: high
  algorithm: MD5
  quantum_safety: classically_broken
  detector: { type: regex, pattern: '\bhashlib\.md5\s*\(' }
`))
	if err != nil {
		t.Fatal(err)
	}
	return rules.NewPackForTest(loaded)
}

// scanOneFile writes src to name inside a temp repo, scans it with the
// sentinel test pack, and returns the emitted findings.
func scanOneFile(t *testing.T, name, src string) []finding.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "findings.jsonl")
	scn := New(Job{ScanJobID: "sentinel-test"}, nil)
	if _, err := scn.Scan(context.Background(), ScanRequest{
		RepoPath: dir,
		Pack:     sentinelTestPack(t),
		Output:   out,
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	all, err := finding.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

// TestScanner_sentinelEmitsOnUnmappedCryptoFile: classical import, nothing
// recognized → exactly one CRYPTO_API_UNMAPPED finding with the contract
// labels (info / unknown / UNKNOWN / 0.5) pinned to the import line.
func TestScanner_sentinelEmitsOnUnmappedCryptoFile(t *testing.T) {
	src := "\"\"\"Uses a crypto library through an API the scanner has no rule for.\"\"\"\n" +
		"from M2Crypto import EVP\n" +
		"\n" +
		"md = EVP.MessageDigest('ripemd160')\n"
	all := scanOneFile(t, "unmapped.py", src)
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(all), all)
	}
	f := all[0]
	if f.RuleID != "CRYPTO_API_UNMAPPED" {
		t.Errorf("rule_id = %q, want CRYPTO_API_UNMAPPED", f.RuleID)
	}
	if f.Category != "coverage-sentinel" {
		t.Errorf("category = %q, want coverage-sentinel", f.Category)
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("severity = %q, want info", f.Severity)
	}
	if f.QuantumSafety != finding.QuantumUnknown {
		t.Errorf("quantum_safety = %q, want unknown", f.QuantumSafety)
	}
	if f.Algorithm != "UNKNOWN" {
		t.Errorf("algorithm = %q, want UNKNOWN", f.Algorithm)
	}
	if f.UsageType != "unknown" {
		t.Errorf("usage_type = %q, want unknown", f.UsageType)
	}
	if f.Confidence != 0.5 {
		t.Errorf("confidence = %v, want 0.5", f.Confidence)
	}
	if f.LineNumber != 2 {
		t.Errorf("line_number = %d, want 2 (the import line)", f.LineNumber)
	}
	if !strings.Contains(f.Snippet, "M2Crypto") {
		t.Errorf("snippet %q should contain the import line", f.Snippet)
	}
	if !strings.Contains(f.Message, `"M2Crypto"`) {
		t.Errorf("message %q should name the library", f.Message)
	}
	if f.Language != string(LangPython) {
		t.Errorf("language = %q, want python", f.Language)
	}
}

// TestScanner_sentinelSuppressedByExistingFinding: a file with a classical
// import AND a recognized API gets only the real finding — never a sentinel.
func TestScanner_sentinelSuppressedByExistingFinding(t *testing.T) {
	src := "from M2Crypto import EVP\n" +
		"import hashlib\n" +
		"\n" +
		"h = hashlib.md5(b'x')\n"
	all := scanOneFile(t, "mixed.py", src)
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(all), all)
	}
	if all[0].RuleID != "PY_MD5_TEST" {
		t.Errorf("rule_id = %q, want PY_MD5_TEST", all[0].RuleID)
	}
	for _, f := range all {
		if f.RuleID == "CRYPTO_API_UNMAPPED" {
			t.Errorf("sentinel must not fire when the file already has findings")
		}
	}
}

// TestScanner_sentinelIgnoresPQCOnlyFile: PQC imports must never trigger the
// sentinel.
func TestScanner_sentinelIgnoresPQCOnlyFile(t *testing.T) {
	src := "import oqs\n" +
		"\n" +
		"with oqs.KeyEncapsulation('ML-KEM-768') as kem:\n" +
		"    kem.generate_keypair()\n"
	all := scanOneFile(t, "pqc_only.py", src)
	if len(all) != 0 {
		t.Fatalf("expected 0 findings on PQC-only file, got %d: %+v", len(all), all)
	}
}

// TestScanner_sentinelIgnoresFileWithoutCryptoImports: ordinary code stays
// silent.
func TestScanner_sentinelIgnoresFileWithoutCryptoImports(t *testing.T) {
	src := "import os\nimport json\n\nprint(json.dumps({'ok': True}))\n"
	all := scanOneFile(t, "plain.py", src)
	if len(all) != 0 {
		t.Fatalf("expected 0 findings on non-crypto file, got %d: %+v", len(all), all)
	}
}
