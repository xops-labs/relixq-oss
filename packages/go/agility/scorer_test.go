// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package agility

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/finding"
)

func mkFinding(ruleID, algo, file, category string) finding.Finding {
	return finding.Finding{
		RuleID:    ruleID,
		Algorithm: algo,
		FilePath:  file,
		Category:  category,
	}
}

// TestScore_emptyFindings asserts the explicit design choice that a repo
// with zero detected crypto returns a perfect score. A clean repo cannot
// be made harder to migrate.
func TestScore_emptyFindings(t *testing.T) {
	sc := Score(nil)
	if sc.TotalScore != 100 {
		t.Errorf("empty findings: want score=100, got %d", sc.TotalScore)
	}
	if sc.Grade != "Agile" {
		t.Errorf("empty findings: want grade=Agile, got %q", sc.Grade)
	}
}

// TestScore_perfectlyAgileRepo simulates a repo with one library, all
// crypto in one file, one algorithm, no hardcoded keys.
func TestScore_perfectlyAgileRepo(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("PYTHON_IMPORT_CRYPTOGRAPHY", "", "src/crypto.py", "crypto-api"),
		mkFinding("PYTHON_HASHLIB_MD5", "MD5", "src/crypto.py", "weak-hash"),
		mkFinding("PYTHON_HASHLIB_SHA1", "MD5", "src/crypto.py", "weak-hash"),
	}
	sc := Score(findings)

	if sc.LibraryConsolidation.Score != 25 {
		t.Errorf("one library: want 25, got %d (%s)", sc.LibraryConsolidation.Score, sc.LibraryConsolidation.Description)
	}
	if sc.CallSiteConcentration.Score != 25 {
		t.Errorf("one file: want 25, got %d (%s)", sc.CallSiteConcentration.Score, sc.CallSiteConcentration.Description)
	}
	if sc.AlgorithmDiversity.Score != 25 {
		t.Errorf("one algorithm: want 25, got %d (%s)", sc.AlgorithmDiversity.Score, sc.AlgorithmDiversity.Description)
	}
	if sc.HardcodedKeyPrevalence.Score != 25 {
		t.Errorf("no hardcoded keys: want 25, got %d (%s)", sc.HardcodedKeyPrevalence.Score, sc.HardcodedKeyPrevalence.Description)
	}
	if sc.TotalScore != 100 {
		t.Errorf("perfectly agile: want 100, got %d", sc.TotalScore)
	}
	if sc.Grade != "Agile" {
		t.Errorf("want grade=Agile, got %q", sc.Grade)
	}
}

// TestScore_brittleRepo simulates a repo with many libraries, scattered
// findings, many algorithms, lots of hardcoded keys.
func TestScore_brittleRepo(t *testing.T) {
	var findings []finding.Finding
	libs := []string{"CRYPTOGRAPHY", "PYCRYPTO", "M2CRYPTO", "PYOPENSSL", "BCRYPT"}
	for _, lib := range libs {
		findings = append(findings, mkFinding("PYTHON_IMPORT_"+lib, "", "src/crypto.py", "crypto-api"))
	}
	// 10 files, 1 finding each — maximally scattered.
	algos := []string{"MD5", "SHA1", "DES", "RC4", "3DES", "RSA", "ECDSA", "DSA"}
	for i, a := range algos {
		findings = append(findings, mkFinding("PYTHON_USAGE_"+a, a, "src/file"+string(rune('a'+i))+".py", "weak-cipher"))
	}
	// Plenty of hardcoded keys — 4 out of 13 findings.
	for i := 0; i < 4; i++ {
		findings = append(findings, mkFinding("CONFIG_HARDCODED_RSA_PRIVATE_KEY", "RSA", "src/secrets/k"+string(rune('a'+i))+".pem", "hardcoded-key"))
	}

	sc := Score(findings)

	if sc.LibraryConsolidation.Score > 10 {
		t.Errorf("5 libraries: want ≤10, got %d (%s)", sc.LibraryConsolidation.Score, sc.LibraryConsolidation.Description)
	}
	if sc.AlgorithmDiversity.Score > 12 {
		t.Errorf("8 algorithms: want ≤12, got %d (%s)", sc.AlgorithmDiversity.Score, sc.AlgorithmDiversity.Description)
	}
	if sc.HardcodedKeyPrevalence.Score > 12 {
		t.Errorf("23%% hardcoded keys: want ≤12, got %d (%s)", sc.HardcodedKeyPrevalence.Score, sc.HardcodedKeyPrevalence.Description)
	}
	if sc.TotalScore > 50 {
		t.Errorf("brittle repo: want ≤50, got %d (%s)", sc.TotalScore, sc.Grade)
	}
}

func TestIsLibrarySurfaceRule(t *testing.T) {
	cases := map[string]bool{
		"PYTHON_IMPORT_HASHLIB":   true,
		"RUBY_REQUIRE_OPENSSL":    true,
		"RUST_USE_RSA_CRATE":      true,
		"QSHARP_OPEN_CLASSICAL_CRYPTO": true,
		"PHP_USE_OPENSSL":         true, // trailing _USE
		"FSHARP_OPEN_BCL_CRYPTO":  true,
		"PYTHON_HASHLIB_MD5":      false,
		"JAVA_DES_CIPHER":         false,
		"CONFIG_TLS_OLD_VERSION":  false,
	}
	for rule, want := range cases {
		if got := isLibrarySurfaceRule(rule); got != want {
			t.Errorf("isLibrarySurfaceRule(%q) = %v, want %v", rule, got, want)
		}
	}
}

func TestLibraryNameFromRule(t *testing.T) {
	cases := map[string]string{
		"PYTHON_IMPORT_HASHLIB":         "HASHLIB",
		"RUBY_REQUIRE_OPENSSL":          "OPENSSL",
		"RUST_USE_RSA_CRATE":            "RSA_CRATE",
		"QSHARP_OPEN_CLASSICAL_CRYPTO":  "CLASSICAL_CRYPTO",
		"FSHARP_OPEN_BCL_CRYPTO":        "BCL_CRYPTO",
	}
	for rule, want := range cases {
		if got := libraryNameFromRule(rule); got != want {
			t.Errorf("libraryNameFromRule(%q) = %q, want %q", rule, got, want)
		}
	}
}

func TestIsHardcodedKeyFinding(t *testing.T) {
	cases := []struct {
		f    finding.Finding
		want bool
	}{
		{finding.Finding{Category: "hardcoded-key"}, true},
		{finding.Finding{Category: "Hardcoded-Secret"}, true},
		{finding.Finding{RuleID: "CONFIG_HARDCODED_RSA_PRIVATE_KEY"}, true},
		{finding.Finding{RuleID: "PERL_USE_DIGEST_MD5", Category: "weak-hash"}, false},
		{finding.Finding{Category: "weak-cipher"}, false},
	}
	for _, c := range cases {
		if got := isHardcodedKeyFinding(c.f); got != c.want {
			t.Errorf("isHardcodedKeyFinding(%+v) = %v, want %v", c.f, got, c.want)
		}
	}
}

// TestScore_concentrationBands exercises the top-3-files threshold table
// directly so a regression in the breakpoints surfaces visibly.
func TestScore_concentrationBands(t *testing.T) {
	mk := func(files map[string]int) []finding.Finding {
		var fs []finding.Finding
		for path, n := range files {
			for i := 0; i < n; i++ {
				fs = append(fs, mkFinding("X_R_"+path, "MD5", path, "weak-hash"))
			}
		}
		return fs
	}
	cases := []struct {
		name      string
		files     map[string]int
		wantScore int
	}{
		// 90% concentrated in top 3
		{"highly concentrated", map[string]int{"a.py": 9, "b.py": 1}, 25},
		// 60% in top 3 — second band
		{"concentrated", map[string]int{"a.py": 3, "b.py": 2, "c.py": 1, "d.py": 1, "e.py": 1, "f.py": 1, "g.py": 1}, 18},
		// 40% in top 3 — third band
		{"moderately scattered", map[string]int{"a.py": 2, "b.py": 2, "c.py": 2, "d.py": 1, "e.py": 1, "f.py": 1, "g.py": 1, "h.py": 1, "i.py": 1, "j.py": 1, "k.py": 1, "l.py": 1, "m.py": 1}, 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := Score(mk(c.files))
			if sc.CallSiteConcentration.Score != c.wantScore {
				t.Errorf("%s: want concentration score %d, got %d (%s)",
					c.name, c.wantScore, sc.CallSiteConcentration.Score, sc.CallSiteConcentration.Description)
			}
		})
	}
}

// TestScore_genericAlgorithmTagsFiltered asserts that catch-all algorithm
// names (TLS / CIPHER / HASH / HMAC) do not inflate the diversity count.
// Without this filter, a single "TLS" finding would be indistinguishable
// from a finding that explicitly names RSA, ECDHE, AES, etc.
func TestScore_genericAlgorithmTagsFiltered(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("CONFIG_TLS_OLD", "TLS", "a.conf", "weak-tls"),
		mkFinding("PYTHON_HMAC", "HMAC", "a.py", "weak-hash"),
		mkFinding("NGINX_CIPHER_RC4", "CIPHER", "nginx.conf", "weak-cipher"),
		mkFinding("PYTHON_RSA_GEN", "RSA", "a.py", "crypto-api"),
	}
	sc := Score(findings)
	// Only "RSA" should count.
	if got := len(sc.DistinctAlgorithms); got != 1 {
		t.Errorf("want 1 distinct algorithm (RSA), got %d: %v", got, sc.DistinctAlgorithms)
	}
}

// TestScore_grade exercises the band table for grade assignment.
func TestScore_grade(t *testing.T) {
	cases := []struct {
		total int
		want  string
	}{
		{100, "Agile"},
		{75, "Agile"},
		{74, "Manageable"},
		{50, "Manageable"},
		{49, "Difficult"},
		{25, "Difficult"},
		{24, "Brittle"},
		{0, "Brittle"},
	}
	for _, c := range cases {
		if got := grade(c.total); got != c.want {
			t.Errorf("grade(%d) = %q, want %q", c.total, got, c.want)
		}
	}
}

// TestScore_diagnosticsSurfaced ensures that the inspection fields are
// populated (used by Build #3 graph correlation and downstream CLIs).
func TestScore_diagnosticsSurfaced(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("PYTHON_IMPORT_CRYPTOGRAPHY", "", "src/a.py", "crypto-api"),
		mkFinding("PYTHON_IMPORT_PYCRYPTO", "", "src/a.py", "crypto-api"),
		mkFinding("PYTHON_HASHLIB_MD5", "MD5", "src/a.py", "weak-hash"),
		mkFinding("PYTHON_HASHLIB_SHA1", "SHA1", "src/b.py", "weak-hash"),
	}
	sc := Score(findings)

	if !strings.Contains(strings.Join(sc.DistinctLibraries, ","), "CRYPTOGRAPHY") {
		t.Errorf("expected CRYPTOGRAPHY in DistinctLibraries: %v", sc.DistinctLibraries)
	}
	if sc.FilesWithFindings != 2 {
		t.Errorf("want 2 files with findings, got %d", sc.FilesWithFindings)
	}
	if sc.TotalFindings != 4 {
		t.Errorf("want 4 total findings, got %d", sc.TotalFindings)
	}
	if len(sc.TopFiles) == 0 {
		t.Errorf("TopFiles should be populated")
	}
}
