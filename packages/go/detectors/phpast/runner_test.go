// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package phpast

import (
	"strings"
	"testing"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

// mustRule builds a *rules.Rule for the given ID + AST query. Test-only.
func mustRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "php",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

func findMatch(t *testing.T, matches []astdet.Match, ruleID string) *astdet.Match {
	t.Helper()
	for i := range matches {
		if matches[i].Rule.ID == ruleID {
			return &matches[i]
		}
	}
	return nil
}

func TestParseQuery_kinds(t *testing.T) {
	cases := []struct {
		in   string
		kind queryKind
	}{
		{"call:md5", queryCall},
		{"method:rsa.encrypt", queryMethod},
		{"new:RSA", queryNew},
		{"use:phpseclib3.Crypt.RSA", queryUse},
		{"use:phpseclib3.Crypt.*", queryUse},
		{"const:OPENSSL_KEYTYPE_RSA", queryConst},
	}
	for _, c := range cases {
		q, err := parseQuery(c.in)
		if err != nil {
			t.Errorf("parseQuery(%q) error: %v", c.in, err)
			continue
		}
		if q.kind != c.kind {
			t.Errorf("parseQuery(%q).kind = %d, want %d", c.in, q.kind, c.kind)
		}
	}
}

func TestParseQuery_wildcardFlag(t *testing.T) {
	q, err := parseQuery("use:phpseclib3.Crypt.*")
	if err != nil {
		t.Fatalf("parseQuery: %v", err)
	}
	if !q.wildcard {
		t.Error("expected wildcard=true for path ending .*")
	}
	if q.wildcardPrefix != "phpseclib3.Crypt" {
		t.Errorf("wildcardPrefix=%q, want %q", q.wildcardPrefix, "phpseclib3.Crypt")
	}
}

func TestParseQuery_badInput(t *testing.T) {
	cases := []string{
		"",
		"no-colon",
		"method:onlyone",
		"call:",
		"unknown:foo",
	}
	for _, c := range cases {
		if _, err := parseQuery(c); err == nil {
			t.Errorf("parseQuery(%q): expected error, got nil", c)
		}
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("x.php", []byte("<?php $x = 1;"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	r := &runner{}
	regexRule := &rules.Rule{
		ID:       "X_REGEX",
		Language: "php",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	matches, err := r.Run("x.php", []byte("<?php $x = 1;"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptySourceReturnsNil(t *testing.T) {
	r := &runner{}
	rule := mustRule("ANY", "call:md5")
	matches, err := r.Run("x.php", []byte("   \n\n  "), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches for empty source, got %v", matches)
	}
}

func TestRun_invalidSyntaxDoesNotPanic(t *testing.T) {
	r := &runner{}
	rule := mustRule("ANY", "call:md5")
	// Wildly malformed source — parser should report errors but Run should not
	// panic and should return either nil or an empty slice.
	_, err := r.Run("x.php", []byte("<?php $x = ;;; func("), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run should swallow parse errors: %v", err)
	}
}

// --- Bare function calls (the most common PHP crypto API) -------------------

func TestRun_md5Call(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$h = md5($x);
`)
	rule := mustRule("PHP_MD5", "call:md5")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "PHP_MD5")
	if m == nil {
		t.Fatalf("expected PHP_MD5 match, got %d matches: %+v", len(matches), matches)
	}
	if m.Line != 2 {
		t.Errorf("match.Line = %d, want 2", m.Line)
	}
	if !strings.Contains(m.Snippet, "md5") {
		t.Errorf("match.Snippet = %q, want substring 'md5'", m.Snippet)
	}
}

func TestRun_sha1Call(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$h = sha1($x);
`)
	rule := mustRule("PHP_SHA1", "call:sha1")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_SHA1") == nil {
		t.Errorf("expected PHP_SHA1 match, got %+v", matches)
	}
}

func TestRun_hashCall(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$h = hash('md5', $x);
`)
	rule := mustRule("PHP_HASH", "call:hash")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_HASH") == nil {
		t.Errorf("expected PHP_HASH match (call:hash), got %+v", matches)
	}
}

func TestRun_opensslPkeyNewCall(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA]);
`)
	rule := mustRule("PHP_OPENSSL_PKEY_NEW", "call:openssl_pkey_new")
	constRule := mustRule("PHP_OPENSSL_KEYTYPE_RSA", "const:OPENSSL_KEYTYPE_RSA")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule, constRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_OPENSSL_PKEY_NEW") == nil {
		t.Errorf("expected PHP_OPENSSL_PKEY_NEW match, got %+v", matches)
	}
	if findMatch(t, matches, "PHP_OPENSSL_KEYTYPE_RSA") == nil {
		t.Errorf("expected PHP_OPENSSL_KEYTYPE_RSA const match, got %+v", matches)
	}
}

// Function call written as `\md5(...)` must still match `call:md5`.
func TestRun_callWithLeadingBackslash(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$h = \md5($x);
`)
	rule := mustRule("PHP_MD5", "call:md5")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_MD5") == nil {
		t.Errorf("expected PHP_MD5 match for fully-qualified \\md5(), got %+v", matches)
	}
}

// --- new expressions --------------------------------------------------------

func TestRun_newClass_simpleNamespace(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$rsa = new \phpseclib3\Crypt\RSA();
`)
	// Rule written with the simple identifier — last-segment match.
	ruleSimple := mustRule("PHP_PHPSECLIB_RSA", "new:RSA")
	// Rule written with the dotted fully-qualified form — exact match.
	ruleFQ := mustRule("PHP_PHPSECLIB_RSA_FQ", "new:phpseclib3.Crypt.RSA")
	matches, err := r.Run("file.php", src, []*rules.Rule{ruleSimple, ruleFQ})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_PHPSECLIB_RSA") == nil {
		t.Errorf("expected PHP_PHPSECLIB_RSA match (simple form), got %+v", matches)
	}
	if findMatch(t, matches, "PHP_PHPSECLIB_RSA_FQ") == nil {
		t.Errorf("expected PHP_PHPSECLIB_RSA_FQ match (fully-qualified), got %+v", matches)
	}
}

func TestRun_newClass_bareIdentifier(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$r = new Random();
`)
	rule := mustRule("PHP_RANDOM", "new:Random")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_RANDOM") == nil {
		t.Errorf("expected PHP_RANDOM match, got %+v", matches)
	}
}

// --- Method calls -----------------------------------------------------------

func TestRun_methodCall_dynamic(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$rsa->encrypt($plain);
`)
	rule := mustRule("PHP_RSA_ENCRYPT", "method:rsa.encrypt")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_RSA_ENCRYPT") == nil {
		t.Errorf("expected PHP_RSA_ENCRYPT match for $rsa->encrypt(), got %+v", matches)
	}
}

func TestRun_methodCall_static(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
RSA::createKey(2048);
`)
	rule := mustRule("PHP_RSA_STATIC", "method:RSA.createKey")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_RSA_STATIC") == nil {
		t.Errorf("expected PHP_RSA_STATIC match for RSA::createKey(), got %+v", matches)
	}
}

// --- Use statements ---------------------------------------------------------

func TestRun_useStatement_exact(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
use phpseclib3\Crypt\RSA;
`)
	rule := mustRule("PHP_USE_RSA", "use:phpseclib3.Crypt.RSA")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "PHP_USE_RSA")
	if m == nil {
		t.Fatalf("expected PHP_USE_RSA match, got %+v", matches)
	}
	if m.Line != 2 {
		t.Errorf("match.Line = %d, want 2", m.Line)
	}
}

func TestRun_useStatement_wildcard(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\RSA;
`)
	rule := mustRule("PHP_USE_PHPSECLIB_CRYPT", "use:phpseclib3.Crypt.*")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Wildcard should match BOTH use statements.
	count := 0
	for _, m := range matches {
		if m.Rule.ID == "PHP_USE_PHPSECLIB_CRYPT" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 wildcard use matches, got %d (%+v)", count, matches)
	}
}

// --- Const fetches ----------------------------------------------------------

func TestRun_constFetch_mcrypt(t *testing.T) {
	r := &runner{}
	src := []byte(`<?php
$cipher = MCRYPT_DES;
`)
	rule := mustRule("PHP_MCRYPT_DES", "const:MCRYPT_DES")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "PHP_MCRYPT_DES") == nil {
		t.Errorf("expected PHP_MCRYPT_DES match, got %+v", matches)
	}
}

// --- Position bookkeeping ---------------------------------------------------

// Source without a leading <?php tag is wrapped by the runner; line numbers
// must still align with the user's original source.
func TestRun_lineNumbersAlignWithoutPHPTag(t *testing.T) {
	r := &runner{}
	// No <?php at the top — the runner prepends one and must subtract the
	// added line so the reported line matches the user's source (line 2).
	src := []byte(`// header
md5($x);
`)
	// PHP rejects bare-script content without <?php at runtime, but the parser
	// will accept it once we prepend a tag. The match should report line 2.
	rule := mustRule("PHP_MD5", "call:md5")
	matches, err := r.Run("file.php", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "PHP_MD5")
	if m == nil {
		t.Fatalf("expected PHP_MD5 match, got %+v", matches)
	}
	if m.Line != 2 {
		t.Errorf("match.Line = %d, want 2 (original source line)", m.Line)
	}
}

// --- Registration -----------------------------------------------------------

func TestRunner_isRegisteredForPHP(t *testing.T) {
	got := astdet.Get("php")
	if got == nil {
		t.Fatal("expected runner registered for php")
	}
	if _, ok := got.(*runner); !ok {
		t.Errorf("registered runner is %T, want *phpast.runner", got)
	}
}
