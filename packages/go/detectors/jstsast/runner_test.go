// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package jstsast

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
		Language: "javascript",
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
		{"call:crypto.createHash", queryCall},
		{"new:NodeRSA", queryNew},
		{"import:crypto", queryImport},
		{"memberref:crypto.constants", queryMemberRef},
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

func TestParseQuery_badInput(t *testing.T) {
	cases := []string{
		"",
		"no-colon",
		"call:onlyone",
		"unknown:foo.bar",
	}
	for _, c := range cases {
		if _, err := parseQuery(c); err == nil {
			t.Errorf("parseQuery(%q): expected error, got nil", c)
		}
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("X.js", []byte("const x = 1;"), nil)
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
		Language: "javascript",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	matches, err := r.Run("X.js", []byte("const x = 1;"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptySourceReturnsNil(t *testing.T) {
	r := &runner{}
	rule := mustRule("ANY", "call:crypto.createHash")
	matches, err := r.Run("X.js", []byte("   \n\n  "), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches for empty source, got %v", matches)
	}
}

func TestRun_invalidSyntaxReturnsNilWithoutPanic(t *testing.T) {
	r := &runner{}
	rule := mustRule("ANY", "call:crypto.createHash")
	// Unterminated string literal — esbuild reports an error.
	matches, err := r.Run("X.js", []byte("const x = 'unterminated"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run should swallow parse errors: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches for invalid syntax, got %v", matches)
	}
}

func TestRun_jsCallExpression(t *testing.T) {
	r := &runner{}
	src := []byte(`const crypto = require('crypto');
const h = crypto.createHash('md5');
`)
	rule := mustRule("JS_MD5", "call:crypto.createHash")
	matches, err := r.Run("file.js", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "JS_MD5")
	if m == nil {
		t.Fatalf("expected JS_MD5 match, got %d matches: %+v", len(matches), matches)
	}
	if m.Line != 2 {
		t.Errorf("match.Line = %d, want 2", m.Line)
	}
	if !strings.Contains(m.Snippet, "createHash") {
		t.Errorf("match.Snippet = %q, want substring 'createHash'", m.Snippet)
	}
}

func TestRun_jsRequireImport(t *testing.T) {
	r := &runner{}
	src := []byte(`const crypto = require('crypto');
`)
	rule := mustRule("JS_IMPORT_CRYPTO", "import:crypto")
	matches, err := r.Run("file.js", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "JS_IMPORT_CRYPTO") == nil {
		t.Errorf("expected JS_IMPORT_CRYPTO match, got %d matches: %+v", len(matches), matches)
	}
}

func TestRun_jsESMImport(t *testing.T) {
	r := &runner{}
	src := []byte(`import * as crypto from 'crypto';
const h = crypto.createHash('sha1');
`)
	importRule := mustRule("JS_IMPORT_CRYPTO", "import:crypto")
	callRule := mustRule("JS_SHA1", "call:crypto.createHash")
	matches, err := r.Run("file.mjs", src, []*rules.Rule{importRule, callRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "JS_IMPORT_CRYPTO") == nil {
		t.Errorf("expected JS_IMPORT_CRYPTO match, got %d matches: %+v", len(matches), matches)
	}
	if findMatch(t, matches, "JS_SHA1") == nil {
		t.Errorf("expected JS_SHA1 match, got %d matches: %+v", len(matches), matches)
	}
}

func TestRun_jsNewExpression(t *testing.T) {
	r := &runner{}
	src := []byte(`const NodeRSA = require('node-rsa');
const key = new NodeRSA({ b: 2048 });
`)
	rule := mustRule("JS_NODE_RSA", "new:NodeRSA")
	matches, err := r.Run("file.js", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "JS_NODE_RSA")
	if m == nil {
		t.Fatalf("expected JS_NODE_RSA match, got %d matches: %+v", len(matches), matches)
	}
	if m.Line != 2 {
		t.Errorf("match.Line = %d, want 2", m.Line)
	}
}

func TestRun_jsMemberRef(t *testing.T) {
	r := &runner{}
	src := []byte(`const crypto = require('crypto');
const pad = crypto.constants.RSA_PKCS1_PADDING;
const h = crypto.createHash('md5');
`)
	rule := &rules.Rule{
		ID:       "JS_CRYPTO_CONSTANTS",
		Language: "javascript",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "memberref:crypto.constants"},
	}
	matches, err := r.Run("file.js", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "JS_CRYPTO_CONSTANTS")
	if m == nil {
		t.Fatalf("expected JS_CRYPTO_CONSTANTS match (memberref), got %d matches: %+v", len(matches), matches)
	}
	// crypto.createHash() on line 3 should NOT fire memberref because it's a
	// callee, not a standalone member access.
	count := 0
	for _, mm := range matches {
		if mm.Rule.ID == "JS_CRYPTO_CONSTANTS" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 memberref match, got %d", count)
	}
}

// TS-specific tests start here. These prove the esbuild pre-transform path.

func TestRun_tsCallExpressionWithTypeAnnotations(t *testing.T) {
	r := &runner{}
	src := []byte(`import * as crypto from 'crypto';

interface HashOptions {
  algorithm: string;
}

function makeHash(opts: HashOptions): string {
  const h: crypto.Hash = crypto.createHash('md5');
  return h.digest('hex');
}
`)
	rule := &rules.Rule{
		ID:       "TS_MD5",
		Language: "typescript",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:crypto.createHash"},
	}
	matches, err := r.Run("file.ts", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "TS_MD5")
	if m == nil {
		t.Fatalf("expected TS_MD5 match, got %d matches: %+v", len(matches), matches)
	}
	// The createHash call is on the ORIGINAL source line 8 (1-indexed).
	if m.Line != 8 {
		t.Errorf("match.Line = %d, want 8 (line in original TS, post sourcemap remap)", m.Line)
	}
	if !strings.Contains(m.Snippet, "createHash") {
		t.Errorf("match.Snippet = %q, want substring 'createHash' from ORIGINAL TS", m.Snippet)
	}
}

func TestRun_tsImport(t *testing.T) {
	r := &runner{}
	src := []byte(`import * as crypto from 'crypto';

const algorithm: string = 'md5';
`)
	rule := &rules.Rule{
		ID:       "TS_IMPORT_CRYPTO",
		Language: "typescript",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "import:crypto"},
	}
	matches, err := r.Run("file.ts", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "TS_IMPORT_CRYPTO")
	if m == nil {
		t.Fatalf("expected TS_IMPORT_CRYPTO match, got %d matches: %+v", len(matches), matches)
	}
	if m.Line != 1 {
		t.Errorf("match.Line = %d, want 1", m.Line)
	}
}

func TestRun_tsNewExpression(t *testing.T) {
	r := &runner{}
	src := []byte(`import NodeRSA from 'node-rsa';

type KeyConfig = {
  b: number;
};

const cfg: KeyConfig = { b: 2048 };
const key = new NodeRSA(cfg);
`)
	rule := &rules.Rule{
		ID:       "TS_NODE_RSA",
		Language: "typescript",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "new:NodeRSA"},
	}
	matches, err := r.Run("file.ts", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := findMatch(t, matches, "TS_NODE_RSA")
	if m == nil {
		t.Fatalf("expected TS_NODE_RSA match, got %d matches: %+v", len(matches), matches)
	}
	// `new NodeRSA(cfg)` is on line 8 of the original TS.
	if m.Line != 8 {
		t.Errorf("match.Line = %d, want 8", m.Line)
	}
}

// TestRun_registeredForBothLanguages confirms the same runner instance
// answers for both "javascript" and "typescript" lookups.
func TestRun_registeredForBothLanguages(t *testing.T) {
	js := astdet.Get("javascript")
	ts := astdet.Get("typescript")
	if js == nil {
		t.Fatal("expected runner registered for javascript")
	}
	if ts == nil {
		t.Fatal("expected runner registered for typescript")
	}
	// Both should be our *runner; compare via the Runner interface identity.
	jsR, jsOK := js.(*runner)
	tsR, tsOK := ts.(*runner)
	if !jsOK || !tsOK {
		t.Fatalf("expected *runner type for both, got %T and %T", js, ts)
	}
	if jsR != tsR {
		t.Error("expected the same *runner instance for both languages")
	}
}
