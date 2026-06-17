// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package rustast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests.
func astRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "rust",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

func TestRun_callScopedPath_RsaPrivateKeyNewWithExp(t *testing.T) {
	src := []byte(`use rsa::RsaPrivateKey;
use num_bigint::BigUint;

fn make_key() -> RsaPrivateKey {
    let exp = BigUint::from(65537u32);
    rsa::RsaPrivateKey::new_with_exp(&mut rand::thread_rng(), 2048, &exp).unwrap()
}
`)
	rule := astRule("RUST_RSA_NEW_WITH_EXP", "call:rsa::RsaPrivateKey::new_with_exp")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "RUST_RSA_NEW_WITH_EXP" {
		t.Errorf("Rule.ID = %q, want RUST_RSA_NEW_WITH_EXP", matches[0].Rule.ID)
	}
	if matches[0].Line != 6 {
		t.Errorf("Line = %d, want 6", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "RsaPrivateKey::new_with_exp") {
		t.Errorf("Snippet = %q, want substring 'RsaPrivateKey::new_with_exp'", matches[0].Snippet)
	}
}

func TestRun_callShortPath_Sha1New(t *testing.T) {
	src := []byte(`use sha1::{Sha1, Digest};

fn h(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
`)
	rule := astRule("RUST_SHA1_NEW", "call:Sha1::new")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 4 {
		t.Errorf("Line = %d, want 4", matches[0].Line)
	}
}

func TestRun_methodCall_Sign(t *testing.T) {
	src := []byte(`fn run(signer: impl Signer, msg: &[u8]) -> Vec<u8> {
    signer.sign(msg)
}
`)
	rule := astRule("RUST_METHOD_SIGN", "methodcall:sign")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2", matches[0].Line)
	}
}

func TestRun_useDeclaration_Specific(t *testing.T) {
	src := []byte(`use ring::rsa::RsaKeyPair;

fn _f() {}
`)
	rule := astRule("RUST_USE_RING_RSA_KEYPAIR", "use:ring::rsa::RsaKeyPair")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1", matches[0].Line)
	}
}

func TestRun_useDeclaration_WildcardSourceMatchesSpecificRule(t *testing.T) {
	// `use ring::rsa::*` should match a rule targeting `ring::rsa::RsaKeyPair`.
	src := []byte(`use ring::rsa::*;

fn _f() {}
`)
	rule := astRule("RUST_USE_RING_RSA_WILDCARD", "use:ring::rsa::RsaKeyPair")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_useDeclaration_RuleWildcard(t *testing.T) {
	src := []byte(`use ring::rsa::RsaKeyPair;
use ring::rsa::PublicKeyComponents;
use ring::signature::EcdsaKeyPair;
use std::collections::HashMap;

fn _f() {}
`)
	rule := astRule("RUST_USE_RING_RSA_STAR", "use:ring::rsa::*")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// `ring::rsa::*` should match the two ring::rsa::* imports but NOT
	// ring::signature::EcdsaKeyPair or std::collections::HashMap.
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_useDeclaration_UseList(t *testing.T) {
	// `use ring::rsa::{RsaKeyPair, PublicKeyComponents}` brings in two paths;
	// a rule targeting the first should fire exactly once.
	src := []byte(`use ring::rsa::{RsaKeyPair, PublicKeyComponents};

fn _f() {}
`)
	rule := astRule("RUST_USE_RING_RSA_KEYPAIR_LIST", "use:ring::rsa::RsaKeyPair")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_useDeclaration_AsAlias(t *testing.T) {
	// `use ring::rsa::RsaKeyPair as KP;` should still match the original path.
	src := []byte(`use ring::rsa::RsaKeyPair as KP;

fn _f() {}
`)
	rule := astRule("RUST_USE_RING_RSA_KEYPAIR_AS", "use:ring::rsa::RsaKeyPair")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_callDoesNotFireOnUnrelatedFunction(t *testing.T) {
	src := []byte(`fn main() {
    let v = std::vec::Vec::<u8>::new();
    println!("{:?}", v);
}
`)
	// call:Sha1::new should NOT match Vec::new or println.
	rule := astRule("RUST_NEGATIVE", "call:Sha1::new")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_emptySourceReturnsNoMatches(t *testing.T) {
	rule := astRule("X", "call:Sha1::new")
	r := &runner{}
	matches, err := r.Run("lib.rs", []byte(""), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty source, got %d", len(matches))
	}
}

func TestRun_invalidSourceDoesNotPanic(t *testing.T) {
	// Tree-sitter is error-resilient: it produces a partial tree even when the
	// source is malformed. We just need to not panic and not over-match.
	rule := astRule("X", "call:Sha1::new")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("lib.rs", []byte("this is { not valid rust }}}"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "rust",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("lib.rs", []byte("fn x() {}"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("lib.rs", []byte("fn x() {}"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestRun_lineNumbersAreCorrect(t *testing.T) {
	// Sha1::new is on line 6. Verify exact line + reasonable column.
	src := []byte(`use sha1::Sha1;

// pad lines so the call shifts down
// to a non-trivial line number
fn h() {
    let _ = Sha1::new();
}
`)
	rule := astRule("RUST_LINE_TEST", "call:Sha1::new")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 6 {
		t.Errorf("Line = %d, want 6", matches[0].Line)
	}
	if matches[0].Column < 1 {
		t.Errorf("Column = %d, want >= 1", matches[0].Column)
	}
	// Context should include the matched line.
	foundInContext := false
	for _, c := range matches[0].Context {
		if strings.Contains(c, "Sha1::new()") {
			foundInContext = true
			break
		}
	}
	if !foundInContext {
		t.Errorf("Context did not include the matched line: %v", matches[0].Context)
	}
}

func TestRun_methodCall_DoesNotFireOnAssociatedFunction(t *testing.T) {
	// `Type::method(...)` is a call_expression with a scoped_identifier callee,
	// NOT a field_expression callee. A methodcall rule must not match it.
	src := []byte(`fn _f() {
    let _ = Sha1::new();
}
`)
	rule := astRule("RUST_METHODCALL_NEG", "methodcall:new")

	r := &runner{}
	matches, err := r.Run("lib.rs", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches (associated function should not trigger methodcall), got %d: %+v", len(matches), matches)
	}
}

func TestParseQuery_kinds(t *testing.T) {
	tests := []struct {
		in       string
		kind     queryKind
		path     string
		wildcard bool
	}{
		{"call:Sha1::new", queryCall, "Sha1::new", false},
		{"call:rsa::RsaPrivateKey::new_with_exp", queryCall, "rsa::RsaPrivateKey::new_with_exp", false},
		{"methodcall:sign", queryMethodCall, "sign", false},
		{"use:ring::rsa", queryUse, "ring::rsa", false},
		{"use:ring::rsa::*", queryUse, "ring::rsa::*", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			pq, err := parseQuery(tt.in)
			if err != nil {
				t.Fatalf("parseQuery: %v", err)
			}
			if pq.kind != tt.kind {
				t.Errorf("kind = %d, want %d", pq.kind, tt.kind)
			}
			if pq.path != tt.path {
				t.Errorf("path = %q, want %q", pq.path, tt.path)
			}
			if pq.wildcard != tt.wildcard {
				t.Errorf("wildcard = %v, want %v", pq.wildcard, tt.wildcard)
			}
		})
	}
}

func TestParseQuery_invalid(t *testing.T) {
	for _, q := range []string{
		"",
		"badprefix:Foo",
		"call:",
		"methodcall:",
		"methodcall:scoped::path",
		"use:",
	} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("parseQuery(%q): expected error", q)
		}
	}
}

func TestUseMatches(t *testing.T) {
	tests := []struct {
		ruleQuery        string
		importPath       string
		importIsWildcard bool
		want             bool
	}{
		// Exact match
		{"use:ring::rsa::RsaKeyPair", "ring::rsa::RsaKeyPair", false, true},
		{"use:ring::rsa::RsaKeyPair", "ring::rsa::Other", false, false},
		// Wildcard source covers specific rule
		{"use:ring::rsa::RsaKeyPair", "ring::rsa", true, true},
		{"use:ring::rsa::RsaKeyPair", "ring::signature", true, false},
		// Wildcard rule
		{"use:ring::rsa::*", "ring::rsa::RsaKeyPair", false, true},
		{"use:ring::rsa::*", "ring::rsa", false, true},
		{"use:ring::rsa::*", "ring::signature::EcdsaKeyPair", false, false},
		{"use:ring::rsa::*", "ring::rsa::sub::Nested", false, true},
	}
	for _, tt := range tests {
		pq, err := parseQuery(tt.ruleQuery)
		if err != nil {
			t.Fatalf("parseQuery(%q): %v", tt.ruleQuery, err)
		}
		got := useMatches(pq, tt.importPath, tt.importIsWildcard)
		if got != tt.want {
			t.Errorf("useMatches(%q, %q, %v) = %v, want %v",
				tt.ruleQuery, tt.importPath, tt.importIsWildcard, got, tt.want)
		}
	}
}
