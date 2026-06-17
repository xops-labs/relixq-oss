// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package rubyast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests.
func astRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "ruby",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

// --- call: ----------------------------------------------------------------

func TestRun_call_DigestMD5_Hexdigest(t *testing.T) {
	// `Digest::MD5.hexdigest(x)` — receiver is a scope_resolution. The rule
	// uses the fully scoped form.
	src := []byte(`require 'digest'

def fingerprint(x)
  Digest::MD5.hexdigest(x)
end
`)
	rule := astRule("RUBY_DIGEST_MD5_HEXDIGEST", "call:Digest::MD5.hexdigest")

	r := &runner{}
	matches, err := r.Run("fp.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "RUBY_DIGEST_MD5_HEXDIGEST" {
		t.Errorf("Rule.ID = %q, want RUBY_DIGEST_MD5_HEXDIGEST", matches[0].Rule.ID)
	}
	if matches[0].Line != 4 {
		t.Errorf("Line = %d, want 4", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "Digest::MD5.hexdigest") {
		t.Errorf("Snippet = %q, want substring 'Digest::MD5.hexdigest'", matches[0].Snippet)
	}
}

func TestRun_call_ShortReceiver_MatchesScopedRule(t *testing.T) {
	// Source uses the bare `MD5.new` after opening Digest. The rule writes
	// the scoped form; permissive short-segment matching should still fire.
	src := []byte(`require 'digest'

include Digest
def h
  MD5.new
end
`)
	rule := astRule("RUBY_MD5_NEW", "call:Digest::MD5.new")

	r := &runner{}
	matches, err := r.Run("fp.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 5 {
		t.Errorf("Line = %d, want 5", matches[0].Line)
	}
}

func TestRun_call_OpenSSLCipherNew(t *testing.T) {
	src := []byte(`require 'openssl'

def enc
  c = OpenSSL::Cipher.new("DES")
  c
end
`)
	rule := astRule("RUBY_OPENSSL_CIPHER_NEW", "call:OpenSSL::Cipher.new")

	r := &runner{}
	matches, err := r.Run("enc.rb", src, []*rules.Rule{rule})
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

func TestRun_call_InstanceReceiver(t *testing.T) {
	// `obj.hexdigest(x)` — receiver is a bare identifier. A rule targeting
	// the bare receiver name should match.
	src := []byte(`def go(md)
  md.hexdigest("x")
end
`)
	rule := astRule("RUBY_MD_HEXDIGEST", "call:md.hexdigest")

	r := &runner{}
	matches, err := r.Run("x.rb", src, []*rules.Rule{rule})
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

// --- new: -----------------------------------------------------------------

func TestRun_new_OpenSSLPKeyRSA(t *testing.T) {
	src := []byte(`require 'openssl'

def k
  OpenSSL::PKey::RSA.new(1024)
end
`)
	rule := astRule("RUBY_RSA_NEW_1024", "new:OpenSSL::PKey::RSA")

	r := &runner{}
	matches, err := r.Run("k.rb", src, []*rules.Rule{rule})
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

func TestRun_new_DoesNotFireOnOtherMethod(t *testing.T) {
	// `OpenSSL::PKey::RSA.generate(2048)` is not `.new(...)`, so `new:` must
	// not fire even though the receiver matches.
	src := []byte(`require 'openssl'
k = OpenSSL::PKey::RSA.generate(2048)
`)
	rule := astRule("RUBY_RSA_NEW_NEG", "new:OpenSSL::PKey::RSA")

	r := &runner{}
	matches, err := r.Run("k.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

// --- const: ---------------------------------------------------------------

func TestRun_const_BareReference(t *testing.T) {
	// `algo = Digest::MD5` — a constant reference NOT in call-receiver
	// position. const: must fire.
	src := []byte(`require 'digest'

ALG = Digest::MD5
`)
	rule := astRule("RUBY_CONST_MD5", "const:Digest::MD5")

	r := &runner{}
	matches, err := r.Run("c.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 3 {
		t.Errorf("Line = %d, want 3", matches[0].Line)
	}
}

func TestRun_const_SuppressedAsCallReceiver(t *testing.T) {
	// `Digest::MD5.new(...)` is a call whose receiver is `Digest::MD5`. The
	// const: rule must NOT fire — the call: rule (if any) is responsible for
	// that site. This prevents double-counting.
	src := []byte(`require 'digest'

def h
  Digest::MD5.new
end
`)
	rule := astRule("RUBY_CONST_MD5_NEG", "const:Digest::MD5")

	r := &runner{}
	matches, err := r.Run("h.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches (const must not fire when const is a call receiver), got %d: %+v", len(matches), matches)
	}
}

// --- require: -------------------------------------------------------------

func TestRun_require_Openssl(t *testing.T) {
	src := []byte(`require 'openssl'
require 'json'

x = 1
`)
	rule := astRule("RUBY_REQ_OPENSSL", "require:openssl")

	r := &runner{}
	matches, err := r.Run("r.rb", src, []*rules.Rule{rule})
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

func TestRun_require_DigestMD5SubPath(t *testing.T) {
	// `require 'digest/md5'` — the require: arg matches the literal string,
	// path slashes and all.
	src := []byte(`require 'digest/md5'
`)
	rule := astRule("RUBY_REQ_DIGEST_MD5", "require:digest/md5")

	r := &runner{}
	matches, err := r.Run("r.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_require_Relative(t *testing.T) {
	src := []byte(`require_relative 'helpers'
`)
	rule := astRule("RUBY_REQ_REL", "require:helpers")

	r := &runner{}
	matches, err := r.Run("r.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

// --- negative / boundary --------------------------------------------------

func TestRun_call_DoesNotFireOnUnrelated(t *testing.T) {
	src := []byte(`puts "hello"
[1,2,3].each { |i| puts i }
`)
	rule := astRule("RUBY_NEG", "call:Digest::MD5.hexdigest")

	r := &runner{}
	matches, err := r.Run("x.rb", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_emptySourceReturnsNoMatches(t *testing.T) {
	rule := astRule("X", "call:Digest::MD5.new")
	r := &runner{}
	matches, err := r.Run("x.rb", []byte(""), []*rules.Rule{rule})
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
	rule := astRule("X", "call:Digest::MD5.new")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("x.rb", []byte("def foo;;; { not ruby"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "ruby",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("x.rb", []byte("def x; end"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("x.rb", []byte("def x; end"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

// --- parseQuery -----------------------------------------------------------

func TestParseQuery_kinds(t *testing.T) {
	tests := []struct {
		in       string
		kind     queryKind
		receiver string
		method   string
		path     string
		lib      string
	}{
		{"call:Digest::MD5.hexdigest", queryCall, "Digest::MD5", "hexdigest", "", ""},
		{"call:OpenSSL::Cipher.new", queryCall, "OpenSSL::Cipher", "new", "", ""},
		{"call:md.hexdigest", queryCall, "md", "hexdigest", "", ""},
		{"new:OpenSSL::PKey::RSA", queryNew, "OpenSSL::PKey::RSA", "new", "", ""},
		{"const:Digest::MD5", queryConst, "", "", "Digest::MD5", ""},
		{"require:openssl", queryRequire, "", "", "", "openssl"},
		{"require:digest/md5", queryRequire, "", "", "", "digest/md5"},
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
			if pq.receiver != tt.receiver {
				t.Errorf("receiver = %q, want %q", pq.receiver, tt.receiver)
			}
			if pq.method != tt.method {
				t.Errorf("method = %q, want %q", pq.method, tt.method)
			}
			if pq.constPath != tt.path {
				t.Errorf("constPath = %q, want %q", pq.constPath, tt.path)
			}
			if pq.libName != tt.lib {
				t.Errorf("libName = %q, want %q", pq.libName, tt.lib)
			}
		})
	}
}

func TestParseQuery_invalid(t *testing.T) {
	for _, q := range []string{
		"",
		"badprefix:Foo",
		"call:",
		"call:NoMethod",       // no '.'
		"call:.bare",          // empty receiver
		"call:Foo.",           // empty method
		"new:",
		"const:",
		"require:",
	} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("parseQuery(%q): expected error", q)
		}
	}
}

// --- helper unit tests ----------------------------------------------------

func TestLastSegment(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"MD5", "MD5"},
		{"Digest::MD5", "MD5"},
		{"OpenSSL::PKey::RSA", "RSA"},
		{"", ""},
	}
	for _, tt := range tests {
		got := lastSegment(tt.in)
		if got != tt.want {
			t.Errorf("lastSegment(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReceiverMatches(t *testing.T) {
	tests := []struct {
		ruleQuery string
		srcFull   string
		srcShort  string
		want      bool
	}{
		// Exact full-path match.
		{"call:Digest::MD5.new", "Digest::MD5", "MD5", true},
		// Short-segment fallback: scoped rule, bare source.
		{"call:Digest::MD5.new", "MD5", "MD5", true},
		// Short-segment fallback: bare rule, scoped source.
		{"call:MD5.new", "Digest::MD5", "MD5", true},
		// Different short segment — no match.
		{"call:Digest::MD5.new", "Digest::SHA1", "SHA1", false},
		{"call:Digest::MD5.new", "Other::Thing", "Thing", false},
	}
	for _, tt := range tests {
		pq, err := parseQuery(tt.ruleQuery)
		if err != nil {
			t.Fatalf("parseQuery(%q): %v", tt.ruleQuery, err)
		}
		got := receiverMatches(pq, tt.srcFull, tt.srcShort)
		if got != tt.want {
			t.Errorf("receiverMatches(%q, %q) = %v, want %v",
				tt.ruleQuery, tt.srcFull, got, tt.want)
		}
	}
}
