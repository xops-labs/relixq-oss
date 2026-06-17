// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package juliaast

import (
	"strings"
	"testing"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests.
func astRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "julia",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

// requireRunner skips the test when the Julia AST runner isn't registered.
// The registry is populated in init() above, but if the grammar pointer is
// somehow unavailable at runtime (e.g. linker stripped the binding on a
// developer machine without the C toolchain) we treat it as a skip.
func requireRunner(t *testing.T) {
	t.Helper()
	if astdet.Get("julia") == nil {
		t.Skip("julia AST runner not registered (CGO build flag missing?)")
	}
}

// --- call: dotted ---------------------------------------------------------

func TestRun_call_SHA_sha256(t *testing.T) {
	requireRunner(t)
	src := []byte(`using SHA

function fingerprint(x)
    SHA.sha256(x)
end
`)
	rule := astRule("JULIA_SHA_SHA256", "call:SHA.sha256")

	r := &runner{}
	matches, err := r.Run("fp.jl", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "JULIA_SHA_SHA256" {
		t.Errorf("Rule.ID = %q, want JULIA_SHA_SHA256", matches[0].Rule.ID)
	}
	if matches[0].Line != 4 {
		t.Errorf("Line = %d, want 4", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "SHA.sha256") {
		t.Errorf("Snippet = %q, want substring 'SHA.sha256'", matches[0].Snippet)
	}
}

func TestRun_call_Nettle_Hasher(t *testing.T) {
	requireRunner(t)
	src := []byte(`using Nettle

h = Nettle.Hasher("md5")
update!(h, b"x")
`)
	rule := astRule("JULIA_NETTLE_HASHER", "call:Nettle.Hasher")

	r := &runner{}
	matches, err := r.Run("h.jl", src, []*rules.Rule{rule})
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

// --- call: bare callee ----------------------------------------------------

func TestRun_call_bare_function(t *testing.T) {
	requireRunner(t)
	// After `using SHA` a user may call `sha1(x)` directly without the module
	// prefix — `call:sha1` (no dot) matches the bare identifier callee.
	src := []byte(`using SHA

function legacy_fp(x)
    sha1(x)
end
`)
	rule := astRule("JULIA_BARE_SHA1", "call:sha1")

	r := &runner{}
	matches, err := r.Run("l.jl", src, []*rules.Rule{rule})
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

func TestRun_call_bare_doesNotMatchDotted(t *testing.T) {
	requireRunner(t)
	// A bare-callee rule MUST NOT fire on `Other.sha1(x)` — that's a
	// field_expression callee, which a dotted rule (call:Other.sha1) owns.
	src := []byte(`Other.sha1(x)
`)
	rule := astRule("JULIA_BARE_SHA1_NEG", "call:sha1")

	r := &runner{}
	matches, err := r.Run("n.jl", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

// --- using: / import: -----------------------------------------------------

func TestRun_using_Module(t *testing.T) {
	requireRunner(t)
	src := []byte(`using SHA
using LinearAlgebra
`)
	rule := astRule("JULIA_USING_SHA", "using:SHA")

	r := &runner{}
	matches, err := r.Run("u.jl", src, []*rules.Rule{rule})
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

func TestRun_using_SelectedImport(t *testing.T) {
	requireRunner(t)
	// `using SHA: sha1, sha256` — selected_import shape; the rule keys on the
	// module name, not the imported symbols.
	src := []byte(`using SHA: sha1, sha256
`)
	rule := astRule("JULIA_USING_SHA_SEL", "using:SHA")

	r := &runner{}
	matches, err := r.Run("s.jl", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_import_Module(t *testing.T) {
	requireRunner(t)
	src := []byte(`import MbedTLS
`)
	rule := astRule("JULIA_IMPORT_MBEDTLS", "import:MbedTLS")

	r := &runner{}
	matches, err := r.Run("i.jl", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_using_DoesNotFireOnImport(t *testing.T) {
	requireRunner(t)
	// `using:Foo` rules must not fire on `import Foo`, and vice versa.
	src := []byte(`import SHA
`)
	rule := astRule("JULIA_USING_NEG", "using:SHA")

	r := &runner{}
	matches, err := r.Run("x.jl", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

// --- negative / boundary --------------------------------------------------

func TestRun_call_DoesNotFireOnUnrelated(t *testing.T) {
	requireRunner(t)
	src := []byte(`println("hello")
x = [1, 2, 3]
for i in x
    println(i)
end
`)
	rule := astRule("JULIA_NEG", "call:SHA.sha256")

	r := &runner{}
	matches, err := r.Run("x.jl", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_emptySourceReturnsNoMatches(t *testing.T) {
	requireRunner(t)
	rule := astRule("X", "call:SHA.sha256")
	r := &runner{}
	matches, err := r.Run("x.jl", []byte(""), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty source, got %d", len(matches))
	}
}

func TestRun_invalidSourceDoesNotPanic(t *testing.T) {
	requireRunner(t)
	// Tree-sitter is error-resilient: it produces a partial tree even when the
	// source is malformed. We just need to not panic and not over-match.
	rule := astRule("X", "call:SHA.sha256")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("x.jl", []byte("function foo;;; { not julia"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	requireRunner(t)
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "julia",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("x.jl", []byte("function x() end"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	requireRunner(t)
	r := &runner{}
	matches, err := r.Run("x.jl", []byte("function x() end"), nil)
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
		function string
		module   string
	}{
		{"call:SHA.sha256", queryCall, "SHA", "sha256", ""},
		{"call:Nettle.Hasher", queryCall, "Nettle", "Hasher", ""},
		{"call:A.B.func", queryCall, "A.B", "func", ""},
		{"call:sha1", queryCall, "", "sha1", ""},
		{"using:SHA", queryUsing, "", "", "SHA"},
		{"using:MbedTLS", queryUsing, "", "", "MbedTLS"},
		{"import:Nettle", queryImport, "", "", "Nettle"},
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
			if pq.function != tt.function {
				t.Errorf("function = %q, want %q", pq.function, tt.function)
			}
			if pq.module != tt.module {
				t.Errorf("module = %q, want %q", pq.module, tt.module)
			}
		})
	}
}

func TestParseQuery_invalid(t *testing.T) {
	for _, q := range []string{
		"",
		"badprefix:Foo",
		"call:",
		"call:Foo.", // empty function
		"call:.bare",
		"using:",
		"import:",
	} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("parseQuery(%q): expected error", q)
		}
	}
}

// --- helper unit tests ----------------------------------------------------

func TestLastDotSegment(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"SHA", "SHA"},
		{"A.B", "B"},
		{"A.B.C", "C"},
		{"", ""},
	}
	for _, tt := range tests {
		got := lastDotSegment(tt.in)
		if got != tt.want {
			t.Errorf("lastDotSegment(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
