// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package cppast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests. `lang` controls the
// rule's Language field (which the runner does not key off — selection by
// extension happens inside Run — but we set it for completeness).
func astRule(id, lang, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: lang,
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

func TestRun_call_RSA_generate_key_ex_inC(t *testing.T) {
	src := []byte(`#include <openssl/rsa.h>

int gen(void) {
    RSA *r = RSA_new();
    int rc = RSA_generate_key_ex(r, 2048, NULL, NULL);
    return rc;
}
`)
	rule := astRule("C_RSA_GEN_TEST", "c", "call:RSA_generate_key_ex")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "C_RSA_GEN_TEST" {
		t.Errorf("Rule.ID = %q, want C_RSA_GEN_TEST", matches[0].Rule.ID)
	}
	if matches[0].Line != 5 {
		t.Errorf("Line = %d, want 5", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "RSA_generate_key_ex(r") {
		t.Errorf("Snippet = %q, want substring 'RSA_generate_key_ex(r'", matches[0].Snippet)
	}
}

func TestRun_call_EVP_md5_noArgs_inC(t *testing.T) {
	src := []byte(`#include <openssl/evp.h>

void h(void) {
    const EVP_MD *m = EVP_md5();
    (void)m;
}
`)
	rule := astRule("C_MD5_TEST", "c", "call:EVP_md5")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
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

func TestRun_methodCall_inCpp(t *testing.T) {
	// Instance method via `.` — bar.compute(payload) should match
	// methodcall:compute. Receiver type is intentionally not constrained.
	src := []byte(`#include <string>

class Hasher {
public:
    std::string compute(const std::string &in);
};

void run() {
    Hasher bar;
    std::string out = bar.compute("data");
    (void)out;
}
`)
	rule := astRule("CPP_METHOD_COMPUTE", "cpp", "methodcall:compute")

	r := &runner{}
	matches, err := r.Run("vuln.cpp", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 10 {
		t.Errorf("Line = %d, want 10", matches[0].Line)
	}
}

func TestRun_methodCall_arrowOperator_inCpp(t *testing.T) {
	// Same shape via `->`. Tree-sitter normalizes both `.` and `->` into
	// a `field_expression` with a `field` child, so one rule handles both.
	src := []byte(`#include <memory>

class Hasher { public: int compute(); };

int run(Hasher *p) {
    return p->compute();
}
`)
	rule := astRule("CPP_METHOD_COMPUTE_ARROW", "cpp", "methodcall:compute")

	r := &runner{}
	matches, err := r.Run("vuln.cpp", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 6 {
		t.Errorf("Line = %d, want 6", matches[0].Line)
	}
}

func TestRun_call_qualified_Cpp(t *testing.T) {
	// C++ scoped call: Outer::Inner::fn(...) should match
	// call:Outer::Inner::fn.
	src := []byte(`namespace Outer {
namespace Inner {
    int fn(int x);
}
}

int run() {
    return Outer::Inner::fn(42);
}
`)
	rule := astRule("CPP_QUALIFIED_FN", "cpp", "call:Outer::Inner::fn")

	r := &runner{}
	matches, err := r.Run("vuln.cpp", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 8 {
		t.Errorf("Line = %d, want 8", matches[0].Line)
	}
}

func TestRun_include_angleBrackets(t *testing.T) {
	src := []byte(`#include <openssl/rsa.h>

int main(void) { return 0; }
`)
	rule := astRule("C_INC_RSA_ANGLE", "c", "include:openssl/rsa.h")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
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

func TestRun_include_quoted(t *testing.T) {
	src := []byte(`#include "openssl/rsa.h"

int main(void) { return 0; }
`)
	rule := astRule("C_INC_RSA_QUOTED", "c", "include:openssl/rsa.h")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
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

func TestRun_ident_RSA_PKCS1_PADDING(t *testing.T) {
	src := []byte(`#include <openssl/rsa.h>

int call(RSA *r, unsigned char *out, const unsigned char *in, int n) {
    return RSA_public_encrypt(n, in, out, r, RSA_PKCS1_PADDING);
}
`)
	rule := astRule("C_PADDING_REF", "c", "ident:RSA_PKCS1_PADDING")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match of bare constant ref, got %d: %+v", len(matches), matches)
	}
	if matches[0].Line != 4 {
		t.Errorf("Line = %d, want 4", matches[0].Line)
	}
}

func TestRun_ident_doesNotFireOnCallCallee(t *testing.T) {
	// `EVP_md5()` would create a `call_expression` whose `function` is an
	// `identifier` named EVP_md5. A rule `ident:EVP_md5` MUST NOT match
	// that callee — it should only match value references. We verify by
	// supplying ONLY the ident rule and asserting 0 matches.
	src := []byte(`#include <openssl/evp.h>

void run(void) {
    const EVP_MD *m = EVP_md5();
    (void)m;
}
`)
	rule := astRule("C_IDENT_CALLEE_NEGATIVE", "c", "ident:EVP_md5")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 ident matches on call callee, got %d: %+v", len(matches), matches)
	}
}

func TestRun_grammarSelection_byExtension(t *testing.T) {
	// Same runner instance, different file extensions: a `.c` file should
	// parse with the C grammar (which doesn't know about namespaces, but
	// happily parses bare-call syntax) and a `.cpp` file should parse with
	// the C++ grammar.
	r := &runner{}

	cSrc := []byte(`int main(void) { return RSA_generate_key_ex(0,0,0,0); }
`)
	cppSrc := []byte(`namespace ns { int f(); }
int main() { return ns::f(); }
`)

	cMatches, err := r.Run("a.c", cSrc, []*rules.Rule{
		astRule("C_RSA", "c", "call:RSA_generate_key_ex"),
	})
	if err != nil {
		t.Fatalf("Run(.c): %v", err)
	}
	if len(cMatches) != 1 {
		t.Errorf("Run(.c): expected 1, got %d", len(cMatches))
	}

	cppMatches, err := r.Run("a.cpp", cppSrc, []*rules.Rule{
		astRule("CPP_NS", "cpp", "call:ns::f"),
	})
	if err != nil {
		t.Fatalf("Run(.cpp): %v", err)
	}
	if len(cppMatches) != 1 {
		t.Errorf("Run(.cpp): expected 1, got %d", len(cppMatches))
	}
}

func TestRun_grammarSelection_dotHHeader(t *testing.T) {
	// `.h` is routed to the C parser. A C-style declaration in a `.h`
	// must parse cleanly so the include + call extraction works.
	src := []byte(`#include <openssl/rsa.h>

int helper(void);
`)
	rule := astRule("C_H_INCLUDE", "c", "include:openssl/rsa.h")

	r := &runner{}
	matches, err := r.Run("api.h", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match in .h, got %d", len(matches))
	}
}

func TestRun_callDoesNotFireOnUnrelatedFunction(t *testing.T) {
	src := []byte(`void run(void) {
    foo(1);
    bar(2);
}
`)
	rule := astRule("C_NEGATIVE", "c", "call:RSA_generate_key_ex")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_emptySourceReturnsNoMatches(t *testing.T) {
	rule := astRule("X", "c", "call:RSA_generate_key_ex")
	r := &runner{}
	matches, err := r.Run("vuln.c", []byte(""), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty source, got %d", len(matches))
	}
}

func TestRun_invalidSourceDoesNotPanic(t *testing.T) {
	// Tree-sitter is error-resilient; partial trees produce no panic.
	rule := astRule("X", "c", "call:RSA_generate_key_ex")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("vuln.c", []byte("this is { not valid C }}}"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "c",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("vuln.c", []byte("int main(void){return 0;}"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("vuln.c", []byte("int main(void){return 0;}"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestParseQuery_kinds(t *testing.T) {
	tests := []struct {
		in    string
		kind  queryKind
		value string
	}{
		{"call:RSA_generate_key_ex", queryCall, "RSA_generate_key_ex"},
		{"call:Outer::Inner::fn", queryCall, "Outer::Inner::fn"},
		{"methodcall:compute", queryMethodCall, "compute"},
		{"include:openssl/rsa.h", queryInclude, "openssl/rsa.h"},
		{"ident:RSA_PKCS1_PADDING", queryIdent, "RSA_PKCS1_PADDING"},
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
			if pq.value != tt.value {
				t.Errorf("value = %q, want %q", pq.value, tt.value)
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
		"include:",
		"ident:",
		"nokind",
	} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("parseQuery(%q): expected error", q)
		}
	}
}

func TestStripTemplateSuffix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Foo::bar", "Foo::bar"},
		{"Foo::bar<int>", "Foo::bar"},
		{"Foo<T>::bar", "Foo<T>::bar"},
		{"plain", "plain"},
		{"plain<X>", "plain"},
	}
	for _, tt := range tests {
		if got := stripTemplateSuffix(tt.in); got != tt.want {
			t.Errorf("stripTemplateSuffix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRun_lineNumbersAreCorrect(t *testing.T) {
	src := []byte(`#include <openssl/rsa.h>


int gen(void) {
    return RSA_generate_key_ex(0, 2048, 0, 0);
}
`)
	rule := astRule("C_LINE_TEST", "c", "call:RSA_generate_key_ex")

	r := &runner{}
	matches, err := r.Run("vuln.c", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 5 {
		t.Errorf("Line = %d, want 5", matches[0].Line)
	}
	if matches[0].Column < 1 {
		t.Errorf("Column = %d, want >= 1", matches[0].Column)
	}
	// Context window should include the matched line.
	foundInContext := false
	for _, c := range matches[0].Context {
		if strings.Contains(c, "RSA_generate_key_ex(0, 2048") {
			foundInContext = true
			break
		}
	}
	if !foundInContext {
		t.Errorf("Context did not include the matched line: %v", matches[0].Context)
	}
}
