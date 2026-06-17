// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package javaast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests.
func astRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "java",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

func TestRun_methodInvocation_MessageDigestGetInstance(t *testing.T) {
	src := []byte(`package acme;
import java.security.MessageDigest;
public class T {
    public static byte[] H(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(b);
    }
}
`)
	rule := astRule("JAVA_MD5_DIGEST_TEST", "call:MessageDigest.getInstance")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "JAVA_MD5_DIGEST_TEST" {
		t.Errorf("Rule.ID = %q, want JAVA_MD5_DIGEST_TEST", matches[0].Rule.ID)
	}
	if matches[0].Line != 5 {
		t.Errorf("Line = %d, want 5", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, `MessageDigest.getInstance("MD5")`) {
		t.Errorf("Snippet = %q, want substring 'MessageDigest.getInstance(\"MD5\")'", matches[0].Snippet)
	}
}

func TestRun_objectCreation_NewRSAPrivateKey(t *testing.T) {
	// Hypothetical: `new` form of a vulnerable type. We use a synthetic class
	// to avoid depending on a specific JCA shape.
	src := []byte(`package acme;
class RSAPrivateKey {}
public class T {
    void mk() {
        Object k = new RSAPrivateKey();
    }
}
`)
	rule := astRule("JAVA_RSA_PRIVATE_KEY_NEW", "new:RSAPrivateKey")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
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

func TestRun_importDeclaration_Specific(t *testing.T) {
	src := []byte(`package acme;
import javax.crypto.spec.IvParameterSpec;
public class T {}
`)
	rule := astRule("JAVA_IMPORT_IV", "import:javax.crypto.spec.IvParameterSpec")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
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

func TestRun_importDeclaration_WildcardSourceMatchesSpecificRule(t *testing.T) {
	// `import javax.crypto.spec.*` should match a rule targeting
	// `javax.crypto.spec.IvParameterSpec`.
	src := []byte(`package acme;
import javax.crypto.spec.*;
public class T {}
`)
	rule := astRule("JAVA_IMPORT_IV_WILDCARD", "import:javax.crypto.spec.IvParameterSpec")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_importDeclaration_RuleWildcard(t *testing.T) {
	src := []byte(`package acme;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.security.MessageDigest;
public class T {}
`)
	rule := astRule("JAVA_IMPORT_CRYPTO_STAR", "import:javax.crypto.*")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// javax.crypto.* should match the IvParameterSpec import (line 2, in
	// javax.crypto.spec) and the Cipher import (line 3, in javax.crypto),
	// but NOT the java.security.MessageDigest import (line 4).
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_fieldRef_Type_field(t *testing.T) {
	src := []byte(`package acme;
public class T {
    void use() {
        int n = Integer.MAX_VALUE;
    }
}
`)
	rule := astRule("JAVA_FIELDREF_TEST", "fieldref:Integer.MAX_VALUE")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
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

func TestRun_callDoesNotFireOnUnrelatedMethod(t *testing.T) {
	src := []byte(`package acme;
public class T {
    void k() {
        String x = "hello";
        x.toUpperCase();
    }
}
`)
	// call:MessageDigest.getInstance should NOT match x.toUpperCase().
	rule := astRule("JAVA_NEGATIVE", "call:MessageDigest.getInstance")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_emptySourceReturnsNoMatches(t *testing.T) {
	rule := astRule("X", "call:MessageDigest.getInstance")
	r := &runner{}
	matches, err := r.Run("T.java", []byte(""), []*rules.Rule{rule})
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
	rule := astRule("X", "call:MessageDigest.getInstance")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("T.java", []byte("this is { not valid java }}}"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "java",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("T.java", []byte("class T {}"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("T.java", []byte("class T {}"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestRun_lineNumbersAreCorrect(t *testing.T) {
	// MessageDigest.getInstance is on line 7. Verify exact line + reasonable column.
	src := []byte(`package acme;

import java.security.MessageDigest;

public class T {
    void h() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
`)
	rule := astRule("JAVA_MD5_LINE_TEST", "call:MessageDigest.getInstance")

	r := &runner{}
	matches, err := r.Run("T.java", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 7 {
		t.Errorf("Line = %d, want 7", matches[0].Line)
	}
	if matches[0].Column < 1 {
		t.Errorf("Column = %d, want >= 1", matches[0].Column)
	}
	// Context should include the matched line.
	foundInContext := false
	for _, c := range matches[0].Context {
		if strings.Contains(c, `MessageDigest.getInstance("MD5")`) {
			foundInContext = true
			break
		}
	}
	if !foundInContext {
		t.Errorf("Context did not include the matched line: %v", matches[0].Context)
	}
}

func TestParseQuery_kinds(t *testing.T) {
	tests := []struct {
		in   string
		kind queryKind
		typ  string
		name string
		path string
	}{
		{"call:MessageDigest.getInstance", queryCall, "MessageDigest", "getInstance", ""},
		{"new:RSAPrivateKey", queryNew, "RSAPrivateKey", "", ""},
		{"import:javax.crypto.Cipher", queryImport, "", "", "javax.crypto.Cipher"},
		{"fieldref:Integer.MAX_VALUE", queryFieldRef, "Integer", "MAX_VALUE", ""},
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
			if pq.typ != tt.typ {
				t.Errorf("typ = %q, want %q", pq.typ, tt.typ)
			}
			if pq.name != tt.name {
				t.Errorf("name = %q, want %q", pq.name, tt.name)
			}
			if pq.path != tt.path {
				t.Errorf("path = %q, want %q", pq.path, tt.path)
			}
		})
	}
}

func TestParseQuery_invalid(t *testing.T) {
	for _, q := range []string{
		"",
		"badprefix:Foo",
		"call:nodot",
		"new:",
		"import:",
		"fieldref:nodot",
	} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("parseQuery(%q): expected error", q)
		}
	}
}

func TestImportMatches(t *testing.T) {
	tests := []struct {
		rulePath, importPath string
		importIsWildcard     bool
		want                 bool
	}{
		// Exact match
		{"javax.crypto.Cipher", "javax.crypto.Cipher", false, true},
		{"javax.crypto.Cipher", "javax.crypto.Mac", false, false},
		// Wildcard source covers specific rule
		{"javax.crypto.Cipher", "javax.crypto", true, true},
		{"javax.crypto.Cipher", "java.security", true, false},
		// Wildcard rule
		{"javax.crypto.*", "javax.crypto.Cipher", false, true},
		{"javax.crypto.*", "javax.crypto", false, true},
		{"javax.crypto.*", "java.security.MessageDigest", false, false},
		// Wildcard rule + wildcard source -> not currently handled; just exercise
		{"javax.crypto.*", "javax.crypto.spec", true, true},
	}
	for _, tt := range tests {
		got := importMatches(tt.rulePath, tt.importPath, tt.importIsWildcard)
		if got != tt.want {
			t.Errorf("importMatches(%q, %q, %v) = %v, want %v",
				tt.rulePath, tt.importPath, tt.importIsWildcard, got, tt.want)
		}
	}
}
