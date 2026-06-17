// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package scalaast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests.
func astRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "scala",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

func TestRun_methodCall_MessageDigestGetInstance(t *testing.T) {
	src := []byte(`package acme
import java.security.MessageDigest
object T {
  def h(b: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("MD5")
    md.digest(b)
  }
}
`)
	rule := astRule("SCALA_MD5_DIGEST_TEST", "call:MessageDigest.getInstance")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "SCALA_MD5_DIGEST_TEST" {
		t.Errorf("Rule.ID = %q, want SCALA_MD5_DIGEST_TEST", matches[0].Rule.ID)
	}
	if matches[0].Line != 5 {
		t.Errorf("Line = %d, want 5", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, `MessageDigest.getInstance("MD5")`) {
		t.Errorf("Snippet = %q, want substring 'MessageDigest.getInstance(\"MD5\")'", matches[0].Snippet)
	}
}

func TestRun_methodCall_CipherGetInstanceDES(t *testing.T) {
	src := []byte(`package acme
import javax.crypto.Cipher
object T {
  def mk(): Cipher = Cipher.getInstance("DES")
}
`)
	rule := astRule("SCALA_DES_CIPHER", "call:Cipher.getInstance")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_newExpression_RSAKeyPairGenerator(t *testing.T) {
	// Synthetic crypto type to avoid depending on a specific JCA shape.
	src := []byte(`package acme
class RSAKeyPairGenerator
object T {
  def mk(): Unit = {
    val g = new RSAKeyPairGenerator()
  }
}
`)
	rule := astRule("SCALA_RSA_NEW", "new:RSAKeyPairGenerator")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
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

func TestRun_newExpression_NoArgs(t *testing.T) {
	// `new Foo` without parentheses must still match new:Foo.
	src := []byte(`package acme
class BouncyCastleProvider
object T {
  val p = new BouncyCastleProvider
}
`)
	rule := astRule("SCALA_BC_NEW", "new:BouncyCastleProvider")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_applyExpression_CompanionSugar(t *testing.T) {
	// `Cipher("DES")` desugars to Cipher.apply("DES") — apply:Cipher should fire.
	src := []byte(`package acme
object Cipher {
  def apply(alg: String): String = alg
}
object T {
  val c = Cipher("DES")
}
`)
	rule := astRule("SCALA_CIPHER_APPLY", "apply:Cipher")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) < 1 {
		t.Fatalf("expected at least 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_importDeclaration_Specific(t *testing.T) {
	src := []byte(`package acme
import java.security.MessageDigest
object T
`)
	rule := astRule("SCALA_IMPORT_MD", "import:java.security.MessageDigest")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
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

func TestRun_importDeclaration_Selectors(t *testing.T) {
	// `import javax.crypto.{Cipher, KeyGenerator}` should match a rule for
	// `javax.crypto.Cipher`.
	src := []byte(`package acme
import javax.crypto.{Cipher, KeyGenerator}
object T
`)
	rule := astRule("SCALA_IMPORT_CIPHER_SELECTOR", "import:javax.crypto.Cipher")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_importDeclaration_WildcardUnderscore(t *testing.T) {
	// `import javax.crypto._` is the Scala 2 wildcard form — it should match a
	// specific rule for `javax.crypto.Cipher`.
	src := []byte(`package acme
import javax.crypto._
object T
`)
	rule := astRule("SCALA_IMPORT_CIPHER_WILDCARD", "import:javax.crypto.Cipher")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_importDeclaration_RuleWildcard(t *testing.T) {
	src := []byte(`package acme
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import java.security.MessageDigest
object T
`)
	rule := astRule("SCALA_IMPORT_CRYPTO_STAR", "import:javax.crypto.*")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// javax.crypto.* should match the Cipher import and the spec.IvParameterSpec
	// import (which is under javax.crypto), but NOT the java.security one.
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_callDoesNotFireOnUnrelatedMethod(t *testing.T) {
	src := []byte(`package acme
object T {
  def k(): Unit = {
    val x = "hello"
    x.toUpperCase()
  }
}
`)
	// call:MessageDigest.getInstance should NOT match x.toUpperCase().
	rule := astRule("SCALA_NEGATIVE", "call:MessageDigest.getInstance")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
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
	matches, err := r.Run("T.scala", []byte(""), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty source, got %d", len(matches))
	}
}

func TestRun_invalidSourceDoesNotPanic(t *testing.T) {
	rule := astRule("X", "call:MessageDigest.getInstance")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("T.scala", []byte("this is { not valid scala }}}"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "scala",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("T.scala", []byte("object T"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("T.scala", []byte("object T"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestRun_lineNumbersAreCorrect(t *testing.T) {
	src := []byte(`package acme

import java.security.MessageDigest

object T {
  def h(): Unit = {
    val md = MessageDigest.getInstance("MD5")
  }
}
`)
	rule := astRule("SCALA_MD5_LINE_TEST", "call:MessageDigest.getInstance")

	r := &runner{}
	matches, err := r.Run("T.scala", src, []*rules.Rule{rule})
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
		{"new:RSAKeyPairGenerator", queryNew, "RSAKeyPairGenerator", "", ""},
		{"apply:Cipher", queryApply, "Cipher", "", ""},
		{"import:javax.crypto.Cipher", queryImport, "", "", "javax.crypto.Cipher"},
		{"memberref:Cipher.ENCRYPT_MODE", queryMemberRef, "Cipher", "ENCRYPT_MODE", ""},
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
		"apply:",
		"import:",
		"memberref:nodot",
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
		// tsec
		{"tsec.hashing.jca.*", "tsec.hashing.jca.MD5", false, true},
		{"tsec.hashing.jca.MD5", "tsec.hashing.jca", true, true},
	}
	for _, tt := range tests {
		got := importMatches(tt.rulePath, tt.importPath, tt.importIsWildcard)
		if got != tt.want {
			t.Errorf("importMatches(%q, %q, %v) = %v, want %v",
				tt.rulePath, tt.importPath, tt.importIsWildcard, got, tt.want)
		}
	}
}
