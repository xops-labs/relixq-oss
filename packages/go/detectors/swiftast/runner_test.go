// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

package swiftast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// astRule is a tiny factory for AST-typed rules in tests.
func astRule(id, query string) *rules.Rule {
	return &rules.Rule{
		ID:       id,
		Language: "swift",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: query},
	}
}

func TestRun_callFreeFunction_CC_MD5(t *testing.T) {
	src := []byte(`import CommonCrypto

func digest(_ data: UnsafeRawPointer, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) {
    CC_MD5(data, len, md)
}
`)
	rule := astRule("SWIFT_CC_MD5", "call:CC_MD5")

	r := &runner{}
	matches, err := r.Run("Hash.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "SWIFT_CC_MD5" {
		t.Errorf("Rule.ID = %q, want SWIFT_CC_MD5", matches[0].Rule.ID)
	}
	if matches[0].Line != 4 {
		t.Errorf("Line = %d, want 4", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "CC_MD5") {
		t.Errorf("Snippet = %q, want substring 'CC_MD5'", matches[0].Snippet)
	}
}

func TestRun_callFreeFunction_CC_SHA1(t *testing.T) {
	src := []byte(`import CommonCrypto

func h(_ data: UnsafeRawPointer, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) {
    CC_SHA1(data, len, md)
}
`)
	rule := astRule("SWIFT_CC_SHA1", "call:CC_SHA1")

	r := &runner{}
	matches, err := r.Run("Hash.swift", src, []*rules.Rule{rule})
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

func TestRun_callMember_InsecureMD5Hash(t *testing.T) {
	// CryptoKit `Insecure.MD5.hash(data:)` — apple explicitly tags this namespace
	// as insecure, perfect rule fodder.
	src := []byte(`import CryptoKit

func fingerprint(_ data: Data) -> Insecure.MD5.Digest {
    return Insecure.MD5.hash(data: data)
}
`)
	rule := astRule("SWIFT_INSECURE_MD5_HASH", "call:Insecure.MD5.hash")

	r := &runner{}
	matches, err := r.Run("Hash.swift", src, []*rules.Rule{rule})
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

func TestRun_callMember_InsecureSHA1Hash(t *testing.T) {
	src := []byte(`import CryptoKit

func fingerprint(_ data: Data) -> Insecure.SHA1.Digest {
    return Insecure.SHA1.hash(data: data)
}
`)
	rule := astRule("SWIFT_INSECURE_SHA1_HASH", "call:Insecure.SHA1.hash")

	r := &runner{}
	matches, err := r.Run("Hash.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_initializerCall_SecKeyCreateRandomKey(t *testing.T) {
	// SecKeyCreateRandomKey is a free function returning a SecKey?; we match
	// it via `call:` even though the user wrote it as a function call (no
	// dotted prefix). Demonstrates the unified call form.
	src := []byte(`import Security

func newKey() -> SecKey? {
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 2048,
    ]
    var err: Unmanaged<CFError>?
    return SecKeyCreateRandomKey(attrs as CFDictionary, &err)
}
`)
	rule := astRule("SWIFT_SEC_KEY_CREATE", "call:SecKeyCreateRandomKey")

	r := &runner{}
	matches, err := r.Run("Key.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if !strings.Contains(matches[0].Snippet, "SecKeyCreateRandomKey") {
		t.Errorf("Snippet = %q, want substring 'SecKeyCreateRandomKey'", matches[0].Snippet)
	}
}

func TestRun_initForm_AsAliasOfCall(t *testing.T) {
	// `init:Foo` should match `Foo(...)` exactly the same as `call:Foo`. We
	// use a synthetic capitalized type to mimic a Swift initializer.
	src := []byte(`struct LegacyHasher {}
let h = LegacyHasher()
`)
	rule := astRule("SWIFT_LEGACY_HASHER_INIT", "init:LegacyHasher")

	r := &runner{}
	matches, err := r.Run("Init.swift", src, []*rules.Rule{rule})
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

func TestRun_importDeclaration_CommonCrypto(t *testing.T) {
	src := []byte(`import CommonCrypto

func _f() {}
`)
	rule := astRule("SWIFT_IMPORT_COMMONCRYPTO", "import:CommonCrypto")

	r := &runner{}
	matches, err := r.Run("X.swift", src, []*rules.Rule{rule})
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

func TestRun_importDeclaration_CryptoKit(t *testing.T) {
	src := []byte(`import CryptoKit
import Foundation

func _f() {}
`)
	rule := astRule("SWIFT_IMPORT_CRYPTOKIT", "import:CryptoKit")

	r := &runner{}
	matches, err := r.Run("X.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
}

func TestRun_importDeclaration_RuleWildcardSwiftSubmodule(t *testing.T) {
	src := []byte(`import struct Foundation.Data
import Foundation
import UIKit

func _f() {}
`)
	rule := astRule("SWIFT_IMPORT_FOUNDATION_STAR", "import:Foundation.*")

	r := &runner{}
	matches, err := r.Run("X.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Foundation.* should match `Foundation.Data` (line 1) and `Foundation`
	// (line 2), but not UIKit.
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_memberRef_NotInCallPosition(t *testing.T) {
	// `kSecAttrKeyTypeRSA` is referenced as a dictionary value — not a call —
	// so a memberref rule should fire even though no parentheses are present.
	// We use a synthetic dotted reference for clarity.
	src := []byte(`import Security

let kt: CFString = LegacyConsts.rsaKeyType
`)
	rule := astRule("SWIFT_LEGACY_CONST_REF", "memberref:LegacyConsts.rsaKeyType")

	r := &runner{}
	matches, err := r.Run("Ref.swift", src, []*rules.Rule{rule})
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

func TestRun_memberRef_DoesNotFireWhenCalled(t *testing.T) {
	// `Insecure.MD5.hash(data:)` is a call_expression; a memberref rule
	// matching `Insecure.MD5.hash` must not fire on it (calls are owned by
	// the `call:` query kind).
	src := []byte(`import CryptoKit

func go(_ d: Data) -> Insecure.MD5.Digest {
    return Insecure.MD5.hash(data: d)
}
`)
	rule := astRule("SWIFT_MEMBERREF_NEG", "memberref:Insecure.MD5.hash")

	r := &runner{}
	matches, err := r.Run("Neg.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches (call_expression target should not trigger memberref), got %d: %+v", len(matches), matches)
	}
}

func TestRun_callDoesNotFireOnUnrelatedFunction(t *testing.T) {
	src := []byte(`func main() {
    let s = "hello"
    print(s.uppercased())
}
`)
	rule := astRule("SWIFT_NEGATIVE", "call:CC_MD5")

	r := &runner{}
	matches, err := r.Run("Neg.swift", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d: %+v", len(matches), matches)
	}
}

func TestRun_emptySourceReturnsNoMatches(t *testing.T) {
	rule := astRule("X", "call:CC_MD5")
	r := &runner{}
	matches, err := r.Run("X.swift", []byte(""), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty source, got %d", len(matches))
	}
}

func TestRun_invalidSourceDoesNotPanic(t *testing.T) {
	rule := astRule("X", "call:CC_MD5")
	r := &runner{}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic on invalid source: %v", rec)
		}
	}()
	_, err := r.Run("X.swift", []byte("this is { not valid swift }}}"), []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run on invalid source: %v", err)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	regexRule := &rules.Rule{
		ID:       "REGEX_RULE",
		Language: "swift",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	r := &runner{}
	matches, err := r.Run("X.swift", []byte("func x() {}"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("X.swift", []byte("func x() {}"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestRun_lineNumbersAreCorrect(t *testing.T) {
	// CC_MD5 is on line 7. Verify exact line + reasonable column.
	src := []byte(`import CommonCrypto

// pad lines so the call shifts down
// to a non-trivial line number
func h(_ d: UnsafeRawPointer, _ l: CC_LONG, _ m: UnsafeMutablePointer<UInt8>) {
    // The vulnerable call:
    CC_MD5(d, l, m)
}
`)
	rule := astRule("SWIFT_LINE_TEST", "call:CC_MD5")

	r := &runner{}
	matches, err := r.Run("X.swift", src, []*rules.Rule{rule})
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
		if strings.Contains(c, "CC_MD5(") {
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
		in       string
		kind     queryKind
		path     string
		wildcard bool
	}{
		{"call:CC_MD5", queryCall, "CC_MD5", false},
		{"call:Insecure.MD5.hash", queryCall, "Insecure.MD5.hash", false},
		{"init:Insecure.MD5", queryInit, "Insecure.MD5", false},
		{"import:CommonCrypto", queryImport, "CommonCrypto", false},
		{"import:Foundation.*", queryImport, "Foundation", true},
		{"memberref:LegacyConsts.rsaKeyType", queryMemberRef, "LegacyConsts.rsaKeyType", false},
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
		"init:",
		"import:",
		"memberref:",
		"memberref:noDot",
	} {
		if _, err := parseQuery(q); err == nil {
			t.Errorf("parseQuery(%q): expected error", q)
		}
	}
}

func TestImportMatches(t *testing.T) {
	tests := []struct {
		ruleQuery  string
		importPath string
		want       bool
	}{
		// Exact match.
		{"import:CommonCrypto", "CommonCrypto", true},
		{"import:CommonCrypto", "CryptoKit", false},
		// Submodule exact.
		{"import:Foundation.Data", "Foundation.Data", true},
		// Wildcard rule.
		{"import:Foundation.*", "Foundation", true},
		{"import:Foundation.*", "Foundation.Data", true},
		{"import:Foundation.*", "Foundation.NSData.Inner", true},
		{"import:Foundation.*", "UIKit", false},
	}
	for _, tt := range tests {
		pq, err := parseQuery(tt.ruleQuery)
		if err != nil {
			t.Fatalf("parseQuery(%q): %v", tt.ruleQuery, err)
		}
		got := importMatches(pq, tt.importPath)
		if got != tt.want {
			t.Errorf("importMatches(%q, %q) = %v, want %v",
				tt.ruleQuery, tt.importPath, got, tt.want)
		}
	}
}
