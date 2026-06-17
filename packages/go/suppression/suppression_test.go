// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package suppression

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseInline_bareSuppressesAll(t *testing.T) {
	d := ParseInline("    // relixq-ignore")
	if d == nil || !d.All {
		t.Fatalf("expected all-suppress directive, got %+v", d)
	}
	if !d.Suppresses("ANY_RULE") {
		t.Fatal("All directive should suppress every rule")
	}
}

func TestParseInline_specificRules(t *testing.T) {
	d := ParseInline("# relixq-ignore: CSHARP_RSA_CREATE, CSHARP_SHA1")
	if d == nil || d.All {
		t.Fatalf("expected scoped directive, got %+v", d)
	}
	if !d.Suppresses("CSHARP_RSA_CREATE") {
		t.Fatal("expected RSA suppressed")
	}
	if d.Suppresses("CSHARP_DSA_CREATE") {
		t.Fatal("DSA must not be suppressed")
	}
}

func TestParseInline_noDirective(t *testing.T) {
	if ParseInline("var x = 1; // not relevant") != nil {
		t.Fatal("non-directive line should not parse")
	}
}

func TestSet_defaultExcludesNodeModules(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsExcluded("node_modules/lib/x.js", false) {
		t.Fatal("node_modules should be excluded by default")
	}
	if !s.IsExcluded(".git/HEAD", false) {
		t.Fatal(".git should be excluded by default")
	}
}

func TestSet_relixqignoreOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".relixqignore"), []byte("/build/\n*.generated.cs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsExcluded("build/output.dll", false) {
		t.Fatal("build/ must be excluded")
	}
	if !s.IsExcluded("src/Foo.generated.cs", false) {
		t.Fatal("*.generated.cs must be excluded")
	}
	if s.IsExcluded("src/Foo.cs", false) {
		t.Fatal("src/Foo.cs must NOT be excluded")
	}
}
