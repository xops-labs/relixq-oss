// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package jstsast

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

// Additional edge-case tests for the import scanner and the line-number
// preserving import strip. These complement runner_test.go.

func TestScanImports_findsESMAndCJS(t *testing.T) {
	src := []byte(`import * as crypto from 'crypto';
import 'side-effect-only';
const NodeRSA = require('node-rsa');
const lazy = require("lodash");
`)
	hits := scanImports(src)
	got := map[string]int{}
	for _, h := range hits {
		got[h.module] = h.line
	}
	want := map[string]int{
		"crypto":            1,
		"side-effect-only":  2,
		"node-rsa":          3,
		"lodash":            4,
	}
	for mod, line := range want {
		if got[mod] != line {
			t.Errorf("scanImports: module %q at line %d, want %d (got map: %v)", mod, got[mod], line, got)
		}
	}
}

func TestStripImportLines_preservesLineCount(t *testing.T) {
	src := []byte(`import * as crypto from 'crypto';
const x = 1;
import 'side';
const y = 2;
`)
	out := stripImportLines(src)
	srcLines := strings.Count(string(src), "\n")
	outLines := strings.Count(string(out), "\n")
	if srcLines != outLines {
		t.Errorf("stripImportLines changed line count: src=%d out=%d", srcLines, outLines)
	}
	// Body lines should still contain their content.
	if !strings.Contains(string(out), "const x = 1;") {
		t.Error("stripImportLines removed body line `const x = 1;`")
	}
	if !strings.Contains(string(out), "const y = 2;") {
		t.Error("stripImportLines removed body line `const y = 2;`")
	}
	// Import lines should be blanked (no `import` keyword left).
	if strings.Contains(string(out), "import") {
		t.Errorf("stripImportLines left an import keyword in: %q", string(out))
	}
}

// TestRun_lineNumbersInOriginalSource asserts that when a TS file has type
// annotations padding multiple lines, the match line is still the line in
// the ORIGINAL source where the user's call sits.
func TestRun_lineNumbersInOriginalSource(t *testing.T) {
	r := &runner{}
	src := []byte(`// line 1
// line 2
import * as crypto from 'crypto';
// line 4
interface Big {
  a: number;
  b: number;
  c: number;
}
// line 10
function ohno(): string {
  return crypto.createHash('md5').digest('hex');
}
`)
	rule := &rules.Rule{
		ID:       "TS_MD5_LINENO",
		Language: "typescript",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:crypto.createHash"},
	}
	matches, err := r.Run("file.ts", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one TS_MD5_LINENO match")
	}
	// The createHash call sits on line 12 of the ORIGINAL TS.
	if matches[0].Line != 12 {
		t.Errorf("match.Line = %d, want 12 (original-source line number after esbuild source-map remap)", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "createHash") {
		t.Errorf("snippet should come from ORIGINAL source: got %q", matches[0].Snippet)
	}
}
