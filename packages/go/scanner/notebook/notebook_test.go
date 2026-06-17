// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package notebook

import (
	"os"
	"strings"
	"testing"
)

// goldenNotebook covers both source shapes (array-of-strings with embedded
// newlines AND single-string), a markdown cell that must be skipped, and an
// empty code cell that must not advance the lineMap. Indentation is JSON-
// literal so the test mirrors what real .ipynb files look like on disk.
const goldenNotebook = `{
 "cells": [
  {
   "cell_type": "code",
   "metadata": {},
   "source": [
    "import hashlib\n",
    "h = hashlib.md5(b'x').hexdigest()\n"
   ]
  },
  {
   "cell_type": "markdown",
   "source": "## This is markdown — must be skipped"
  },
  {
   "cell_type": "code",
   "source": ""
  },
  {
   "cell_type": "code",
   "source": "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
  }
 ],
 "metadata": {},
 "nbformat": 4,
 "nbformat_minor": 5
}`

func TestPreprocess_goldenMixedShapes(t *testing.T) {
	synth, lineMap, err := Preprocess([]byte(goldenNotebook))
	if err != nil {
		t.Fatalf("Preprocess: %v", err)
	}
	if len(synth) == 0 {
		t.Fatal("expected non-empty synthesized buffer")
	}

	lines := strings.Split(strings.TrimRight(string(synth), "\n"), "\n")
	// Two code cells contribute: 2 lines + blank-separator + 2 lines = 5 lines.
	if got, want := len(lines), 5; got != want {
		t.Fatalf("synthesized line count = %d, want %d\nbuffer:\n%s", got, want, string(synth))
	}

	wantBody := []string{
		"import hashlib",
		"h = hashlib.md5(b'x').hexdigest()",
		"",
		"from cryptography.hazmat.primitives.asymmetric import rsa",
		"key = rsa.generate_private_key(public_exponent=65537, key_size=1024)",
	}
	for i, w := range wantBody {
		if lines[i] != w {
			t.Errorf("synth line %d = %q, want %q", i+1, lines[i], w)
		}
	}

	// lineMap must be 1:1 with the synthesized lines.
	if got, want := len(lineMap), len(wantBody); got != want {
		t.Fatalf("lineMap length = %d, want %d", got, want)
	}

	// First code cell: lines 1-2 → (cell=0, line=1), (cell=0, line=2).
	wantMap := []SourceLine{
		{CellIndex: 0, CellLine: 1},
		{CellIndex: 0, CellLine: 2},
		// Separator line points at the START of the upcoming cell. The empty
		// code cell was skipped so its codeIdx (1) is consumed even though it
		// produced no source; the next non-empty code cell therefore lands at
		// codeIdx 2.
		{CellIndex: 2, CellLine: 1},
		{CellIndex: 2, CellLine: 1},
		{CellIndex: 2, CellLine: 2},
	}
	for i, w := range wantMap {
		if lineMap[i] != w {
			t.Errorf("lineMap[%d] = %+v, want %+v", i, lineMap[i], w)
		}
	}
}

func TestTranslateLine_acrossCellBoundary(t *testing.T) {
	_, lineMap, err := Preprocess([]byte(goldenNotebook))
	if err != nil {
		t.Fatalf("Preprocess: %v", err)
	}

	// Synthesized line 2 is `h = hashlib.md5(...)` — should resolve to the
	// SECOND line of the FIRST code cell.
	cell, cellLine, ok := TranslateLine(lineMap, 2)
	if !ok {
		t.Fatal("TranslateLine(2) returned ok=false")
	}
	if cell != 0 || cellLine != 2 {
		t.Errorf("TranslateLine(2) = (%d, %d), want (0, 2)", cell, cellLine)
	}

	// Synthesized line 5 is the second line of the third code cell (cell
	// index 2 — the empty code cell consumed index 1 but emitted nothing).
	cell, cellLine, ok = TranslateLine(lineMap, 5)
	if !ok {
		t.Fatal("TranslateLine(5) returned ok=false")
	}
	if cell != 2 || cellLine != 2 {
		t.Errorf("TranslateLine(5) = (%d, %d), want (2, 2)", cell, cellLine)
	}

	// Out-of-range line numbers return ok=false.
	if _, _, ok := TranslateLine(lineMap, 0); ok {
		t.Error("TranslateLine(0) should return ok=false")
	}
	if _, _, ok := TranslateLine(lineMap, len(lineMap)+1); ok {
		t.Error("TranslateLine(len+1) should return ok=false")
	}
}

func TestPreprocess_malformedJSON(t *testing.T) {
	cases := [][]byte{
		[]byte("not a notebook"),
		[]byte("{\"cells\": [unterminated"),
		[]byte("{\"cells\": [{\"cell_type\": \"code\", \"source\": 42}]}"),
	}
	for i, c := range cases {
		_, _, err := Preprocess(c)
		if err == nil {
			t.Errorf("case %d: expected error for input %q", i, c)
		}
	}
}

func TestPreprocess_emptyInput(t *testing.T) {
	synth, lineMap, err := Preprocess(nil)
	if err != nil {
		t.Errorf("empty input should not error, got: %v", err)
	}
	if synth != nil || lineMap != nil {
		t.Errorf("empty input: expected nil/nil, got synth=%q lineMap=%v", synth, lineMap)
	}
}

func TestPreprocess_zeroCodeCells(t *testing.T) {
	nb := `{"cells": [{"cell_type": "markdown", "source": "# heading"}], "nbformat": 4}`
	synth, lineMap, err := Preprocess([]byte(nb))
	if err != nil {
		t.Fatalf("Preprocess: %v", err)
	}
	if synth != nil {
		t.Errorf("expected nil synthesized buffer for markdown-only notebook, got %q", synth)
	}
	if lineMap != nil {
		t.Errorf("expected nil lineMap for markdown-only notebook, got %v", lineMap)
	}
}

func TestPreprocess_singleStringSource(t *testing.T) {
	// Some converters emit "source" as a single string with embedded \n
	// rather than an array. Verify we accept it.
	nb := `{"cells": [{"cell_type": "code", "source": "import hashlib\nhashlib.sha1(b'').digest()\n"}]}`
	synth, lineMap, err := Preprocess([]byte(nb))
	if err != nil {
		t.Fatalf("Preprocess: %v", err)
	}
	if !strings.Contains(string(synth), "hashlib.sha1") {
		t.Errorf("synthesized buffer missing sha1 call: %q", synth)
	}
	if len(lineMap) != 2 {
		t.Errorf("expected 2 line-map entries, got %d", len(lineMap))
	}
	if lineMap[1].CellIndex != 0 || lineMap[1].CellLine != 2 {
		t.Errorf("second entry should be (0,2), got %+v", lineMap[1])
	}
}

func TestPreprocess_realFixture(t *testing.T) {
	// Read the on-disk vulnerable-jupyter fixture and confirm the preprocessor
	// produces a buffer containing every API call the integration test will
	// match against. Guards both the fixture JSON shape and the preprocessor
	// at once.
	const fixtureRel = "../../../fixtures/vulnerable-jupyter/notebook.ipynb"
	raw, err := os.ReadFile(fixtureRel)
	if err != nil {
		t.Skipf("fixture not readable from this CWD (%v); skipping (integration test still covers it)", err)
	}
	synth, lineMap, err := Preprocess(raw)
	if err != nil {
		t.Fatalf("Preprocess(fixture): %v", err)
	}
	body := string(synth)
	for _, want := range []string{
		"hashlib.md5",
		"hashlib.sha1",
		"rsa.generate_private_key",
		"key_size=1024",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fixture synthesized buffer missing %q\nbuffer:\n%s", want, body)
		}
	}
	if len(lineMap) == 0 {
		t.Error("fixture produced an empty lineMap")
	}
}

func TestPreprocess_nullSource(t *testing.T) {
	// A null source should be skipped, not error.
	nb := `{"cells": [{"cell_type": "code", "source": null}, {"cell_type": "code", "source": "x = 1\n"}]}`
	synth, lineMap, err := Preprocess([]byte(nb))
	if err != nil {
		t.Fatalf("Preprocess: %v", err)
	}
	if strings.TrimSpace(string(synth)) != "x = 1" {
		t.Errorf("expected only the second cell's content, got %q", synth)
	}
	// codeIdx advanced past the null cell, so the surviving line maps to
	// CellIndex 1.
	if len(lineMap) != 1 || lineMap[0].CellIndex != 1 {
		t.Errorf("expected single entry at CellIndex=1, got %+v", lineMap)
	}
}
