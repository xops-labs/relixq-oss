// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package notebook is a preprocessor — NOT a detector — that lifts the code
// cells out of a Jupyter (.ipynb) document and concatenates them into a
// single Python-source-shaped buffer suitable for feeding into the existing
// pyast runner.
//
// Jupyter coverage reuses the entire
// Python rule pack — there is no new "jupyter" detector, no new rules, no new
// AST grammar. The only novel piece is mapping line numbers in the
// synthesized buffer back to the (cell, line-within-cell) coordinates the
// reviewer sees in the .ipynb document. That translation lives here.
//
// The .ipynb format (https://nbformat.readthedocs.io) ships a JSON document
// whose top-level "cells" array contains objects with a "cell_type"
// ("code" | "markdown" | "raw") and a "source" field. The source field is
// EITHER an array of strings (one entry per line, with newlines INCLUDED in
// the strings except possibly the last) OR a single string. Both shapes are
// normalized here.
//
// Cells are concatenated with a single blank-line separator (`\n\n`) so that
// the synthesized buffer is syntactically a valid Python file (notebooks
// effectively run each cell sequentially in one interpreter, so this matches
// runtime semantics for our detection purposes).
package notebook

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SourceLine identifies a single synthesized line's origin inside the .ipynb
// document. CellIndex is the zero-based index of the code cell (NOT the raw
// "cells" index — skipped markdown/raw cells don't advance it). CellLine is
// 1-based within that cell's source.
type SourceLine struct {
	CellIndex int
	CellLine  int
}

// rawNotebook is the minimum JSON shape we care about. nbformat ships many
// more fields; the unknown ones decode silently into the empty struct fields
// we ignore.
type rawNotebook struct {
	Cells []rawCell `json:"cells"`
}

// rawCell.Source is decoded as json.RawMessage so we can support both the
// array-of-strings and single-string variants the nbformat spec allows.
type rawCell struct {
	CellType string          `json:"cell_type"`
	Source   json.RawMessage `json:"source"`
}

// Preprocess parses .ipynb JSON, extracts every code cell's source, and
// returns:
//
//   - synthesized: a Python-source-shaped byte slice containing the
//     concatenated contents of every code cell, separated by a single blank
//     line between adjacent cells.
//   - lineMap:     a slice indexed by (synthesized-line - 1) whose entry
//     gives the originating (CellIndex, CellLine) for that line. Separator
//     lines between cells carry the trailing cell's coordinates so a finding
//     that lands on a separator (extremely unlikely — rules never point at
//     blank lines) at least resolves to a real cell.
//
// Errors only surface for malformed JSON. Empty / nil source cells, markdown
// cells, and raw cells are silently skipped. A notebook with zero code cells
// is not an error; the caller will receive an empty buffer and an empty
// lineMap.
func Preprocess(src []byte) ([]byte, []SourceLine, error) {
	if len(src) == 0 {
		return nil, nil, nil
	}

	var nb rawNotebook
	if err := json.Unmarshal(src, &nb); err != nil {
		return nil, nil, fmt.Errorf("notebook: parse .ipynb JSON: %w", err)
	}

	var buf strings.Builder
	var lineMap []SourceLine

	codeIdx := 0
	for _, c := range nb.Cells {
		if c.CellType != "code" {
			continue
		}
		cellSrc, err := normalizeSource(c.Source)
		if err != nil {
			// Per-cell decode error means the notebook is malformed; bubble up.
			return nil, nil, fmt.Errorf("notebook: cell %d: %w", codeIdx, err)
		}
		if cellSrc == "" {
			codeIdx++
			continue
		}

		// Split on '\n' so we can build the line map deterministically.
		// strings.Split keeps a trailing empty element when the source ends
		// with '\n'; drop it so we don't emit a phantom CellLine.
		lines := strings.Split(cellSrc, "\n")
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
		if len(lines) == 0 {
			codeIdx++
			continue
		}

		// If buf already has content, insert a blank-line separator so the
		// synthesized file parses as Python (each cell becomes its own
		// logical block). The blank separator line itself gets a lineMap
		// entry pointing at the START of the upcoming cell — line 1.
		if buf.Len() > 0 {
			buf.WriteByte('\n')
			lineMap = append(lineMap, SourceLine{CellIndex: codeIdx, CellLine: 1})
		}

		for i, ln := range lines {
			buf.WriteString(ln)
			buf.WriteByte('\n')
			lineMap = append(lineMap, SourceLine{CellIndex: codeIdx, CellLine: i + 1})
		}
		codeIdx++
	}

	if buf.Len() == 0 {
		return nil, nil, nil
	}
	return []byte(buf.String()), lineMap, nil
}

// normalizeSource handles the two JSON shapes nbformat permits for a cell's
// "source" field:
//
//  1. Array of strings — one entry per logical source line, with newline
//     characters INCLUDED in each string except possibly the last. This is
//     the canonical form Jupyter writes.
//  2. Single string — the entire cell's source as one blob. Some converters
//     and hand-authored notebooks ship this shape.
//
// Both shapes are normalized to a single string with '\n' line terminators.
// A nil/null source returns "" cleanly.
func normalizeSource(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	// Cheap shape probe: skip leading whitespace, look at the first non-WS byte.
	first := byte(0)
	for _, b := range raw {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		first = b
		break
	}
	switch first {
	case 0:
		return "", nil
	case 'n': // null
		return "", nil
	case '[':
		var parts []string
		if err := json.Unmarshal(raw, &parts); err != nil {
			return "", fmt.Errorf("source array: %w", err)
		}
		return strings.Join(parts, ""), nil
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("source string: %w", err)
		}
		return s, nil
	default:
		return "", fmt.Errorf("source: unexpected JSON kind starting with %q", string(first))
	}
}

// TranslateLine reverse-maps a 1-based synthesized line number to its
// originating (CellIndex, CellLine). Returns ok=false if synthesizedLine is
// out of range. CellIndex is 0-based; CellLine is 1-based.
func TranslateLine(lineMap []SourceLine, synthesizedLine int) (int, int, bool) {
	if synthesizedLine < 1 || synthesizedLine > len(lineMap) {
		return 0, 0, false
	}
	sl := lineMap[synthesizedLine-1]
	return sl.CellIndex, sl.CellLine, true
}
