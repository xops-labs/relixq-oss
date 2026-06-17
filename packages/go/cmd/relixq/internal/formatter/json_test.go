// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

func TestWriteJSON_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(sampleFindings(), &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got []model.Finding
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	if got[0].RuleID != "GO_RSA_GENERATE_KEY" || got[0].Severity != "critical" {
		t.Fatalf("first finding wrong shape: %+v", got[0])
	}
	if got[1].RuleID != "GO_SHA1_NEW" || got[1].Algorithm != "SHA1" {
		t.Fatalf("second finding wrong shape: %+v", got[1])
	}
}

func TestWriteJSON_IndentsForReadability(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(sampleFindings(), &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// Indented JSON contains newlines + leading whitespace on property lines.
	// SetIndent("", "  ") puts "rule_id" at column 4 inside an array of objects.
	out := buf.String()
	if !strings.Contains(out, "\n    \"rule_id\"") {
		t.Fatalf("expected indented JSON; got:\n%s", out)
	}
}

func TestWriteJSONL_OneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSONL(sampleFindings(), &buf); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var f model.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line %d not valid JSON: %v (%q)", i, err, line)
		}
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(nil, &buf); err != nil {
		t.Fatalf("WriteJSON nil: %v", err)
	}
	// "null\n" or "[]\n" — both valid encodings of an empty findings list.
	out := strings.TrimSpace(buf.String())
	if out != "null" && out != "[]" {
		t.Fatalf("expected empty-list JSON, got %q", out)
	}
}
