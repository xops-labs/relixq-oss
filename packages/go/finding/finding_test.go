// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package finding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONLWriter_writesLinePerFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	w, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	fs := []*Finding{
		{ScanJobID: "j", RuleID: "R1", FilePath: "a.cs", LineNumber: 1, Severity: SeverityHigh},
		{ScanJobID: "j", RuleID: "R2", FilePath: "b.cs", LineNumber: 2, Severity: SeverityCritical},
	}
	for _, f := range fs {
		if err := w.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	if w.Count() != 2 {
		t.Errorf("Count = %d", w.Count())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "{") {
			t.Errorf("not a JSON object: %q", line)
		}
	}
}

func TestJSONLWriter_assignsIDAndTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.jsonl")
	w, _ := NewJSONLWriter(path)
	defer w.Close()
	f := &Finding{ScanJobID: "j", RuleID: "R", FilePath: "a", LineNumber: 1, Severity: SeverityLow}
	if err := w.Write(f); err != nil {
		t.Fatal(err)
	}
	if f.FindingID == "" {
		t.Error("FindingID not set")
	}
	if f.DetectedAt.IsZero() {
		t.Error("DetectedAt not set")
	}
}
