// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
)

func TestScanner_endToEndOnFixtureLikeDir(t *testing.T) {
	dir := t.TempDir()
	src := `using System.Security.Cryptography;
namespace X {
    public class A {
        public RSA NewKey() { return RSA.Create(2048); }
        public byte[] H(byte[] d) { using var s = SHA1.Create(); return s.ComputeHash(d); }
    }
}`
	if err := os.WriteFile(filepath.Join(dir, "A.cs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := rules.LoadBytes([]byte(`
- id: CSHARP_RSA_CREATE
  language: csharp
  severity: critical
  algorithm: RSA
  detector: { type: regex, pattern: '\bRSA\.Create\s*\(' }
- id: CSHARP_SHA1
  language: csharp
  severity: high
  algorithm: SHA1
  detector: { type: regex, pattern: '\bSHA1\.Create\b' }
`))
	if err != nil {
		t.Fatal(err)
	}
	pack := rules.NewPackForTest(loaded)

	out := filepath.Join(dir, "findings.jsonl")
	scn := New(Job{ScanJobID: "job-1", ScanRunID: "run-1", OrganizationID: "org-1"}, nil)
	res, err := scn.Scan(context.Background(), ScanRequest{
		RepoPath: dir,
		Pack:     pack,
		Output:   out,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.FindingsCount != 2 {
		t.Errorf("expected 2 findings, got %d", res.FindingsCount)
	}
	if res.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", res.FilesScanned)
	}

	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	all, err := finding.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 lines in jsonl, got %d", len(all))
	}
	var ruleIDs []string
	for _, fnd := range all {
		ruleIDs = append(ruleIDs, fnd.RuleID)
		if fnd.ScanJobID != "job-1" {
			t.Errorf("scan_job_id not propagated: %q", fnd.ScanJobID)
		}
		if fnd.FilePath != "A.cs" {
			t.Errorf("expected relative path A.cs, got %q", fnd.FilePath)
		}
	}
	if !strings.Contains(strings.Join(ruleIDs, ","), "CSHARP_RSA_CREATE") {
		t.Errorf("missing CSHARP_RSA_CREATE rule id: %v", ruleIDs)
	}
}

func TestScanner_includeOnlyRestrictsFiles(t *testing.T) {
	dir := t.TempDir()
	src := "RSA.Create();"
	if err := os.WriteFile(filepath.Join(dir, "scan_me.cs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skip_me.cs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, _ := rules.LoadBytes([]byte(`
- id: R
  language: csharp
  severity: high
  detector: { type: regex, pattern: 'RSA\.Create' }
`))
	pack := rules.NewPackForTest(loaded)

	scn := New(Job{ScanJobID: "j"}, nil)
	out := filepath.Join(dir, "out.jsonl")
	res, err := scn.Scan(context.Background(), ScanRequest{
		RepoPath:    dir,
		Pack:        pack,
		Output:      out,
		IncludeOnly: map[string]struct{}{"scan_me.cs": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", res.FilesScanned)
	}
}
