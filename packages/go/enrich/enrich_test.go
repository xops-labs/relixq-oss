// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package enrich

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relix-q/relix-q/finding"
)

const dsaEnrichment = `- rule_id: CSHARP_DSA_CREATE
  layer: enrichment
  recommendation: "Migrate to ML-DSA (FIPS 204)."
  migration_target: "ML-DSA (FIPS 204)"
  vertical_context: "Code-signing and TLS mutual-auth."
  references:
    - "https://csrc.nist.gov/pubs/fips/204/final"
  cwe: [327]
`

func writePack(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sub := filepath.Join(dir, "csharp")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "dsa.yaml"), []byte(dsaEnrichment), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadDir_IndexesByRuleID(t *testing.T) {
	idx, err := LoadDir(writePack(t))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	e, ok := idx["CSHARP_DSA_CREATE"]
	if !ok {
		t.Fatal("expected CSHARP_DSA_CREATE in index")
	}
	if e.MigrationTarget != "ML-DSA (FIPS 204)" {
		t.Errorf("migration_target = %q", e.MigrationTarget)
	}
	if len(e.References) != 1 || e.CWE[0] != 327 {
		t.Errorf("references/cwe not parsed: %+v", e)
	}
}

func TestLoadDir_MissingDirIsNoError(t *testing.T) {
	idx, err := LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing rule-pack dir should not error: %v", err)
	}
	if len(idx) != 0 {
		t.Fatalf("expected empty index, got %d", len(idx))
	}
	idx, err = LoadDir("")
	if err != nil || len(idx) != 0 {
		t.Fatalf("empty path: idx=%d err=%v", len(idx), err)
	}
}

func TestApply_OverlaysDetectionFinding(t *testing.T) {
	idx, _ := LoadDir(writePack(t))
	findings := []finding.Finding{
		{RuleID: "CSHARP_DSA_CREATE", Algorithm: "DSA", QuantumSafety: finding.QuantumVulnerable, Severity: finding.SeverityHigh, Message: "DSA detected."},
		{RuleID: "CSHARP_SHA1", Message: "unrelated"},
	}
	n := Apply(findings, idx)
	if n != 1 {
		t.Fatalf("expected 1 finding enriched, got %d", n)
	}
	got := findings[0]
	if got.Recommendation == "" || got.MigrationTarget != "ML-DSA (FIPS 204)" || got.VerticalContext == "" {
		t.Errorf("detection finding not fully enriched: %+v", got)
	}
	if len(got.References) != 1 || len(got.CWE) != 1 {
		t.Errorf("references/cwe not overlaid: %+v", got)
	}
	// Detection-level fields are never altered by enrichment.
	if got.Algorithm != "DSA" || got.QuantumSafety != finding.QuantumVulnerable || got.Severity != finding.SeverityHigh {
		t.Errorf("enrichment must not alter detection fields: %+v", got)
	}
	// Unrelated finding is untouched.
	if findings[1].Recommendation != "" {
		t.Errorf("non-matching finding was enriched: %+v", findings[1])
	}
}

func TestApply_DoesNotOverwriteExisting(t *testing.T) {
	idx, _ := LoadDir(writePack(t))
	findings := []finding.Finding{
		{RuleID: "CSHARP_DSA_CREATE", Recommendation: "pre-existing advice"},
	}
	n := Apply(findings, idx)
	if findings[0].Recommendation != "pre-existing advice" {
		t.Errorf("Apply overwrote an existing recommendation: %q", findings[0].Recommendation)
	}
	// migration_target/vertical_context were still empty, so they get filled;
	// the finding still counts as enriched.
	if n != 1 || findings[0].MigrationTarget == "" {
		t.Errorf("expected additive enrichment of empty fields, n=%d got=%+v", n, findings[0])
	}
}

func TestApply_EmptyIndexNoOp(t *testing.T) {
	findings := []finding.Finding{{RuleID: "CSHARP_DSA_CREATE"}}
	if n := Apply(findings, Index{}); n != 0 {
		t.Fatalf("empty index should enrich nothing, got %d", n)
	}
}
