// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

func TestWriteSARIF_ValidSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(sampleFindings(), &buf); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	// SARIF root must have version + $schema + at least one run.
	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name           string `json:"name"`
					InformationUri string `json:"informationUri"`
					Rules          []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							Uri string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}

	if doc.Version != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != toolName {
		t.Fatalf("tool name = %q, want %q", run.Tool.Driver.Name, toolName)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("critical → error in SARIF; got %q", run.Results[0].Level)
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Fatalf("startLine should be 42, got %d", run.Results[0].Locations[0].PhysicalLocation.Region.StartLine)
	}
}

func TestWriteSARIF_RoundTripViaReadSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(sampleFindings(), &buf); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "out.sarif")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSARIF(path)
	if err != nil {
		t.Fatalf("ReadSARIF: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings round-tripped, got %d", len(got))
	}
	if got[0].RuleID != "GO_RSA_GENERATE_KEY" {
		t.Fatalf("first finding rule id = %q", got[0].RuleID)
	}
	// SARIF doesn't carry our enum severity; verify the level mapping survives.
	if got[0].Severity != "high" { // critical → error → mapped back as "high"
		t.Fatalf("severity mapping: got %q, want high", got[0].Severity)
	}
}

func TestWriteSARIF_EnrichmentAndProperties(t *testing.T) {
	enriched := []model.Finding{{
		RuleID:          "CSHARP_DSA_CREATE",
		Algorithm:       "DSA",
		QuantumSafety:   "vulnerable",
		FilePath:        "Services/DigitalSignatureService.cs",
		LineNumber:      15,
		Severity:        "high",
		Snippet:         "DSA.Create(2048)",
		Message:         "DSA is quantum-vulnerable.",
		Recommendation:  "Migrate to ML-DSA (FIPS 204).",
		MigrationTarget: "ML-DSA (FIPS 204)",
		VerticalContext: "Code-signing pipelines.",
		References:      []string{"https://csrc.nist.gov/pubs/fips/204/final"},
		CWE:             []int{327},
	}}

	var buf bytes.Buffer
	if err := WriteSARIF(enriched, &buf); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID   string `json:"id"`
						Help struct {
							Markdown string `json:"markdown"`
						} `json:"help"`
						Properties struct {
							SecuritySeverity string   `json:"security-severity"`
							Tags             []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if rule.Properties.SecuritySeverity != "8.1" {
		t.Errorf("security-severity for high = %q, want 8.1", rule.Properties.SecuritySeverity)
	}
	if !containsStr(rule.Properties.Tags, "pqc") || !containsStr(rule.Properties.Tags, "external/cwe/cwe-327") {
		t.Errorf("tags missing pqc/cwe: %v", rule.Properties.Tags)
	}
	if !strings.Contains(rule.Help.Markdown, "ML-DSA (FIPS 204)") {
		t.Errorf("enrichment migration target not in help.markdown:\n%s", rule.Help.Markdown)
	}
	if !strings.Contains(rule.Help.Markdown, "fips/204") {
		t.Errorf("enrichment reference not in help.markdown:\n%s", rule.Help.Markdown)
	}

	fp := doc.Runs[0].Results[0].PartialFingerprints["relixq/v1"]
	if len(fp) != 64 { // sha256 hex
		t.Errorf("partial fingerprint relixq/v1 = %q (len %d), want 64-char hex", fp, len(fp))
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestSeverityToSARIFLevel(t *testing.T) {
	cases := map[string]string{
		"critical": "error",
		"high":     "error",
		"medium":   "warning",
		"low":      "note",
		"info":     "note",
		"":         "note",
		"CRITICAL": "error", // case-insensitive
	}
	for sev, want := range cases {
		if got := severityToSARIFLevel(sev); got != want {
			t.Errorf("severity %q -> %q, want %q", sev, got, want)
		}
	}
}
