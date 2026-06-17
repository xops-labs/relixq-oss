// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package fusion

import (
	"math"
	"testing"

	"github.com/relix-q/relix-q/finding"
)

func mkF(rule, algo string, sev finding.Severity, conf float64) finding.Finding {
	return finding.Finding{
		RuleID:     rule,
		Algorithm:  algo,
		Severity:   sev,
		Confidence: conf,
	}
}

// TestFuse_singleChannelPassthrough asserts single-channel findings
// flow through with their original confidence and a 1-corroboration
// count. Fusion must be a no-op when only one channel reports.
func TestFuse_singleChannelPassthrough(t *testing.T) {
	clusters := Fuse(
		Channel{Name: "ast", Findings: []finding.Finding{
			mkF("PYTHON_RSA_GEN", "RSA-2048", finding.SeverityHigh, 0.85),
		}},
	)
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	c := clusters[0]
	if c.AlgorithmClass != "RSA" {
		t.Errorf("want class=RSA after suffix stripping, got %q", c.AlgorithmClass)
	}
	if c.CorroborationCount != 1 {
		t.Errorf("want corroboration=1, got %d", c.CorroborationCount)
	}
	if math.Abs(c.FusedConfidence-0.85) > 1e-9 {
		t.Errorf("want fused=0.85 (passthrough), got %v", c.FusedConfidence)
	}
}

// TestFuse_twoChannelCorroboration is the core IP demonstration: AST
// + SBOM both report RSA-related risk; fusion should produce ONE cluster
// with elevated confidence.
func TestFuse_twoChannelCorroboration(t *testing.T) {
	clusters := Fuse(
		Channel{Name: "ast", Findings: []finding.Finding{
			mkF("PYTHON_RSA_GEN", "RSA-2048", finding.SeverityHigh, 0.85),
		}},
		Channel{Name: "sbom", Findings: []finding.Finding{
			mkF("SBOM_PYTHON_CRYPTOGRAPHY_RSA", "RSA", finding.SeverityInfo, 0.7),
		}},
	)
	if len(clusters) != 1 {
		t.Fatalf("want 1 fused cluster, got %d", len(clusters))
	}
	c := clusters[0]
	if c.AlgorithmClass != "RSA" {
		t.Errorf("want class=RSA, got %q", c.AlgorithmClass)
	}
	if c.CorroborationCount != 2 {
		t.Errorf("want corroboration=2, got %d (channels=%v)", c.CorroborationCount, c.Channels)
	}
	// Expected: 1 - (1-0.85)*(1-0.7) = 1 - 0.15*0.3 = 1 - 0.045 = 0.955
	expect := 1.0 - 0.15*0.30
	if math.Abs(c.FusedConfidence-expect) > 1e-9 {
		t.Errorf("want fused=%v, got %v", expect, c.FusedConfidence)
	}
	// Severity should be promoted to the max (High > Info).
	if c.Severity != finding.SeverityHigh {
		t.Errorf("want severity=high (max), got %q", c.Severity)
	}
}

// TestFuse_threeChannelCorroboration exercises the multi-channel case
// to confirm the formula scales correctly. Confidence is capped at 0.99.
func TestFuse_threeChannelCorroboration(t *testing.T) {
	clusters := Fuse(
		Channel{Name: "ast", Findings: []finding.Finding{
			mkF("R1", "ECDSA", finding.SeverityMedium, 0.85),
		}},
		Channel{Name: "sbom", Findings: []finding.Finding{
			mkF("R2", "ECDSA", finding.SeverityMedium, 0.7),
		}},
		Channel{Name: "tls", Findings: []finding.Finding{
			mkF("R3", "ECDSA-P256", finding.SeverityHigh, 0.95),
		}},
	)
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	c := clusters[0]
	if c.CorroborationCount != 3 {
		t.Errorf("want corroboration=3, got %d", c.CorroborationCount)
	}
	expect := 1.0 - (1-0.85)*(1-0.7)*(1-0.95)
	if expect > 0.99 {
		expect = 0.99
	}
	if math.Abs(c.FusedConfidence-expect) > 1e-9 {
		t.Errorf("want fused=%v, got %v", expect, c.FusedConfidence)
	}
}

// TestFuse_disjointAlgosNotCorroborated asserts that AST reporting RSA
// and SBOM reporting AES produce TWO clusters, not one. Co-occurrence
// in the same channel set does not imply corroboration.
func TestFuse_disjointAlgosNotCorroborated(t *testing.T) {
	clusters := Fuse(
		Channel{Name: "ast", Findings: []finding.Finding{
			mkF("R1", "RSA", finding.SeverityHigh, 0.85),
		}},
		Channel{Name: "sbom", Findings: []finding.Finding{
			mkF("R2", "AES", finding.SeverityInfo, 0.5),
		}},
	)
	if len(clusters) != 2 {
		t.Fatalf("want 2 separate clusters, got %d", len(clusters))
	}
	classes := map[string]bool{}
	for _, c := range clusters {
		classes[c.AlgorithmClass] = true
		if c.CorroborationCount != 1 {
			t.Errorf("disjoint classes should each have 1 corroboration, %s got %d", c.AlgorithmClass, c.CorroborationCount)
		}
	}
	if !classes["RSA"] || !classes["AES"] {
		t.Errorf("expected RSA and AES clusters, got %v", classes)
	}
}

// TestClassKey_suffixStripping checks that key-size / curve / padding
// / digest suffixes don't fragment the cluster. Every variant of
// RSA / ECDSA risk collapses to the bare primitive class.
func TestClassKey_suffixStripping(t *testing.T) {
	cases := map[string]string{
		"RSA-1024":     "RSA",
		"RSA-2048":     "RSA",
		"RSA_3072":     "RSA",
		"ECDSA-P256":   "ECDSA", // curve suffix stripped
		"ECDSA-P384":   "ECDSA",
		"ECDSA-K1":     "ECDSA", // short form for secp256k1
		"RSA-OAEP":     "RSA",   // padding suffix stripped
		"RSA-PKCS1V15": "RSA",
		"RSA-MD5":      "RSA",   // signature with hash digest — joins the key cluster
		"RSA":          "RSA",
		"rsa":          "RSA",   // case fold
	}
	for in, want := range cases {
		got := classKey(in)
		if got != want {
			t.Errorf("classKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestClassKey_aliasCollapse checks that variant spellings of the same
// primitive (3DES vs TripleDES vs DES_EDE3) join to one class.
func TestClassKey_aliasCollapse(t *testing.T) {
	all := []string{"3DES", "TRIPLEDES", "DES_EDE3"}
	for _, a := range all {
		if got := classKey(a); got != "DES" {
			t.Errorf("classKey(%q) = %q, want DES", a, got)
		}
	}
	// SHA family
	if classKey("SHA-1") != "SHA1" || classKey("SHA1") != "SHA1" {
		t.Errorf("SHA-1 / SHA1 should both → SHA1")
	}
	if classKey("SHA-256") != "SHA256" || classKey("SHA256") != "SHA256" {
		t.Errorf("SHA-256 / SHA256 should both → SHA256")
	}
}

// TestClassKey_genericTagsFiltered confirms catch-all tags don't
// produce cluster entries.
func TestClassKey_genericTagsFiltered(t *testing.T) {
	for _, generic := range []string{"TLS", "CIPHER", "HASH", "HMAC", "ANY", "UNKNOWN", ""} {
		if got := classKey(generic); got != "" {
			t.Errorf("classKey(%q) should filter to empty, got %q", generic, got)
		}
	}
}

// TestBayesianFuse_edges covers the formula's boundary behaviour.
func TestBayesianFuse_edges(t *testing.T) {
	cases := []struct {
		probs []float64
		want  float64
	}{
		{nil, 0},
		{[]float64{0.85}, 0.85},
		{[]float64{0.5, 0.5}, 0.75},
		{[]float64{0.99, 0.99, 0.99}, 0.99}, // capped
		{[]float64{0.0, 0.0}, 0.75},         // 0 → 0.5 fallback, then fused 0.75
		{[]float64{1.0, 1.0}, 0.99},         // 1 capped to 0.99
	}
	for _, c := range cases {
		got := bayesianFuse(c.probs)
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("bayesianFuse(%v) = %v, want %v", c.probs, got, c.want)
		}
	}
}

// TestFuse_determinism asserts repeated invocations with the same
// input produce identical outputs. Critical for downstream consumers
// that compare scorecards across runs.
func TestFuse_determinism(t *testing.T) {
	mk := func() []Cluster {
		return Fuse(
			Channel{Name: "ast", Findings: []finding.Finding{
				mkF("R1", "RSA-2048", finding.SeverityHigh, 0.85),
				mkF("R2", "ECDSA", finding.SeverityMedium, 0.85),
			}},
			Channel{Name: "sbom", Findings: []finding.Finding{
				mkF("R3", "RSA", finding.SeverityInfo, 0.7),
				mkF("R4", "AES", finding.SeverityInfo, 0.5),
			}},
		)
	}
	first := mk()
	for i := 0; i < 5; i++ {
		next := mk()
		if len(first) != len(next) {
			t.Fatalf("non-deterministic length: %d vs %d", len(first), len(next))
		}
		for j := range first {
			if first[j].AlgorithmClass != next[j].AlgorithmClass {
				t.Errorf("idx %d: class %q vs %q", j, first[j].AlgorithmClass, next[j].AlgorithmClass)
			}
			if first[j].FusedConfidence != next[j].FusedConfidence {
				t.Errorf("idx %d: fused %v vs %v", j, first[j].FusedConfidence, next[j].FusedConfidence)
			}
		}
	}
}

// TestSeverityRank tests the severity comparison used for the max-
// severity promotion across corroborating findings.
func TestSeverityRank(t *testing.T) {
	cases := []struct {
		s    finding.Severity
		want int
	}{
		{finding.SeverityCritical, 5},
		{finding.SeverityHigh, 4},
		{finding.SeverityMedium, 3},
		{finding.SeverityLow, 2},
		{finding.SeverityInfo, 1},
		{"", 0},
	}
	for _, c := range cases {
		if got := severityRank(c.s); got != c.want {
			t.Errorf("severityRank(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

// TestFuse_emptyInputProducesEmptyOutput is the simplest invariant.
func TestFuse_emptyInputProducesEmptyOutput(t *testing.T) {
	out := Fuse()
	if len(out) != 0 {
		t.Errorf("expected empty output, got %d clusters", len(out))
	}
}
