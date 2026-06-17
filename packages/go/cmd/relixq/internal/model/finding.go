// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Finding is the canonical cross-service CryptoFinding shape (mirrors HLD §7 /
// RiskScoring.Domain.CryptoFinding). The CLI receives these from the scanner
// subprocess as newline-delimited JSON.
type Finding struct {
	FindingID     string  `json:"finding_id,omitempty"`
	RuleID        string  `json:"rule_id"`
	Algorithm     string  `json:"algorithm"`
	UsageType     string  `json:"usage_type,omitempty"`
	QuantumSafety string  `json:"quantum_safety"` // vulnerable|grover_weakened|classically_broken|hybrid|quantum_safe|unknown
	KeySize       *int    `json:"key_size,omitempty"`
	FilePath      string  `json:"file_path"`
	LineNumber    int     `json:"line_number"`
	Column        *int    `json:"column,omitempty"`
	Snippet       string  `json:"snippet,omitempty"`
	Fingerprint   string  `json:"fingerprint,omitempty"`
	Severity      string  `json:"severity"` // info|low|medium|high|critical
	Confidence    float64 `json:"confidence"`
	Message       string  `json:"message,omitempty"`
	// Recommendation, MigrationTarget, VerticalContext and References are the
	// enrichment surface — empty on a bare OSS detection finding, populated
	// when the scanner ran with a rule-pack overlay (see packages/go/enrich).
	Recommendation  string   `json:"recommendation,omitempty"`
	MigrationTarget string   `json:"migration_target,omitempty"`
	VerticalContext string   `json:"vertical_context,omitempty"`
	References      []string `json:"references,omitempty"`
	CWE             []int    `json:"cwe,omitempty"`
}

// ComputeFingerprint derives a stable, content-based identity for a finding,
// used for baseline matching and SARIF partialFingerprints. It is resilient to
// line-number drift: it keys on rule + file + the trimmed match snippet, and
// only falls back to the line number when no snippet is present. (The optional
// Fingerprint field above is reserved for a scanner-supplied value; the CLI
// computes its own when that is absent.)
func (f Finding) ComputeFingerprint() string {
	h := sha256.New()
	writeField(h, f.RuleID)
	writeField(h, f.FilePath)
	if snip := strings.TrimSpace(f.Snippet); snip != "" {
		writeField(h, snip)
	} else {
		writeField(h, fmt.Sprintf("L%d", f.LineNumber))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h io.Writer, s string) {
	io.WriteString(h, s)
	h.Write([]byte{0})
}

// SeverityOrder maps severity names to numeric rank for threshold comparisons.
var SeverityOrder = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}
