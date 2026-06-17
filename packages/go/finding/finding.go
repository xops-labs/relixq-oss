// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package finding owns the on-disk Finding schema (the
// canonical CryptoFinding contract). Scanners produce one *Finding per match
// and the JSONL writer streams them to disk before upload.
package finding

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

// Severity values mirror the rule pack severity field.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// QuantumSafety classifies an algorithm's resistance to a CRQC.
//
// Risk-tagged values (two-tier quantum taxonomy plus the classical floor):
//
//   - QuantumVulnerable — Shor-broken asymmetric crypto (RSA, ECDSA/ECDH/ECC,
//     EdDSA, DH, DSA, classical TLS key exchange, certificates). Falls
//     completely to a CRQC.
//   - GroverWeakened — symmetric/hash strength halved by Grover's algorithm
//     (AES-128, 3DES, other ≤128-bit-security symmetric primitives, and
//     256-bit hashes flagged for quantum inventory).
//   - ClassicallyBroken — broken TODAY without any quantum computer
//     (MD5, SHA-1, RC4, single DES, RC2, MD4, RIPEMD family).
//
// Non-risk values: hybrid (classical+PQC), quantum_safe, unknown.
type QuantumSafety string

const (
	QuantumVulnerable QuantumSafety = "vulnerable"
	GroverWeakened    QuantumSafety = "grover_weakened"
	ClassicallyBroken QuantumSafety = "classically_broken"
	QuantumHybrid     QuantumSafety = "hybrid"
	QuantumSafe       QuantumSafety = "quantum_safe"
	QuantumUnknown    QuantumSafety = "unknown"
)

// Finding is the canonical record emitted to JSONL.
type Finding struct {
	FindingID      string        `json:"finding_id"`
	ScanJobID      string        `json:"scan_job_id"`
	RuleID         string        `json:"rule_id"`
	Language       string        `json:"language"`
	Algorithm      string        `json:"algorithm,omitempty"`
	UsageType      string        `json:"usage_type,omitempty"`
	QuantumSafety  QuantumSafety `json:"quantum_safety"`
	Severity       Severity      `json:"severity"`
	KeySize        *int          `json:"key_size,omitempty"`
	FilePath       string        `json:"file_path"`
	LineNumber     int           `json:"line_number"`
	Column         int           `json:"column"`
	Snippet        string        `json:"snippet"`
	SnippetContext []string      `json:"snippet_context,omitempty"`
	Confidence     float64       `json:"confidence"`
	Category       string        `json:"category,omitempty"`
	Message        string        `json:"message,omitempty"`
	// Recommendation, MigrationTarget, VerticalContext and References are the
	// enrichment surface. A bare OSS detection finding leaves them empty;
	// when an optional rule-pack overlay is present the enrich overlay fills
	// them in, keyed by RuleID (see package enrich).
	Recommendation  string    `json:"recommendation,omitempty"`
	MigrationTarget string    `json:"migration_target,omitempty"`
	VerticalContext string    `json:"vertical_context,omitempty"`
	References      []string  `json:"references,omitempty"`
	CWE             []int     `json:"cwe,omitempty"`
	GitBlameAuthor  string    `json:"git_blame_author,omitempty"`
	GitBlameCommit  string    `json:"git_blame_commit,omitempty"`
	DetectedAt      time.Time `json:"detected_at"`
	DeltaState      string    `json:"delta_state,omitempty"` // new | modified | removed (PR diff mode only)
}

// NewID returns a fresh finding id.
func NewID() string { return uuid.NewString() }

// JSONLWriter streams Findings to a file as newline-delimited JSON. It is
// not safe for concurrent use; callers must serialize writes themselves.
type JSONLWriter struct {
	f   *os.File
	w   *bufio.Writer
	enc *json.Encoder
	n   int
}

// NewJSONLWriter creates the parent directory if needed and opens path for write.
func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, fmt.Errorf("create findings dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("open findings file: %w", err)
	}
	w := bufio.NewWriterSize(f, 64*1024)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONLWriter{f: f, w: w, enc: enc}, nil
}

// Write emits one Finding as a JSON line.
func (j *JSONLWriter) Write(f *Finding) error {
	if f.FindingID == "" {
		f.FindingID = NewID()
	}
	if f.DetectedAt.IsZero() {
		f.DetectedAt = time.Now().UTC()
	}
	if err := j.enc.Encode(f); err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	j.n++
	return nil
}

// Count returns the number of findings written so far.
func (j *JSONLWriter) Count() int { return j.n }

// Close flushes and closes the underlying file. Safe to call multiple times.
func (j *JSONLWriter) Close() error {
	if j.f == nil {
		return nil
	}
	flushErr := j.w.Flush()
	closeErr := j.f.Close()
	j.f = nil
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

// ReadAll is a test/CLI helper: consume a JSONL file into a slice. Not used in the hot path.
func ReadAll(r io.Reader) ([]Finding, error) {
	dec := json.NewDecoder(r)
	var out []Finding
	for {
		var f Finding
		if err := dec.Decode(&f); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
		out = append(out, f)
	}
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
