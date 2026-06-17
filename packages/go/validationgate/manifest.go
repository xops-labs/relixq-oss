// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package validationgate is the scanner regression gate over the labeled
// ground-truth corpus at fixtures/validation-corpus. The only non-test code
// here is the expected-findings.yaml manifest schema, its loader, and the
// label-normalization helpers; the gate itself lives in gate_test.go and runs
// with `go test ./validationgate/... -run TestCorpus` from packages/go.
//
// The manifest is the spec and the scanner is the implementation: ground
// truth encodes the TARGET labels (including taxonomy values like
// grover_weakened / classically_broken that rules may not emit yet), and the
// gate stays red until detection catches up. Never edit the manifest to match
// scanner output; edit it only when the ground truth itself was wrong.
package validationgate

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LineTolerance is how far (in lines, either direction) a finding may sit
// from an instance's labeled line and still be credited. Two lines absorbs
// trivial drift (a rule anchored on the import or the opening paren) without
// letting findings wander to a different statement.
const LineTolerance = 2

// riskTagged are the quantum_safety values the gate treats as "this location
// was flagged as a risk". It includes the current model value ("vulnerable")
// plus the two-tier taxonomy values being introduced ("grover_weakened",
// "classically_broken") so the gate keeps working across the migration.
var riskTagged = map[string]struct{}{
	"vulnerable":         {},
	"grover_weakened":    {},
	"classically_broken": {},
}

// IsRiskTagged reports whether a finding's quantum_safety marks it as a risk
// flag (as opposed to hybrid / quantum_safe / unknown informational output).
func IsRiskTagged(quantumSafety string) bool {
	_, ok := riskTagged[strings.ToLower(strings.TrimSpace(quantumSafety))]
	return ok
}

// severityRank orders severities for "at most X" comparisons. Unknown
// severities rank above critical so a malformed value can never slip under
// an allowance threshold.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 5
}

// NormalizeAlgorithm folds an algorithm label to a canonical comparison key:
// uppercase, punctuation stripped (AES-128 == AES128, SHA-1 == SHA1), and the
// triple-DES spelling family (TripleDES / DESede / TDEA) folded to 3DES.
// Single DES deliberately does NOT fold to 3DES — mislabeling DESede as DES
// is one of the bugs this gate exists to catch.
func NormalizeAlgorithm(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	switch n := b.String(); n {
	case "TRIPLEDES", "DESEDE", "TDEA":
		return "3DES"
	default:
		return n
	}
}

// StringList accepts either a YAML scalar or a YAML sequence of scalars, so
// manifest authors can write `algorithm: RSA` and `algorithm: [RSA, ECDH]`
// interchangeably.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var one string
		if err := value.Decode(&one); err != nil {
			return err
		}
		*s = StringList{one}
		return nil
	case yaml.SequenceNode:
		var many []string
		if err := value.Decode(&many); err != nil {
			return err
		}
		*s = StringList(many)
		return nil
	}
	return fmt.Errorf("expected string or list of strings (yaml line %d)", value.Line)
}

// containsFold reports membership with case-insensitive comparison.
func (s StringList) containsFold(v string) bool {
	for _, x := range s {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

// Manifest is the parsed expected-findings.yaml.
type Manifest struct {
	Version        int                 `yaml:"version"`
	Corpus         string              `yaml:"corpus"`
	Instances      []Instance          `yaml:"instances"`
	Forbidden      []ForbiddenLocation `yaml:"forbidden"`
	PolicyExcluded []PolicyExcluded    `yaml:"policy_excluded"`
	Deps           DepsExpectations    `yaml:"deps"`
}

// Instance is one ground-truth crypto instance that must be detected.
type Instance struct {
	ID            string     `yaml:"id"`
	File          string     `yaml:"file"`
	Line          *int       `yaml:"line"` // nil = file-level match
	Algorithm     StringList `yaml:"algorithm"`
	Bucket        string     `yaml:"bucket"` // A | B | L | S (S = informational coverage-sentinel)
	Severity      StringList `yaml:"severity"`
	QuantumSafety StringList `yaml:"quantum_safety"`
	Tier          string     `yaml:"tier"`           // floor | ast
	RuleIDPrefix  string     `yaml:"rule_id_prefix"` // optional finding discriminator
}

// AcceptsAlgorithm reports whether a finding's algorithm label satisfies this
// instance (normalized comparison).
func (i Instance) AcceptsAlgorithm(algorithm string) bool {
	got := NormalizeAlgorithm(algorithm)
	if got == "" {
		return false
	}
	for _, want := range i.Algorithm {
		if NormalizeAlgorithm(want) == got {
			return true
		}
	}
	return false
}

// AcceptsSeverity reports whether a finding's severity is in the accepted set.
func (i Instance) AcceptsSeverity(severity string) bool {
	return i.Severity.containsFold(severity)
}

// AcceptsQuantumSafety reports whether a finding's quantum_safety is in the
// accepted set.
func (i Instance) AcceptsQuantumSafety(qs string) bool {
	return i.QuantumSafety.containsFold(qs)
}

// LineNear reports whether a finding at the given line can credit this
// instance: any line for file-level instances, +/-LineTolerance otherwise.
func (i Instance) LineNear(line int) bool {
	if i.Line == nil {
		return true
	}
	d := line - *i.Line
	if d < 0 {
		d = -d
	}
	return d <= LineTolerance
}

// Location renders "file:line" (or a file-level marker) for reports.
func (i Instance) Location() string {
	if i.Line == nil {
		return i.File + ":(file)"
	}
	return fmt.Sprintf("%s:%d", i.File, *i.Line)
}

// ForbiddenLocation is a bucket-C location where no risk-tagged finding may
// appear, with an optional narrowly-scoped Allowance.
type ForbiddenLocation struct {
	File    string     `yaml:"file"`
	Line    *int       `yaml:"line"` // nil = whole file
	LineEnd *int       `yaml:"line_end"`
	Reason  string     `yaml:"reason"`
	Allow   *Allowance `yaml:"allow"`
}

// Covers reports whether the forbidden location includes the given line.
func (f ForbiddenLocation) Covers(line int) bool {
	if f.Line == nil {
		return true
	}
	from, to := *f.Line, *f.Line
	if f.LineEnd != nil {
		to = *f.LineEnd
	}
	return line >= from && line <= to
}

// Location renders "file:line[-end]" (or a whole-file marker) for reports.
func (f ForbiddenLocation) Location() string {
	switch {
	case f.Line == nil:
		return f.File + ":(whole file)"
	case f.LineEnd != nil:
		return fmt.Sprintf("%s:%d-%d", f.File, *f.Line, *f.LineEnd)
	default:
		return fmt.Sprintf("%s:%d", f.File, *f.Line)
	}
}

// Allowance tolerates findings at a forbidden location when BOTH conditions
// hold: quantum_safety is in QuantumSafety and severity is at most
// MaxSeverity. Tolerated findings are also exempt from the precision check.
type Allowance struct {
	QuantumSafety StringList `yaml:"quantum_safety"`
	MaxSeverity   string     `yaml:"max_severity"`
}

// Tolerates reports whether the allowance covers a finding with the given
// labels. A nil Allowance tolerates nothing.
func (a *Allowance) Tolerates(quantumSafety, severity string) bool {
	if a == nil {
		return false
	}
	if len(a.QuantumSafety) > 0 && !a.QuantumSafety.containsFold(quantumSafety) {
		return false
	}
	if a.MaxSeverity != "" && severityRank(severity) > severityRank(a.MaxSeverity) {
		return false
	}
	return true
}

// PolicyExcluded is a file the walker excludes by design. Not gated in either
// direction: no recall is required and findings there are ignored.
type PolicyExcluded struct {
	File   string `yaml:"file"`
	Reason string `yaml:"reason"`
}

// DepsExpectations is the dependency-scan ground truth.
type DepsExpectations struct {
	Expect      []DepExpectation `yaml:"expect"`
	MustNotFlag []DepMustNotFlag `yaml:"must_not_flag"`
}

// DepExpectation requires >=1 risk-tagged finding per listed algorithm for
// one package declared in one manifest file. Supersets are allowed.
type DepExpectation struct {
	Manifest          string     `yaml:"manifest"`
	Ecosystem         string     `yaml:"ecosystem"`
	Package           string     `yaml:"package"`
	AlgorithmsInclude StringList `yaml:"algorithms_include"`
}

// DepMustNotFlag requires ZERO risk-tagged findings for the package.
// Informational PQ-ready findings (quantum_safety=quantum_safe) are allowed.
type DepMustNotFlag struct {
	Manifest string `yaml:"manifest"`
	Package  string `yaml:"package"`
	Reason   string `yaml:"reason"`
}

// LoadManifest parses and validates expected-findings.yaml.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // typos in the manifest must fail loudly, not silently skip a gate
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", path, err)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if len(m.Instances) == 0 {
		return fmt.Errorf("no instances")
	}
	seen := map[string]struct{}{}
	for _, inst := range m.Instances {
		switch {
		case inst.ID == "":
			return fmt.Errorf("instance with empty id (file %q)", inst.File)
		case inst.File == "":
			return fmt.Errorf("instance %s: empty file", inst.ID)
		case len(inst.Algorithm) == 0:
			return fmt.Errorf("instance %s: no accepted algorithms", inst.ID)
		case len(inst.Severity) == 0:
			return fmt.Errorf("instance %s: no accepted severities", inst.ID)
		case len(inst.QuantumSafety) == 0:
			return fmt.Errorf("instance %s: no accepted quantum_safety values", inst.ID)
		}
		if inst.Tier != "floor" && inst.Tier != "ast" {
			return fmt.Errorf("instance %s: tier must be floor|ast, got %q", inst.ID, inst.Tier)
		}
		// Bucket S is the informational coverage-sentinel bucket: instances
		// whose quantum_safety is "unknown" by design (CRYPTO_API_UNMAPPED).
		// It participates in recall and precision like any other bucket and
		// deliberately does NOT alter the risk-tag forbidden semantics.
		if inst.Bucket != "A" && inst.Bucket != "B" && inst.Bucket != "L" && inst.Bucket != "S" {
			return fmt.Errorf("instance %s: bucket must be A|B|L|S, got %q", inst.ID, inst.Bucket)
		}
		if _, dup := seen[inst.ID]; dup {
			return fmt.Errorf("duplicate instance id %s", inst.ID)
		}
		seen[inst.ID] = struct{}{}
	}
	for _, fb := range m.Forbidden {
		if fb.File == "" {
			return fmt.Errorf("forbidden entry with empty file (reason %q)", fb.Reason)
		}
		if fb.LineEnd != nil && fb.Line == nil {
			return fmt.Errorf("forbidden %s: line_end without line", fb.File)
		}
		if fb.LineEnd != nil && *fb.LineEnd < *fb.Line {
			return fmt.Errorf("forbidden %s: line_end %d < line %d", fb.File, *fb.LineEnd, *fb.Line)
		}
	}
	for _, d := range m.Deps.Expect {
		if d.Manifest == "" || d.Package == "" || len(d.AlgorithmsInclude) == 0 {
			return fmt.Errorf("deps.expect entry needs manifest, package, algorithms_include (package %q)", d.Package)
		}
	}
	for _, d := range m.Deps.MustNotFlag {
		if d.Manifest == "" || d.Package == "" {
			return fmt.Errorf("deps.must_not_flag entry needs manifest and package (package %q)", d.Package)
		}
	}
	return nil
}
