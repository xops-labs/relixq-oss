// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package rules loads YAML rule packs and compiles them into
// matchable detectors. The schema supports both AST and regex detector kinds
// — only regex is wired in v0.1; AST rules are loaded but skipped with a
// structured "ast_runner_unavailable" log message until Tree-sitter is added.
package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/relix-q/relix-q/finding"
	"gopkg.in/yaml.v3"
)

// DetectorKind enumerates the rule detector implementations.
type DetectorKind string

const (
	DetectorRegex DetectorKind = "regex"
	DetectorAST   DetectorKind = "ast"
)

// Rule is the on-disk YAML shape plus a compiled regex.
type Rule struct {
	ID       string `yaml:"id"`
	Language string `yaml:"language"`
	Category string `yaml:"category"`
	// Layer marks the two-layer split for crypto-api rules: "detection"
	// rules ship in the OSS community tree (they carry pattern/algorithm/
	// quantum_safety); "enrichment" rules live in an optional external rule-pack
	// overlay keyed by id (see package enrich). Empty == detection (the default
	// for every non-crypto-api baseline rule).
	Layer          string                `yaml:"layer"`
	Severity       finding.Severity      `yaml:"severity"`
	Algorithm      string                `yaml:"algorithm"`
	UsageType      string                `yaml:"usage_type"`
	QuantumSafe    bool                  `yaml:"quantum_safe"`
	QuantumSafety  finding.QuantumSafety `yaml:"quantum_safety"`
	KeySize        *int                  `yaml:"key_size,omitempty"`
	Detector       Detector              `yaml:"detector"`
	Message        string                `yaml:"message"`
	Recommendation string                `yaml:"recommendation"`
	References     []string              `yaml:"references"`
	CWE            []int                 `yaml:"cwe"`
	Confidence     float64               `yaml:"confidence"`
	FileGlobs      []string              `yaml:"file_globs"` // optional restriction by glob
	// Examples are inline self-tests for the rule: every `match` line must
	// trigger the detector and every `no_match` line must not. Validated by
	// the rules schema test; required for new regex rules (older rules are
	// grandfathered via the examples baseline — see rules_test.go).
	Examples *RuleExamples `yaml:"examples,omitempty"`

	compiled *regexp.Regexp
}

// RuleExamples holds the inline positive/negative self-test lines for a rule.
type RuleExamples struct {
	Match   []string `yaml:"match"`
	NoMatch []string `yaml:"no_match"`
}

// Detector is the discriminated union for ast vs regex.
type Detector struct {
	Type    DetectorKind `yaml:"type"`
	Pattern string       `yaml:"pattern"` // regex
	Query   string       `yaml:"query"`   // ast
	Flags   string       `yaml:"flags"`   // regex flags: 'i', 'm', 's' combinations
}

// Pack is a loaded set of rules, indexed by language for fast routing.
type Pack struct {
	Version    string
	All        []*Rule
	byLanguage map[string][]*Rule
}

// EffectiveQuantumSafety derives quantum_safety from the legacy quantum_safe bool
// when the new field is absent.
func (r *Rule) EffectiveQuantumSafety() finding.QuantumSafety {
	if r.QuantumSafety != "" {
		return r.QuantumSafety
	}
	if r.QuantumSafe {
		return finding.QuantumSafe
	}
	return finding.QuantumVulnerable
}

// Compiled returns the compiled regex (only valid for regex detectors).
func (r *Rule) Compiled() *regexp.Regexp { return r.compiled }

// LoadDir walks a rule-pack directory and parses every *.yaml / *.yml file it
// contains. Files may declare either a single rule (mapping) or a list of rules.
func LoadDir(root string) (*Pack, error) {
	pack := &Pack{Version: deriveVersion(root), byLanguage: map[string][]*Rule{}}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rules, err := loadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, r := range rules {
			pack.All = append(pack.All, r)
			pack.byLanguage[strings.ToLower(r.Language)] = append(
				pack.byLanguage[strings.ToLower(r.Language)], r,
			)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pack, nil
}

// LoadBytes parses one YAML document. Useful for tests.
func LoadBytes(data []byte) ([]*Rule, error) {
	return parse(data, "<bytes>")
}

// NewPackForTest builds an indexed Pack from a slice of already-loaded rules.
// Test-only helper — production code should use LoadDir.
func NewPackForTest(rules []*Rule) *Pack {
	p := &Pack{Version: "test", byLanguage: map[string][]*Rule{}}
	for _, r := range rules {
		p.All = append(p.All, r)
		p.byLanguage[strings.ToLower(r.Language)] = append(p.byLanguage[strings.ToLower(r.Language)], r)
	}
	return p
}

// ForLanguage returns every rule that targets the given language. The special
// language "any" applies to all files.
func (p *Pack) ForLanguage(lang string) []*Rule {
	lang = strings.ToLower(lang)
	out := append([]*Rule(nil), p.byLanguage[lang]...)
	if lang != "any" {
		out = append(out, p.byLanguage["any"]...)
	}
	return out
}

// Languages returns the set of languages the pack covers.
func (p *Pack) Languages() []string {
	out := make([]string, 0, len(p.byLanguage))
	for k := range p.byLanguage {
		out = append(out, k)
	}
	return out
}

func loadFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data, path)
}

func parse(data []byte, source string) ([]*Rule, error) {
	// Try list form first.
	var asList []*Rule
	if err := yaml.Unmarshal(data, &asList); err == nil && len(asList) > 0 && asList[0] != nil && asList[0].ID != "" {
		return finalize(asList, source)
	}
	var single Rule
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if single.ID == "" {
		return nil, fmt.Errorf("rule %s has no id", source)
	}
	return finalize([]*Rule{&single}, source)
}

func finalize(rules []*Rule, source string) ([]*Rule, error) {
	for _, r := range rules {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rule %s in %s: %w", r.ID, source, err)
		}
		if r.Confidence == 0 {
			switch r.Detector.Type {
			case DetectorAST:
				r.Confidence = 0.95
			case DetectorRegex:
				r.Confidence = 0.7
			}
		}
		if r.Detector.Type == DetectorRegex {
			pattern := r.Detector.Pattern
			if r.Detector.Flags != "" {
				pattern = "(?" + r.Detector.Flags + ")" + pattern
			}
			rx, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: regex compile: %w", r.ID, err)
			}
			r.compiled = rx
		}
	}
	return rules, nil
}

func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("missing id")
	}
	if r.Language == "" {
		return fmt.Errorf("missing language")
	}
	if r.Severity == "" {
		return fmt.Errorf("missing severity")
	}
	switch r.Detector.Type {
	case DetectorRegex:
		if r.Detector.Pattern == "" {
			return fmt.Errorf("regex detector missing pattern")
		}
	case DetectorAST:
		if r.Detector.Query == "" {
			return fmt.Errorf("ast detector missing query")
		}
	default:
		return fmt.Errorf("unknown detector type %q", r.Detector.Type)
	}
	switch r.Severity {
	case finding.SeverityInfo, finding.SeverityLow, finding.SeverityMedium, finding.SeverityHigh, finding.SeverityCritical:
	default:
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	return nil
}

func deriveVersion(root string) string {
	if v, ok := os.LookupEnv("RELIXQ_RULE_PACK_VERSION"); ok {
		return v
	}
	return "local-" + filepath.Base(root)
}
