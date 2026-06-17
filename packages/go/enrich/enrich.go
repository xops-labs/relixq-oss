// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package enrich implements the two-layer overlay. Detection rules ship in
// the OSS community tree and emit bare quantum-vulnerability findings. An
// optional external rule-pack overlay can supply a parallel tree of enrichment
// entries, each keyed by the same rule id, carrying migration intelligence
// (NIST substitution, vertical context, references). At report time the overlay
// merges each enrichment entry onto the matching detection finding in place.
//
// The mechanism is self-contained; the overlay content is supplied separately
// and is optional. When no overlay is present LoadDir returns an empty index
// and Apply is a no-op, so the scanner emits detection-only findings —
// actionable on their own.
//
package enrich

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/relix-q/relix-q/finding"
	"gopkg.in/yaml.v3"
)

// Entry is one migration-enrichment overlay, keyed to a detection rule by id.
// It carries no detector/pattern — it is never matched independently; it only
// decorates a finding the detection layer already produced.
type Entry struct {
	RuleID          string   `yaml:"rule_id"`
	Layer           string   `yaml:"layer"`
	Recommendation  string   `yaml:"recommendation"`
	MigrationTarget string   `yaml:"migration_target"`
	VerticalContext string   `yaml:"vertical_context"`
	References      []string `yaml:"references"`
	CWE             []int    `yaml:"cwe"`
}

// Index maps a rule id to its enrichment overlay.
type Index map[string]Entry

// LoadDir walks a rule-pack overlay directory and indexes every enrichment
// entry by rule id. A missing directory is not an error — it is the ordinary
// OSS case (no overlay installed), and yields an empty index so Apply becomes
// a no-op.
func LoadDir(dir string) (Index, error) {
	idx := Index{}
	if dir == "" {
		return idx, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return idx, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("enrich: rule-pack path %q is not a directory", dir)
	}

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
		entries, err := loadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, e := range entries {
			if e.RuleID == "" {
				return fmt.Errorf("%s: enrichment entry missing rule_id", path)
			}
			idx[e.RuleID] = e
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return idx, nil
}

func loadFile(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// List form first (the common case), then single-mapping fallback.
	var asList []Entry
	if err := yaml.Unmarshal(data, &asList); err == nil && len(asList) > 0 && asList[0].RuleID != "" {
		return asList, nil
	}
	var single Entry
	if err := yaml.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if single.RuleID == "" {
		return nil, nil
	}
	return []Entry{single}, nil
}

// Apply overlays enrichment onto findings in place and returns the number of
// findings enriched. Overlay is additive and never destructive: it only fills
// fields the detection finding left empty, so a finding that somehow already
// carries a recommendation is untouched. Detection-level fields (algorithm,
// quantum_safety, severity, message) are never altered.
func Apply(findings []finding.Finding, idx Index) int {
	if len(idx) == 0 {
		return 0
	}
	n := 0
	for i := range findings {
		e, ok := idx[findings[i].RuleID]
		if !ok {
			continue
		}
		enriched := false
		if findings[i].Recommendation == "" && e.Recommendation != "" {
			findings[i].Recommendation = e.Recommendation
			enriched = true
		}
		if findings[i].MigrationTarget == "" && e.MigrationTarget != "" {
			findings[i].MigrationTarget = e.MigrationTarget
			enriched = true
		}
		if findings[i].VerticalContext == "" && e.VerticalContext != "" {
			findings[i].VerticalContext = e.VerticalContext
			enriched = true
		}
		if len(findings[i].References) == 0 && len(e.References) > 0 {
			findings[i].References = e.References
			enriched = true
		}
		if len(findings[i].CWE) == 0 && len(e.CWE) > 0 {
			findings[i].CWE = e.CWE
			enriched = true
		}
		if enriched {
			n++
		}
	}
	return n
}
