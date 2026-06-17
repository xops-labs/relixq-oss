// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package baseline implements accepted-findings baselining: a
// scan can record its current findings as a baseline, and later scans report
// only findings absent from it. This lets a team adopt the scanner on a legacy
// codebase and gate CI on *new* quantum-vulnerable crypto without drowning in
// the pre-existing backlog. Identity is model.Finding.ComputeFingerprint, which
// is resilient to line-number drift.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// DefaultFile is the conventional baseline path, checked into the repo so CI
// and local scans share the same accepted set.
const DefaultFile = ".relixq-baseline.json"

// SchemaVersion is the on-disk baseline format version.
const SchemaVersion = 1

// Entry records one accepted finding. RuleID and FilePath are denormalized for
// human readability when reviewing the baseline file in a diff; Fingerprint is
// the matched identity.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	FilePath    string `json:"file_path"`
}

// Baseline is the set of accepted findings.
type Baseline struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Entry   `json:"findings"`

	set map[string]struct{}
}

// FromFindings builds a baseline from a scan's findings, de-duplicating by
// fingerprint and sorting for a stable, diff-friendly file.
func FromFindings(findings []model.Finding) *Baseline {
	b := &Baseline{Version: SchemaVersion, GeneratedAt: time.Now().UTC(), set: map[string]struct{}{}}
	for _, f := range findings {
		fp := f.ComputeFingerprint()
		if _, dup := b.set[fp]; dup {
			continue
		}
		b.set[fp] = struct{}{}
		b.Findings = append(b.Findings, Entry{Fingerprint: fp, RuleID: f.RuleID, FilePath: f.FilePath})
	}
	sort.Slice(b.Findings, func(i, j int) bool {
		if b.Findings[i].FilePath != b.Findings[j].FilePath {
			return b.Findings[i].FilePath < b.Findings[j].FilePath
		}
		return b.Findings[i].Fingerprint < b.Findings[j].Fingerprint
	})
	return b
}

// Save writes the baseline as indented JSON with a trailing newline.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Load reads a baseline file and rebuilds its lookup set. A missing file is
// returned as an error — callers point --baseline at a file they expect to
// exist; use os.IsNotExist on the error to special-case first-run flows.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	b.set = make(map[string]struct{}, len(b.Findings))
	for _, e := range b.Findings {
		b.set[e.Fingerprint] = struct{}{}
	}
	return &b, nil
}

// Contains reports whether a finding is already in the baseline.
func (b *Baseline) Contains(f model.Finding) bool {
	_, ok := b.set[f.ComputeFingerprint()]
	return ok
}

// Filter partitions findings into the ones NOT in the baseline (returned — the
// new findings a gated scan should report) and a count of those suppressed
// because they were already accepted.
func (b *Baseline) Filter(findings []model.Finding) (newFindings []model.Finding, suppressed int) {
	for _, f := range findings {
		if b.Contains(f) {
			suppressed++
			continue
		}
		newFindings = append(newFindings, f)
	}
	return newFindings, suppressed
}
