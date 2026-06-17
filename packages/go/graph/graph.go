// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package graph implements the Crypto Blast-Radius Graph (Build #3) —
// the third algorithm in the migration-readiness pipeline.
//
// Given a finding (e.g. "RSA-1024 keypair generation in auth.py:42"),
// the blast-radius graph answers: "if you migrate this, how many other
// files in this repo are transitively affected?" — identifying the
// transitive set of files / modules dependent on a target crypto-
// bearing source file, weighted by the severity and corroboration
// level of the originating finding.
//
// The algorithm composes cleanly with the prior two builds:
//
//   - Findings from internal/agility tell us HOW HARD the migration is.
//   - Clusters from internal/fusion tell us HOW SURE we are.
//   - Blast-radius from this package tells us HOW WIDE the impact is.
//
// Together they convert per-finding records into a per-finding
// migration-cost projection that compounds across the three
// algorithms rather than living in any single one.
//
// # Approach
//
// In v1, the graph is built from import statements in three languages
// (Go / Python / JS / TS) that have simple, regex-extractable import
// syntax. These cover the majority of typical polyglot repos. Files in
// languages without an import extractor still appear as nodes — their
// blast radius is computed from a same-directory-neighbor fallback,
// which is a useful proxy for tightly-coupled modules even without
// dependency resolution.
//
// Adding a new language is mechanical (one regex extractor in
// importers.go + one entry in the dispatcher). Future builds may swap
// the regex extractors for AST-based extraction reusing the scanner's
// existing tree-sitter / Roslyn runners — but the graph structure and
// the BlastRadius algorithm stay identical.
package graph

import (
	"sort"
	"strings"

	"github.com/relix-q/relix-q/finding"
)

// Graph is a directed file-dependency graph. Edges point from
// importer → importee, i.e. an edge (a.go → b.go) means "a.go imports
// b.go". The reverse map exists to answer "who depends on b.go?" in
// O(1) without rebuilding.
//
// Files are stored as repo-relative slash-separated paths so the same
// repo on Windows / macOS / Linux produces the same graph.
type Graph struct {
	// edges[importer] = set of importees
	edges map[string]map[string]struct{}
	// reverse[importee] = set of importers
	reverse map[string]map[string]struct{}
	// files known to the graph (may have neither incoming nor outgoing
	// edges if the file has no imports + no importers in the resolved
	// set, but we still need them as graph nodes for directory-neighbor
	// fallback)
	files map[string]struct{}
}

// New creates an empty Graph.
func New() *Graph {
	return &Graph{
		edges:   map[string]map[string]struct{}{},
		reverse: map[string]map[string]struct{}{},
		files:   map[string]struct{}{},
	}
}

// AddFile registers a file as a graph node even if it has no edges.
// Idempotent — duplicate calls are no-ops.
func (g *Graph) AddFile(path string) {
	g.files[normalisePath(path)] = struct{}{}
}

// AddEdge records "from imports to". Both endpoints are registered as
// nodes automatically. Idempotent on (from, to) pairs.
func (g *Graph) AddEdge(from, to string) {
	from = normalisePath(from)
	to = normalisePath(to)
	if from == "" || to == "" || from == to {
		return
	}
	g.AddFile(from)
	g.AddFile(to)
	if g.edges[from] == nil {
		g.edges[from] = map[string]struct{}{}
	}
	g.edges[from][to] = struct{}{}
	if g.reverse[to] == nil {
		g.reverse[to] = map[string]struct{}{}
	}
	g.reverse[to][from] = struct{}{}
}

// DirectImporters returns the files that directly import path
// (one-hop). Sorted for determinism.
func (g *Graph) DirectImporters(path string) []string {
	path = normalisePath(path)
	importers := g.reverse[path]
	out := make([]string, 0, len(importers))
	for f := range importers {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// TransitiveImporters returns the full closure of files that
// transitively import path. Uses BFS with cycle detection (cycles can
// legitimately exist in some package graphs, especially TypeScript).
//
// maxHops bounds the BFS depth. 0 means unbounded. Bounding is
// recommended for very large repos where the full closure can dominate
// the output set and add little marginal signal beyond the first
// few hops.
func (g *Graph) TransitiveImporters(path string, maxHops int) []string {
	path = normalisePath(path)
	visited := map[string]struct{}{path: {}}
	queue := []string{path}
	depth := 0
	for len(queue) > 0 {
		if maxHops > 0 && depth >= maxHops {
			break
		}
		next := []string{}
		for _, cur := range queue {
			for f := range g.reverse[cur] {
				if _, seen := visited[f]; !seen {
					visited[f] = struct{}{}
					next = append(next, f)
				}
			}
		}
		queue = next
		depth++
	}
	out := make([]string, 0, len(visited))
	for f := range visited {
		if f == path {
			continue
		}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// SameDirectoryFiles returns sibling files in the same directory as
// path. Used as the directory-neighbor fallback signal — files that
// share a directory are typically tightly coupled even if no import
// edge has been resolved between them (especially common in
// languages where import extraction isn't implemented yet).
func (g *Graph) SameDirectoryFiles(path string) []string {
	path = normalisePath(path)
	dir := dirOf(path)
	out := []string{}
	for f := range g.files {
		if f == path {
			continue
		}
		if dirOf(f) == dir {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// NodeCount returns the total number of files in the graph. Useful
// for sanity-checking the build step against expected repo size.
func (g *Graph) NodeCount() int { return len(g.files) }

// EdgeCount returns the total number of import edges resolved. The
// ratio EdgeCount / NodeCount is a useful coupling indicator on its
// own — a repo with 100 files and 500 edges is significantly more
// tightly coupled than one with 100 files and 50 edges.
func (g *Graph) EdgeCount() int {
	n := 0
	for _, out := range g.edges {
		n += len(out)
	}
	return n
}

// ImpactReport bundles the blast-radius computation for one finding.
// The fields are explicitly named so the JSON output documents itself
// for downstream consumers.
type ImpactReport struct {
	FindingID           string `json:"finding_id,omitempty"`
	FilePath            string `json:"file_path"`
	RuleID              string `json:"rule_id"`
	Algorithm           string `json:"algorithm,omitempty"`
	Severity            string `json:"severity,omitempty"`
	LineNumber          int    `json:"line_number,omitempty"`
	Column              int    `json:"column,omitempty"`
	DirectImporters     int    `json:"direct_importers"`
	TransitiveImporters int    `json:"transitive_importers"`
	SameDirectoryFiles  int    `json:"same_directory_files"`
	// BlastRadius is the headline number. It composes the three
	// signals with weights chosen so that transitive impact dominates
	// (an import chain implies semantic dependency) but direct
	// importers and same-directory neighbours still register a base
	// signal even when import edges weren't resolved.
	BlastRadius int `json:"blast_radius"`
	// MigrationCostBand bins BlastRadius into Low/Medium/High/
	// Catastrophic for dashboard summarisation. Thresholds are
	// deterministic and integer-keyed; same inputs → same band.
	MigrationCostBand string `json:"migration_cost_band"`
	// AffectedFiles lists the transitively-impacted files (capped to
	// keep the JSON small) so reviewers can inspect what would break.
	AffectedFiles []string `json:"affected_files,omitempty"`
}

// affectedFilesCap limits how many file paths flow into AffectedFiles.
// Full closures can be thousands of files on big monorepos; the cap
// keeps the JSON dashboard-friendly while preserving the count.
const affectedFilesCap = 20

// computeBlastRadius is the weighted-sum formula used to produce the
// headline number from the three signal counts.
//
//	blast_radius = 3·transitive + 1·direct + 1·same_dir
//
// Rationale for the 3x weighting on transitive: a transitive importer
// represents a semantic dependency (the code uses something the
// crypto-bearing file exports). A same-directory file is a weaker
// signal because directory co-location doesn't prove coupling. The
// formula is intentionally simple — like the agility scorecard, it is
// transparent and table-explainable, not tuned to a benchmark.
func computeBlastRadius(direct, transitive, sameDir int) int {
	return 3*transitive + direct + sameDir
}

// bandForBlastRadius returns the deterministic band label for a
// blast-radius score. Bands are integer-keyed to preserve the
// same-input → same-output invariant.
func bandForBlastRadius(br int) string {
	switch {
	case br >= 200:
		return "Catastrophic"
	case br >= 50:
		return "High"
	case br >= 10:
		return "Medium"
	default:
		return "Low"
	}
}

// Impact computes blast-radius reports for every finding. Findings
// sharing a FilePath produce one report per finding (the per-finding
// rule metadata is preserved) but the file-level numbers
// (direct/transitive/same-dir) are stable across them.
//
// Output is sorted by BlastRadius desc then FilePath asc — the
// dashboard's "most impactful migration target" list is reproducible.
func Impact(g *Graph, findings []finding.Finding) []ImpactReport {
	cache := map[string]struct {
		direct, transitive, sameDir int
		affected                    []string
	}{}

	out := make([]ImpactReport, 0, len(findings))
	for _, f := range findings {
		key := normalisePath(f.FilePath)
		entry, ok := cache[key]
		if !ok {
			direct := len(g.DirectImporters(key))
			trans := g.TransitiveImporters(key, 0)
			sameDir := len(g.SameDirectoryFiles(key))
			affected := trans
			if len(affected) > affectedFilesCap {
				affected = affected[:affectedFilesCap]
			}
			entry = struct {
				direct, transitive, sameDir int
				affected                    []string
			}{direct, len(trans), sameDir, affected}
			cache[key] = entry
		}
		br := computeBlastRadius(entry.direct, entry.transitive, entry.sameDir)
		out = append(out, ImpactReport{
			FindingID:           f.FindingID,
			FilePath:            key,
			RuleID:              f.RuleID,
			Algorithm:           f.Algorithm,
			Severity:            string(f.Severity),
			LineNumber:          f.LineNumber,
			Column:              f.Column,
			DirectImporters:     entry.direct,
			TransitiveImporters: entry.transitive,
			SameDirectoryFiles:  entry.sameDir,
			BlastRadius:         br,
			MigrationCostBand:   bandForBlastRadius(br),
			AffectedFiles:       entry.affected,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BlastRadius != out[j].BlastRadius {
			return out[i].BlastRadius > out[j].BlastRadius
		}
		return out[i].FilePath < out[j].FilePath
	})
	return out
}

// normalisePath converts to slash form and lower-cases. Lower-casing
// is intentional for case-insensitive filesystems (Windows / macOS
// default) so the same logical file is not represented twice.
func normalisePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.ToLower(p)
}

// dirOf returns the directory portion of a slash-form path. Returns
// "." for files at repo root (consistent with filepath.Dir but
// independent of OS separator).
func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}
