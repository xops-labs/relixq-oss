// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package agility computes a Crypto-Agility Scorecard for a repository — a
// quantification of how mechanically replaceable the cryptographic surface
// is, independent of which specific algorithms are in use.
//
// The scorecard answers a question no other PQC scanner currently answers:
// "Given that you have to migrate this crypto, how hard will it be?" Two
// repositories may both depend on RSA-2048, but the one with all crypto
// behind a single CryptoProvider interface migrates in a day; the one with
// 47 scattered direct-API call sites takes weeks.
//
// # Methodology
//
// The total score is the sum of four sub-metrics, each in the 0..25 range,
// giving a 0..100 final score. Sub-metrics are intentionally simple and
// deterministic — they read only from the canonical CryptoFinding stream
// the scanner already produces, with no schema enrichment required. This
// keeps the algorithm reproducible and the inputs auditable.
//
//   1. Library consolidation (0..25) — distinct crypto libraries imported
//   2. Call-site concentration (0..25) — fraction in top-3 files
//   3. Algorithm diversity (0..25) — distinct algorithm families
//   4. Hardcoded-key prevalence (0..25) — fraction of findings with literal keys
//
// Each sub-metric is documented at its computation site. The weightings are
// equal by deliberate design: the scorecard is intended to be transparent
// and explainable end-to-end, not tuned to any specific benchmark dataset.
//
// # Grade bands
//
//   - Agile      75..100 — mechanical migration; library/config swap suffices
//   - Manageable 50..74  — focused refactoring required, single-sprint scope
//   - Difficult  25..49  — architectural changes; needs design review
//   - Brittle     0..24  — fundamental rewrite; crypto is structurally entangled
//
// # Determinism and dependency-free output
//
// Score() is a pure function over the finding slice. Same inputs, same
// outputs. Implementation deliberately avoids floating-point comparison
// in band selection — all sub-metric thresholds are integer-keyed.
package agility

import (
	"sort"
	"strings"

	"github.com/relix-q/relix-q/finding"
)

// Scorecard is the complete agility assessment for a repository.
type Scorecard struct {
	TotalScore int    `json:"total_score"` // 0..100
	Grade      string `json:"grade"`       // Agile | Manageable | Difficult | Brittle

	LibraryConsolidation   SubMetric `json:"library_consolidation"`
	CallSiteConcentration  SubMetric `json:"call_site_concentration"`
	AlgorithmDiversity     SubMetric `json:"algorithm_diversity"`
	HardcodedKeyPrevalence SubMetric `json:"hardcoded_key_prevalence"`

	// Diagnostics — populated for inspection and for downstream consumers
	// (Build #3 graph correlation, dashboards) that want to drill into the
	// raw counts without re-deriving them.
	DistinctLibraries  []string    `json:"distinct_libraries"`
	DistinctAlgorithms []string    `json:"distinct_algorithms"`
	TopFiles           []FileCount `json:"top_files"`
	HardcodedKeyCount  int         `json:"hardcoded_key_count"`
	TotalFindings      int         `json:"total_findings"`
	FilesWithFindings  int         `json:"files_with_findings"`
}

// SubMetric is one of the four scorecard dimensions.
type SubMetric struct {
	Score       int    `json:"score"`        // 0..25
	MaxScore    int    `json:"max_score"`    // 25
	Description string `json:"description"`  // human-readable signal
	Detail      string `json:"detail,omitempty"`
}

// FileCount is one entry in the per-file finding histogram.
type FileCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// Score computes the agility scorecard for a slice of findings.
//
// Behavior on edge cases:
//   - Zero findings: returns a 100/100 "Agile" scorecard. A repo without
//     any detected crypto cannot be made harder to migrate. This is by
//     design — a clean repo should not be penalised.
//   - Findings without algorithm field: counted only by file and category.
func Score(findings []finding.Finding) Scorecard {
	sc := Scorecard{
		TotalFindings: len(findings),
	}

	if len(findings) == 0 {
		sc.LibraryConsolidation = SubMetric{Score: 25, MaxScore: 25, Description: "no crypto libraries detected"}
		sc.CallSiteConcentration = SubMetric{Score: 25, MaxScore: 25, Description: "no call sites"}
		sc.AlgorithmDiversity = SubMetric{Score: 25, MaxScore: 25, Description: "no algorithms in use"}
		sc.HardcodedKeyPrevalence = SubMetric{Score: 25, MaxScore: 25, Description: "no hardcoded keys"}
		sc.TotalScore = 100
		sc.Grade = grade(100)
		return sc
	}

	sc.LibraryConsolidation = scoreLibraryConsolidation(findings, &sc)
	sc.CallSiteConcentration = scoreCallSiteConcentration(findings, &sc)
	sc.AlgorithmDiversity = scoreAlgorithmDiversity(findings, &sc)
	sc.HardcodedKeyPrevalence = scoreHardcodedKeyPrevalence(findings, &sc)

	sc.TotalScore = sc.LibraryConsolidation.Score +
		sc.CallSiteConcentration.Score +
		sc.AlgorithmDiversity.Score +
		sc.HardcodedKeyPrevalence.Score
	sc.Grade = grade(sc.TotalScore)

	return sc
}

// grade returns the band label for a total score. Bands are integer-keyed
// to keep the result table-driven and free of floating-point comparison
// surprises.
func grade(total int) string {
	switch {
	case total >= 75:
		return "Agile"
	case total >= 50:
		return "Manageable"
	case total >= 25:
		return "Difficult"
	default:
		return "Brittle"
	}
}

// scoreLibraryConsolidation rewards repositories that depend on FEWER
// crypto libraries. Rationale: each additional library is a separate
// migration project — different ecosystems ship PQC support at different
// paces, and coordinating the cutover is the dominant cost in real
// migrations. A repo using only `cryptography` migrates as one project; a
// repo also using `pycryptodome`, `M2Crypto`, and `pyOpenSSL` migrates as
// four.
//
// Detection heuristic: any rule whose ID contains IMPORT / REQUIRE / USE
// is treated as a library-surface rule. The rule pack tags such rules
// consistently across languages (see rules/ruby/crypto.yaml,
// rules/python/crypto.yaml, etc.).
func scoreLibraryConsolidation(findings []finding.Finding, sc *Scorecard) SubMetric {
	libs := map[string]struct{}{}
	for _, f := range findings {
		if isLibrarySurfaceRule(f.RuleID) {
			lib := libraryNameFromRule(f.RuleID)
			if lib != "" {
				libs[lib] = struct{}{}
			}
		}
	}

	names := make([]string, 0, len(libs))
	for n := range libs {
		names = append(names, n)
	}
	sort.Strings(names)
	sc.DistinctLibraries = names

	n := len(names)
	var s int
	var desc string
	switch {
	case n == 0:
		// No import-surface rules fired. Either the repo uses crypto via
		// direct stdlib calls without a corresponding IMPORT rule (rare),
		// or the language pack doesn't have IMPORT rules yet. Score
		// neutrally at 18 (not 25) so this missing-signal case can be
		// distinguished from genuine single-library focus.
		s = 18
		desc = "no library-surface rules fired (neutral score)"
	case n == 1:
		s = 25
		desc = "single crypto library"
	case n == 2:
		s = 20
		desc = "two crypto libraries"
	case n <= 4:
		s = 12
		desc = "three or four crypto libraries"
	default:
		s = 5
		desc = "five or more crypto libraries"
	}
	return SubMetric{
		Score:       s,
		MaxScore:    25,
		Description: desc,
		Detail:      strings.Join(names, ", "),
	}
}

// scoreCallSiteConcentration rewards repositories whose crypto is
// concentrated in a few files. Concentration is a strong migration-cost
// predictor — refactoring three files is dramatically cheaper than
// touching forty. The metric is "fraction of total findings in the top-3
// files", computed deterministically.
//
// A repo with all crypto in one module scores 25; a repo with crypto
// scattered evenly across many files scores low. Configuration files
// (e.g. nginx.conf) count as files for this purpose — concentration of
// TLS misconfiguration in one config file is itself easier to migrate.
func scoreCallSiteConcentration(findings []finding.Finding, sc *Scorecard) SubMetric {
	perFile := map[string]int{}
	for _, f := range findings {
		perFile[f.FilePath]++
	}
	sc.FilesWithFindings = len(perFile)

	files := make([]FileCount, 0, len(perFile))
	for p, c := range perFile {
		files = append(files, FileCount{Path: p, Count: c})
	}
	// Sort by count descending, then path ascending for determinism on ties.
	sort.Slice(files, func(i, j int) bool {
		if files[i].Count != files[j].Count {
			return files[i].Count > files[j].Count
		}
		return files[i].Path < files[j].Path
	})

	topN := 3
	if len(files) < topN {
		topN = len(files)
	}
	sc.TopFiles = files[:topN]

	top3Count := 0
	for i := 0; i < topN; i++ {
		top3Count += files[i].Count
	}
	frac := float64(top3Count) / float64(len(findings))

	var s int
	var desc string
	switch {
	case frac >= 0.80:
		s = 25
		desc = "highly concentrated — top 3 files hold 80%+ of crypto"
	case frac >= 0.50:
		s = 18
		desc = "concentrated — top 3 files hold 50–80%"
	case frac >= 0.30:
		s = 12
		desc = "moderately scattered — top 3 files hold 30–50%"
	default:
		s = 5
		desc = "highly scattered — crypto spread across many files"
	}
	return SubMetric{
		Score:       s,
		MaxScore:    25,
		Description: desc,
	}
}

// scoreAlgorithmDiversity rewards repositories using FEWER distinct
// crypto algorithms. Rationale: the migration plan for "swap MD5 → SHA-3"
// is different from the plan for "swap RSA-2048 → ML-KEM-768". A repo
// using 1–2 algorithm families needs one migration plan; a repo touching
// 8 distinct primitives needs eight coordinated plans.
//
// Generic / catch-all algorithm names ("TLS", "CIPHER", "HASH", "HMAC",
// empty) are filtered — they conflate too many primitives to be
// meaningful and would falsely inflate the diversity count.
func scoreAlgorithmDiversity(findings []finding.Finding, sc *Scorecard) SubMetric {
	algos := map[string]struct{}{}
	for _, f := range findings {
		a := strings.ToUpper(strings.TrimSpace(f.Algorithm))
		if a == "" {
			continue
		}
		// Filter generic / catch-all algorithm tags. These collapse many
		// distinct primitives into a single tag and would distort the
		// diversity count downward (a single "TLS" tag could conceal
		// RSA + ECDHE + 3DES + AES).
		switch a {
		case "TLS", "CIPHER", "HASH", "HMAC", "MAC", "RNG", "SIGNATURE":
			continue
		}
		algos[a] = struct{}{}
	}
	names := make([]string, 0, len(algos))
	for n := range algos {
		names = append(names, n)
	}
	sort.Strings(names)
	sc.DistinctAlgorithms = names

	n := len(names)
	var s int
	var desc string
	switch {
	case n <= 2:
		s = 25
		desc = "1–2 algorithm families — single migration plan"
	case n <= 4:
		s = 18
		desc = "3–4 algorithm families"
	case n <= 6:
		s = 12
		desc = "5–6 algorithm families"
	default:
		s = 5
		desc = "7+ algorithm families — many parallel migrations"
	}
	return SubMetric{
		Score:       s,
		MaxScore:    25,
		Description: desc,
		Detail:      strings.Join(names, ", "),
	}
}

// scoreHardcodedKeyPrevalence penalises repositories where a significant
// fraction of findings are hardcoded keys / certificates. Rationale:
// hardcoded keys are the least agile of all crypto surfaces — they are
// not swappable by changing an import or a config flag; every embedded
// key requires generation of a replacement, redistribution, and a
// cutover. A repo with even 5% hardcoded-key findings is structurally
// rigid.
//
// Detection: rules whose category is "hardcoded-key" OR whose rule ID
// contains "HARDCODED". The rule-pack convention is consistent across
// every language we ship.
func scoreHardcodedKeyPrevalence(findings []finding.Finding, sc *Scorecard) SubMetric {
	hc := 0
	for _, f := range findings {
		if isHardcodedKeyFinding(f) {
			hc++
		}
	}
	sc.HardcodedKeyCount = hc

	frac := float64(hc) / float64(len(findings))

	var s int
	var desc string
	switch {
	case hc == 0:
		s = 25
		desc = "no hardcoded keys detected"
	case frac <= 0.02:
		s = 20
		desc = "very low hardcoded-key prevalence (<2%)"
	case frac <= 0.05:
		s = 12
		desc = "low hardcoded-key prevalence (2–5%)"
	case frac <= 0.10:
		s = 5
		desc = "moderate hardcoded-key prevalence (5–10%)"
	default:
		s = 0
		desc = "high hardcoded-key prevalence (>10%) — structurally rigid"
	}
	return SubMetric{
		Score:       s,
		MaxScore:    25,
		Description: desc,
	}
}

// isLibrarySurfaceRule heuristically identifies rules that fire on an
// import / require / use statement. Rule pack convention is to put one
// of these tokens in the rule ID for library-surface rules. The tokens
// were chosen to be language-agnostic — IMPORT covers Python / Java /
// TypeScript / Dart / etc.; REQUIRE covers Ruby / Node; USE covers Rust /
// PHP / Clojure / VHDL. Treating these uniformly is what makes the
// library-consolidation metric portable across the 28-language coverage.
func isLibrarySurfaceRule(ruleID string) bool {
	id := strings.ToUpper(ruleID)
	for _, marker := range []string{"_IMPORT_", "_REQUIRE_", "_USE_", "_OPEN_"} {
		if strings.Contains(id, marker) {
			return true
		}
	}
	// Trailing forms (e.g. RULE_NAME_IMPORT) — check suffix as well.
	for _, suffix := range []string{"_IMPORT", "_REQUIRE", "_USE", "_OPEN"} {
		if strings.HasSuffix(id, suffix) {
			return true
		}
	}
	return false
}

// libraryNameFromRule extracts the library identifier embedded in a
// library-surface rule ID. Convention: rule IDs are <LANG>_<KIND>_<LIB>
// or <LANG>_<LIB>_<KIND> — we extract the segment that follows the
// IMPORT/REQUIRE/USE marker, or precedes the IMPORT/REQUIRE/USE suffix.
// This is intentionally heuristic — perfect extraction would require
// schema enrichment; the heuristic suffices for the consolidation
// metric, which counts distinct strings rather than verifying them.
func libraryNameFromRule(ruleID string) string {
	id := strings.ToUpper(ruleID)
	for _, marker := range []string{"_IMPORT_", "_REQUIRE_", "_USE_", "_OPEN_"} {
		if idx := strings.Index(id, marker); idx >= 0 {
			tail := id[idx+len(marker):]
			return tail
		}
	}
	for _, suffix := range []string{"_IMPORT", "_REQUIRE", "_USE", "_OPEN"} {
		if strings.HasSuffix(id, suffix) {
			// Strip the language prefix (first underscore-delimited token)
			// and the trailing _IMPORT etc.
			body := strings.TrimSuffix(id, suffix)
			if idx := strings.Index(body, "_"); idx >= 0 {
				return body[idx+1:]
			}
			return body
		}
	}
	return ""
}

// isHardcodedKeyFinding identifies findings about embedded crypto
// material. Two signals are used: the canonical Category field (set by
// the rule pack to "hardcoded-key" or "hardcoded-secret") and the rule
// ID containing "HARDCODED" as a fallback for older / inconsistent rule
// authoring.
func isHardcodedKeyFinding(f finding.Finding) bool {
	cat := strings.ToLower(f.Category)
	if strings.Contains(cat, "hardcoded") {
		return true
	}
	if strings.Contains(strings.ToUpper(f.RuleID), "HARDCODED") {
		return true
	}
	return false
}
