// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package sbom

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/relix-q/relix-q/finding"
)

// Ingest walks repoRoot, finds every manifest ParseManifest knows,
// joins the declared dependencies against the knowledge base, and
// returns one CryptoFinding per (manifest line × known-crypto-library
// × algorithm).
//
// scanJobID is stamped on every emitted finding to match the AST
// scanner's behaviour — fusion (Build #2b) then treats SBOM and AST
// findings as equally first-class records that share a join key.
//
// The fan-out of one library to N algorithm findings is deliberate.
// A library covering RSA + ECDSA + AES + SHA-1 produces four findings,
// one per primitive, so fusion's Bayesian update can corroborate each
// primitive independently against the AST channel. Without the fan-out,
// the fusion algorithm would have to learn the library's algorithm set
// at runtime, defeating the deterministic-by-construction design.
func Ingest(repoRoot, scanJobID string) ([]finding.Finding, error) {
	var out []finding.Finding

	err := filepath.WalkDir(repoRoot, func(absPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// Skip noisy vendor / node_modules dirs to keep ingestion
			// honest — manifests inside vendor copies describe deps of
			// the dep, not deps of THIS project.
			base := strings.ToLower(d.Name())
			if base == "node_modules" || base == "vendor" || base == ".venv" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, absPath)
		if relErr != nil {
			rel = absPath
		}
		rel = filepath.ToSlash(rel)
		if !IsManifest(rel) {
			return nil
		}
		deps, parseErr := ParseManifest(absPath, rel)
		if parseErr != nil {
			// Malformed manifest — log to stderr via the standard "skip"
			// policy (silent here; the CLI wraps and logs).
			return nil
		}
		for _, dep := range deps {
			lib := Lookup(dep.Ecosystem, dep.PackageName)
			if lib == nil {
				continue
			}
			out = append(out, toFindings(dep, lib, scanJobID)...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk sbom manifests: %w", err)
	}
	return out, nil
}

// toFindings expands one (dependency, knowledge-base entry) pair into
// the per-algorithm finding fan-out. Each emitted finding carries:
//
//   - RuleID: synthetic SBOM_<ECOSYSTEM>_<PKG>_<ALGO> — readable, joins
//     cleanly against fusion's algorithm-class key, and stays distinct
//     from AST rule IDs.
//   - Algorithm: the canonical primitive tag (RSA, ECDSA, ...)
//   - Language: the ecosystem string (python / javascript / go) — same
//     vocabulary the AST scanner emits, so dashboards group them.
//   - FilePath: the manifest path (requirements.txt / package.json /
//     go.mod) — the user-actionable line where the dep is declared.
//   - Snippet: a human-readable summary that the dashboard can render
//     without needing additional lookups.
//   - Confidence: starts at 0.7 for SBOM-only findings (Bayesian prior
//     for "dependency present" → "code uses dep's crypto"). Fusion will
//     ratchet this when AST corroborates.
func toFindings(dep Dependency, lib *CryptoLib, scanJobID string) []finding.Finding {
	severity := finding.Severity(lib.Severity)
	if severity == "" {
		severity = finding.SeverityInfo
	}

	out := make([]finding.Finding, 0, len(lib.Algorithms))
	for _, algo := range lib.Algorithms {
		qs := algorithmQuantumSafety(algo)
		if lib.PQReady {
			qs = finding.QuantumSafe
		}
		ruleID := fmt.Sprintf("SBOM_%s_%s_%s",
			strings.ToUpper(string(dep.Ecosystem)),
			normaliseRuleSegment(dep.PackageName),
			normaliseRuleSegment(algo))

		risk := "quantum-vulnerable"
		switch qs {
		case finding.GroverWeakened:
			risk = "Grover-weakened"
		case finding.ClassicallyBroken:
			risk = "classically broken"
		}
		msg := fmt.Sprintf("Dependency %q (%s) implements %s — %s; audit usage and plan PQC migration.",
			dep.PackageName, dep.Version, algo, risk)
		if lib.Deprecated {
			msg = fmt.Sprintf("Dependency %q (%s) is DEPRECATED and implements %s. %s",
				dep.PackageName, dep.Version, algo, lib.Notes)
		}
		if lib.PQReady {
			msg = fmt.Sprintf("Dependency %q (%s) ships PQC primitive %s — migration target, not risk. %s",
				dep.PackageName, dep.Version, algo, lib.Notes)
		}

		out = append(out, finding.Finding{
			ScanJobID:     scanJobID,
			RuleID:        ruleID,
			Language:      string(dep.Ecosystem),
			Algorithm:     algo,
			UsageType:     "dependency",
			QuantumSafety: qs,
			Severity:      severity,
			FilePath:      dep.Manifest,
			LineNumber:    dep.LineNumber,
			Column:        1,
			Snippet:       fmt.Sprintf("%s@%s", dep.PackageName, dep.Version),
			Confidence:    0.7,
			Category:      lib.Category,
			Message:       msg,
		})
	}
	return out
}

// normaliseRuleSegment converts arbitrary names (which may contain
// dashes, slashes, dots) to ALL_CAPS_UNDERSCORE for use in a rule ID
// segment. The rule IDs need to be greppable / Slack-shareable, so
// keep them ASCII and explicit.
func normaliseRuleSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - ('a' - 'A'))
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
