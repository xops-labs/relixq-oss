// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// File-level multi-signal promotion ("fusion within a file"): individual
// hand-rolled / constant-fingerprint rules are deliberately low-confidence —
// a bare 65537 or a lone modexp is a lead, not a verdict. But when two or
// more DISTINCT rules agree on the same algorithm inside one file, the joint
// signal is strong: this pass emits ONE additional promoted finding per
// agreeing algorithm group, leaving the raw signals in place.
//
// Confidence uses the same Bayesian independent-observation form as the
// cross-channel package fusion (see fusion.bayesianFuse):
//
//	P(true) = 1 - Π_i (1 - c_i)
//
// over the distinct contributing rules, capped at promotedConfidenceCap.
// This pass is deliberately NOT wired into package fusion itself — fusion's
// model is cross-channel / repo-level (AST × SBOM × TLS), while promotion is
// strictly within-file corroboration of weak detection-layer signals.
package scanner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/relix-q/relix-q/finding"
)

const (
	// promotedRulePrefix / promotedRuleSuffix shape the synthetic rule id:
	// HANDROLLED_<ALG>_PROMOTED (e.g. HANDROLLED_RSA_PROMOTED).
	promotedRulePrefix = "HANDROLLED_"
	promotedRuleSuffix = "_PROMOTED"

	// promotedConfidenceCap keeps a promoted finding distinguishable from a
	// direct high-confidence API detection (which may legitimately claim more).
	promotedConfidenceCap = 0.95

	// promotedUsageType marks the synthetic finding and guards re-promotion.
	promotedUsageType = "handrolled"
)

// promotionCategories are the signal categories eligible for promotion: the
// low-confidence hand-rolled heuristics and the constant-fingerprint pack.
var promotionCategories = map[string]struct{}{
	"handrolled-crypto":  {},
	"crypto-fingerprint": {},
}

// promoteHandrolled inspects one file's already-collected findings and
// returns the promoted findings to append (possibly none). Promoted findings
// flow through the normal JSONL/SARIF path unchanged; they never re-feed
// promotion (guarded by usage_type and the synthetic rule-id shape).
func promoteHandrolled(fileFindings []*finding.Finding) []*finding.Finding {
	// Collect eligible raw signals in input order.
	var signals []*finding.Finding
	for _, f := range fileFindings {
		if _, ok := promotionCategories[f.Category]; !ok {
			continue
		}
		if isPromotedFinding(f) {
			continue
		}
		if promotionAlgKey(f.Algorithm) == "" {
			continue
		}
		signals = append(signals, f)
	}
	if len(signals) < 2 {
		return nil
	}

	// Group signals by normalized algorithm. Special case: the modexp family.
	// Modular exponentiation is RSA/DH-ambiguous (GO_BIGINT_MODEXP labels it
	// RSA at low confidence by convention), so RSA- and DH-labeled signals in
	// the same file still corroborate each other; the merged group adopts the
	// algorithm of its most confident signal (a MODP prime IS Diffie-Hellman,
	// so the 0.95 fingerprint outranks the 0.35 modexp heuristic).
	keyOf := func(f *finding.Finding) string { return promotionAlgKey(f.Algorithm) }
	hasRSA, hasDH := false, false
	for _, s := range signals {
		switch keyOf(s) {
		case "RSA":
			hasRSA = true
		case "DH":
			hasDH = true
		}
	}
	if hasRSA && hasDH {
		dominant := dominantSignal(signals, func(f *finding.Finding) bool {
			k := keyOf(f)
			return k == "RSA" || k == "DH"
		})
		mergedKey := promotionAlgKey(dominant.Algorithm)
		keyOf = func(f *finding.Finding) string {
			k := promotionAlgKey(f.Algorithm)
			if k == "RSA" || k == "DH" {
				return mergedKey
			}
			return k
		}
	}

	groups := map[string][]*finding.Finding{}
	for _, s := range signals {
		k := keyOf(s)
		groups[k] = append(groups[k], s)
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output order

	var promoted []*finding.Finding
	for _, k := range keys {
		group := groups[k]

		// Distinct rule ids only: a rule firing on five lines is still one
		// signal. Keep each rule's maximum confidence.
		confByRule := map[string]float64{}
		for _, s := range group {
			if c := s.Confidence; c > confByRule[s.RuleID] {
				confByRule[s.RuleID] = c
			}
		}
		if len(confByRule) < 2 {
			continue // a single corroborating rule is not corroboration
		}

		// Bayesian fusion over the distinct signals (cited form above).
		complement := 1.0
		ruleIDs := make([]string, 0, len(confByRule))
		for id, c := range confByRule {
			ruleIDs = append(ruleIDs, id)
			if c <= 0 {
				c = 0.5 // uninformative prior, mirrors fusion.bayesianFuse
			}
			if c > 1 {
				c = 1
			}
			complement *= 1.0 - c
		}
		sort.Strings(ruleIDs)
		fused := 1.0 - complement
		if fused > promotedConfidenceCap {
			fused = promotedConfidenceCap
		}

		first := group[0]                              // line attribution: the first signal's line
		dominant := dominantSignal(group, nil)         // labels: the most confident signal
		fnd := &finding.Finding{
			ScanJobID: first.ScanJobID,
			RuleID:    promotedRulePrefix + k + promotedRuleSuffix,
			Language:  first.Language,
			Algorithm: dominant.Algorithm,
			UsageType: promotedUsageType,
			// quantum_safety inherited from the signals' tier (the rules
			// already encode it: vulnerable for RSA/DH/ECDSA, grover_weakened
			// for AES/SHA-256, classically_broken for MD5/SHA-1).
			QuantumSafety:  dominant.QuantumSafety,
			Severity:       finding.SeverityHigh,
			FilePath:       first.FilePath,
			LineNumber:     first.LineNumber,
			Column:         first.Column,
			Snippet:        first.Snippet,
			SnippetContext: first.SnippetContext,
			Confidence:     fused,
			Category:       "handrolled-crypto",
			Message: fmt.Sprintf(
				"Hand-rolled %s implementation: %d corroborating detection signals in this file (%s). Fused confidence %.2f.",
				dominant.Algorithm, len(ruleIDs), strings.Join(ruleIDs, ", "), fused),
			Recommendation: "Replace hand-rolled cryptography with a vetted library, then migrate to the NIST PQC suite (FIPS 203/204/205).",
			CWE:            []int{327},
		}
		promoted = append(promoted, fnd)
	}
	return promoted
}

// isPromotedFinding guards against a promoted finding re-feeding promotion.
func isPromotedFinding(f *finding.Finding) bool {
	if f.UsageType == promotedUsageType {
		return true
	}
	return strings.HasPrefix(f.RuleID, promotedRulePrefix) &&
		strings.HasSuffix(f.RuleID, promotedRuleSuffix)
}

// dominantSignal returns the highest-confidence finding (ties: first in
// input order) among those accepted by the filter (nil filter = all).
func dominantSignal(findings []*finding.Finding, accept func(*finding.Finding) bool) *finding.Finding {
	var best *finding.Finding
	for _, f := range findings {
		if accept != nil && !accept(f) {
			continue
		}
		if best == nil || f.Confidence > best.Confidence {
			best = f
		}
	}
	return best
}

// promotionAlgKey folds an algorithm label to an uppercase alphanumeric key
// (AES-128 == AES128, SHA-256 == SHA256) — the same folding the validation
// gate applies — so rule packs with different punctuation conventions still
// group together. Empty input yields "" (signal excluded from promotion).
func promotionAlgKey(algorithm string) string {
	var b strings.Builder
	for _, r := range algorithm {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}
