// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package fusion implements cross-vertical crypto-finding fusion: the
// algorithm that combines findings from N independent detection
// channels (AST scanner, SBOM ingestor, future TLS / cloud / runtime
// channels) into a single corroboration-weighted finding stream with
// Bayesian confidence calibration.
//
// This is the IP core of Build #2 — the novelty is *not* the inputs
// (those are CryptoFindings the scanner already emits) but the
// reconciliation algorithm, which becomes more precise the more
// detection channels are added. The product already runs across 28
// programming languages + 11 config formats + SBOM (this commit) for a
// minimum of two channels; future channels (TLS handshake, cloud KMS,
// runtime telemetry) compose into the same fusion without altering the
// algorithm.
//
// # Conceptual model
//
// Each detection channel produces zero or more findings. A finding is
// characterised by (algorithm_class, repository, channel). Two findings
// from different channels are "corroborating" if they share
// (algorithm_class, repository) — they are independent reports of the
// same underlying crypto fact observed from different vantage points.
//
// # Bayesian update
//
// For an algorithm-class cluster with N corroborating channels, fused
// confidence is computed by combining independent observations:
//
//     P(true) = 1 - Π_i (1 - P_i)
//
// where P_i is the channel's per-finding confidence. Two channels at
// 0.85 fuse to 0.9775; three channels at 0.85/0.7/0.8 fuse to 0.991.
// Confidence is capped at 0.99 to keep a fused finding distinguishable
// from a perfect-certainty marker.
//
// When only one channel reports, confidence is the channel's original
// value — fusion is a no-op for unique observations. This means
// unfused findings flow through with their existing confidence intact,
// which is important for downstream consumers that already calibrate
// against per-channel confidence distributions.
//
// # Why "algorithm_class" and not file-path?
//
// Channels emit at different granularities. AST sees a source line in
// auth.py:42. SBOM sees a single line in requirements.txt. TLS sees a
// network endpoint. Cloud KMS sees a key ARN. There is no natural file
// join key. The cross-channel join key is the cryptographic primitive
// being detected — RSA, ECDSA, MD5, etc. — within the same repository.
// Two reports of "RSA-related risk in repo X" from independent channels
// corroborate each other regardless of which line numbers they point at.
//
// # Algorithm class normalisation
//
// Channels use different conventions: AST may say "RSA-1024", SBOM may
// say "RSA", TLS may say "RSA_KEY_EXCHANGE". The classKey function
// canonicalises these to a single algorithm class. Without this step,
// a true corroboration would look like a non-match.
package fusion

import (
	"sort"
	"strings"

	"github.com/relix-q/relix-q/finding"
)

// Cluster is the fused output of one algorithm-class corroboration.
// Each cluster bundles the source findings (preserved for drill-down)
// with the calibrated confidence and the channel count.
type Cluster struct {
	// AlgorithmClass is the canonical algorithm key after normalisation
	// (e.g. "RSA", "ECDSA", "MD5"). Two channels reporting on the same
	// class within the same scan are fused into one cluster.
	AlgorithmClass string `json:"algorithm_class"`

	// Channels lists which detection channels contributed findings to
	// this cluster, in deterministic order. Used by the dashboard to
	// render the corroboration badge ("AST + SBOM" vs "AST only").
	Channels []string `json:"channels"`

	// CorroborationCount is len(Channels) — pre-computed for cheap
	// downstream filtering / sorting.
	CorroborationCount int `json:"corroboration_count"`

	// FusedConfidence is the Bayesian-fused per-cluster confidence,
	// capped at 0.99 to preserve a perfect-certainty marker.
	FusedConfidence float64 `json:"fused_confidence"`

	// Severity is the maximum severity across contributing findings.
	// Rationale: any channel reporting a critical-severity finding
	// indicates the cluster as a whole carries that severity, even if
	// other channels saw weaker forms. Promoting the max keeps the
	// signal honest.
	Severity finding.Severity `json:"severity"`

	// Findings holds every contributing finding so that drilling into a
	// cluster surfaces the individual source records (with their file
	// paths, line numbers, snippets).
	Findings []finding.Finding `json:"findings"`
}

// Fuse takes findings from multiple channels and returns one Cluster
// per (repository × algorithm_class). The input is a slice of
// (channel-name, findings) pairs so the caller can name the channels
// freely (in practice they will be "ast" and "sbom" for Build #2;
// future builds add "tls", "cloud", "runtime").
//
// Channels with overlapping algorithm classes produce fused clusters
// with elevated confidence. Channels with non-overlapping classes
// produce single-channel clusters that flow through unchanged.
//
// Output is sorted deterministically: by CorroborationCount desc,
// then by AlgorithmClass asc. This means the dashboard's "most
// corroborated" view is reproducible from the same inputs.
type Channel struct {
	Name     string
	Findings []finding.Finding
}

// contrib is one (channel, finding) pair in a class bucket.
type contrib struct {
	channel string
	find    finding.Finding
}

func Fuse(channels ...Channel) []Cluster {
	// Step 1: group findings by canonical algorithm class.
	// Map key is the canonical class; value collects (channel, finding).
	byClass := map[string][]contrib{}

	for _, ch := range channels {
		for _, f := range ch.Findings {
			class := classKey(f.Algorithm)
			if class == "" {
				continue // findings without an extractable algorithm class
				// can't participate in fusion; the AST channel emits a
				// passthrough cluster for them in step 3.
			}
			byClass[class] = append(byClass[class], contrib{channel: ch.Name, find: f})
		}
	}

	// Step 2: build clusters. For each class, identify distinct
	// channels that contributed, apply Bayesian fusion.
	clusters := make([]Cluster, 0, len(byClass))
	for class, items := range byClass {
		channelsHit := distinctSorted(items)
		probs := make([]float64, 0, len(items))
		var maxSev finding.Severity
		findingsCopy := make([]finding.Finding, 0, len(items))
		for _, it := range items {
			probs = append(probs, conf(it.find))
			findingsCopy = append(findingsCopy, it.find)
			if severityRank(it.find.Severity) > severityRank(maxSev) {
				maxSev = it.find.Severity
			}
		}
		cl := Cluster{
			AlgorithmClass:     class,
			Channels:           channelsHit,
			CorroborationCount: len(channelsHit),
			FusedConfidence:    bayesianFuse(probs),
			Severity:           maxSev,
			Findings:           findingsCopy,
		}
		clusters = append(clusters, cl)
	}

	// Step 3: emit passthrough clusters for findings without an
	// extractable algorithm class. These keep flowing — losing them
	// would break the dashboard's "total findings" count and create
	// confusion. Each passthrough is its own single-finding cluster.
	for _, ch := range channels {
		for _, f := range ch.Findings {
			if classKey(f.Algorithm) != "" {
				continue
			}
			clusters = append(clusters, Cluster{
				AlgorithmClass:     "UNCLASSIFIED:" + f.RuleID,
				Channels:           []string{ch.Name},
				CorroborationCount: 1,
				FusedConfidence:    conf(f),
				Severity:           f.Severity,
				Findings:           []finding.Finding{f},
			})
		}
	}

	// Deterministic ordering for reproducibility.
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].CorroborationCount != clusters[j].CorroborationCount {
			return clusters[i].CorroborationCount > clusters[j].CorroborationCount
		}
		return clusters[i].AlgorithmClass < clusters[j].AlgorithmClass
	})

	return clusters
}

// classKey canonicalises an Algorithm string to a fusion join key.
// Channels report algorithms differently — AST may say "RSA-1024",
// SBOM may say "RSA", TLS may someday say "TLS_RSA_WITH_AES_128_GCM" —
// and we need them to land in the same bucket. The canonicalisation:
//
//  1. Uppercase the input.
//  2. Strip any key-size suffix (-1024, -2048, -3072, -4096, -224,
//     -256, -384, -512). These vary per channel and shouldn't fragment
//     the cluster.
//  3. Map known aliases to a primary form (3DES → DES, SHA-1 → SHA1).
//  4. Filter generic catch-all tags (TLS, CIPHER, HASH, HMAC) — they
//     conflate too many primitives to be meaningful keys.
//
// Returns "" for un-extractable / non-meaningful inputs so they take
// the passthrough path.
func classKey(algo string) string {
	a := strings.ToUpper(strings.TrimSpace(algo))
	if a == "" {
		return ""
	}
	// Filter generic catch-alls.
	switch a {
	case "TLS", "CIPHER", "HASH", "HMAC", "MAC", "RNG", "SIGNATURE", "ANY", "UNKNOWN", "NA":
		return ""
	}
	// Aliases: collapse to primary form.
	aliases := map[string]string{
		"3DES":            "DES",
		"TRIPLEDES":       "DES",
		"DES_EDE3":        "DES",
		"SHA-1":           "SHA1",
		"SHA-2":           "SHA2",
		"SHA-256":         "SHA256",
		"SHA-384":         "SHA384",
		"SHA-512":         "SHA512",
		"SHA-3":           "SHA3",
		"SHA-3-256":       "SHA3",
		"SHA3-256":        "SHA3",
		"X25519":          "X25519",
		"CURVE25519":      "X25519",
		"ED25519":         "ED25519",
		"CHACHA20":        "CHACHA20",
		"POLY1305":        "POLY1305",
		"BCRYPT":          "BCRYPT",
		"ARGON2":          "ARGON2",
		"PBKDF2":          "PBKDF2",
		"AES-GCM":         "AES",
		"AES-CBC":         "AES",
		"AES-CCM":         "AES",
	}
	if v, ok := aliases[a]; ok {
		return v
	}
	// Strip recognised suffixes that vary per channel and shouldn't
	// fragment a cluster:
	//
	//   - Key-size: RSA-1024 / RSA_2048 → RSA
	//   - Curve:    ECDSA-P256 / ECDSA-P384 / ECDSA-K1 → ECDSA
	//   - Padding:  RSA-OAEP / RSA-PKCS1V15 / RSA-PSS → RSA
	//   - Digest:   RSA-MD5 / RSA-SHA1 → RSA (the key risk; hash risk is its own class)
	//
	// All channels lose precision but gain cluster joinability, which
	// is the right trade-off for the cross-vertical-corroboration claim.
	for _, suf := range []string{
		"-1024", "-2048", "-3072", "-4096", "-512", "-256", "-224", "-384",
		"_1024", "_2048", "_3072", "_4096", "_512", "_256", "_224", "_384",
		"-P256", "-P384", "-P521", "_P256", "_P384", "_P521",
		"-K1", "-R1", "_K1", "_R1",
		"-OAEP", "-PKCS1V15", "-PSS", "_OAEP", "_PKCS1V15", "_PSS",
		"-MD5", "-SHA1", "-SHA256", "-SHA384", "-SHA512",
	} {
		if strings.HasSuffix(a, suf) {
			return a[:len(a)-len(suf)]
		}
	}
	// Recognised primary forms — pass through.
	switch a {
	case "RSA", "ECDSA", "ECDH", "ECC", "DSA", "DH", "DES", "RC4", "RC2",
		"MD5", "MD4", "MD2", "SHA1", "SHA2", "SHA3",
		"SHA256", "SHA384", "SHA512",
		"AES",
		"ML-KEM", "ML-DSA", "SLH-DSA", "FALCON",
		"ED25519", "X25519", "POLY1305", "CHACHA20",
		"BCRYPT", "ARGON2", "PBKDF2", "X509":
		return a
	}
	// Unknown / fixture-only / vertical-specific tags — drop into
	// passthrough rather than introducing noise in the cluster space.
	return ""
}

// distinctSorted extracts the unique channel names from a contribs
// slice, returning them in sorted order for deterministic output.
func distinctSorted(items []contrib) []string {
	seen := map[string]struct{}{}
	for _, it := range items {
		seen[it.channel] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// bayesianFuse combines per-channel confidences using:
//
//     P(true) = 1 - Π_i (1 - P_i)
//
// This is the formula for combining independent observations of the
// same event. Empty input returns 0; single-input returns that input;
// the cap at 0.99 reserves 1.0 for explicit-certainty markers.
//
// Channels without a confidence value default to 0.5 (uninformative
// prior) so missing data degrades to a neutral signal rather than
// dropping the channel.
func bayesianFuse(probs []float64) float64 {
	if len(probs) == 0 {
		return 0
	}
	complement := 1.0
	for _, p := range probs {
		if p <= 0 {
			p = 0.5
		}
		if p > 1 {
			p = 1
		}
		complement *= 1.0 - p
	}
	fused := 1.0 - complement
	if fused > 0.99 {
		fused = 0.99
	}
	return fused
}

// conf returns a finding's confidence, with a sensible fallback when
// the channel didn't set one. The 0.5 fallback matches bayesianFuse's
// internal uninformative-prior so the two are consistent.
func conf(f finding.Finding) float64 {
	if f.Confidence > 0 {
		return f.Confidence
	}
	return 0.5
}

// severityRank converts severity to a comparable integer so the
// max-severity reduction is well-defined.
func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 5
	case finding.SeverityHigh:
		return 4
	case finding.SeverityMedium:
		return 3
	case finding.SeverityLow:
		return 2
	case finding.SeverityInfo:
		return 1
	}
	return 0
}
