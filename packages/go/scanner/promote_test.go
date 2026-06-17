// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"math"
	"testing"

	"github.com/relix-q/relix-q/finding"
)

// sig builds a raw promotion-eligible signal finding for the table tests.
func sig(ruleID, category, algorithm string, qs finding.QuantumSafety, conf float64, line int) *finding.Finding {
	return &finding.Finding{
		ScanJobID:     "job-1",
		RuleID:        ruleID,
		Language:      "python",
		Algorithm:     algorithm,
		QuantumSafety: qs,
		Severity:      finding.SeverityLow,
		FilePath:      "src/x.py",
		LineNumber:    line,
		Confidence:    conf,
		Category:      category,
	}
}

func TestPromoteHandrolled(t *testing.T) {
	const eps = 1e-9

	tests := []struct {
		name     string
		in       []*finding.Finding
		wantN    int
		wantRule string
		wantAlg  string
		wantConf float64
		wantQS   finding.QuantumSafety
		wantLine int
	}{
		{
			name:  "single signal does not promote",
			in:    []*finding.Finding{sig("PYTHON_HANDROLLED_RSA", "handrolled-crypto", "RSA", finding.QuantumVulnerable, 0.4, 14)},
			wantN: 0,
		},
		{
			name: "two distinct same-algorithm rules promote with fused confidence",
			in: []*finding.Finding{
				sig("PYTHON_HANDROLLED_RSA", "handrolled-crypto", "RSA", finding.QuantumVulnerable, 0.4, 14),
				sig("CRYPTO_FP_RSA_PUBLIC_EXPONENT", "crypto-fingerprint", "RSA", finding.QuantumVulnerable, 0.35, 37),
			},
			wantN:    1,
			wantRule: "HANDROLLED_RSA_PROMOTED",
			wantAlg:  "RSA",
			wantConf: 1 - (1-0.4)*(1-0.35), // 0.61
			wantQS:   finding.QuantumVulnerable,
			wantLine: 14, // first signal's line
		},
		{
			name: "two different algorithms do not promote",
			in: []*finding.Finding{
				sig("CRYPTO_FP_AES_SBOX", "crypto-fingerprint", "AES", finding.GroverWeakened, 0.9, 4),
				sig("CRYPTO_FP_MD5_SINE", "crypto-fingerprint", "MD5", finding.ClassicallyBroken, 0.9, 20),
			},
			wantN: 0,
		},
		{
			name: "same rule firing twice is one signal, not corroboration",
			in: []*finding.Finding{
				sig("CRYPTO_FP_RSA_PUBLIC_EXPONENT", "crypto-fingerprint", "RSA", finding.QuantumVulnerable, 0.35, 7),
				sig("CRYPTO_FP_RSA_PUBLIC_EXPONENT", "crypto-fingerprint", "RSA", finding.QuantumVulnerable, 0.35, 28),
			},
			wantN: 0,
		},
		{
			name: "promoted finding never re-feeds promotion",
			in: []*finding.Finding{
				sig("PYTHON_HANDROLLED_RSA", "handrolled-crypto", "RSA", finding.QuantumVulnerable, 0.4, 14),
				func() *finding.Finding {
					f := sig("HANDROLLED_RSA_PROMOTED", "handrolled-crypto", "RSA", finding.QuantumVulnerable, 0.61, 14)
					f.UsageType = "handrolled"
					return f
				}(),
			},
			wantN: 0,
		},
		{
			name: "fused confidence is capped at 0.95",
			in: []*finding.Finding{
				sig("CRYPTO_FP_AES_SBOX", "crypto-fingerprint", "AES", finding.GroverWeakened, 0.9, 4),
				sig("CRYPTO_FP_AES_INV_SBOX", "crypto-fingerprint", "AES", finding.GroverWeakened, 0.9, 11),
			},
			wantN:    1,
			wantRule: "HANDROLLED_AES_PROMOTED",
			wantAlg:  "AES",
			wantConf: 0.95, // 1 - 0.1*0.1 = 0.99 → cap
			wantQS:   finding.GroverWeakened,
			wantLine: 4,
		},
		{
			name: "algorithm punctuation folds (SHA-256 == SHA256) and shapes the rule id",
			in: []*finding.Finding{
				sig("CRYPTO_FP_SHA256_K", "crypto-fingerprint", "SHA-256", finding.GroverWeakened, 0.9, 5),
				sig("CRYPTO_FP_SHA256_IV", "crypto-fingerprint", "SHA256", finding.GroverWeakened, 0.85, 10),
			},
			wantN:    1,
			wantRule: "HANDROLLED_SHA256_PROMOTED",
			wantAlg:  "SHA-256", // dominant (highest-confidence) signal's label
			wantConf: 0.95,     // 1 - 0.1*0.15 = 0.985 → cap
			wantQS:   finding.GroverWeakened,
			wantLine: 5,
		},
		{
			name: "modexp family fold: RSA-labeled modexp corroborates a DH fingerprint",
			in: []*finding.Finding{
				sig("CRYPTO_FP_MODP_PRIME", "crypto-fingerprint", "DH", finding.QuantumVulnerable, 0.95, 9),
				sig("GO_BIGINT_MODEXP", "handrolled-crypto", "RSA", finding.QuantumVulnerable, 0.35, 21),
			},
			wantN:    1,
			wantRule: "HANDROLLED_DH_PROMOTED", // dominant signal (MODP, 0.95) wins the label
			wantAlg:  "DH",
			wantConf: 0.95, // 1 - 0.05*0.65 = 0.9675 → cap
			wantQS:   finding.QuantumVulnerable,
			wantLine: 9,
		},
		{
			name: "non-eligible categories are ignored even when algorithms agree",
			in: []*finding.Finding{
				sig("PYTHON_RSA_GENERATE", "crypto-api", "RSA", finding.QuantumVulnerable, 0.95, 7),
				sig("CRYPTO_FP_RSA_PUBLIC_EXPONENT", "crypto-fingerprint", "RSA", finding.QuantumVulnerable, 0.35, 7),
			},
			wantN: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := promoteHandrolled(tc.in)
			if len(got) != tc.wantN {
				t.Fatalf("promoted %d findings, want %d: %+v", len(got), tc.wantN, got)
			}
			if tc.wantN == 0 {
				return
			}
			p := got[0]
			if p.RuleID != tc.wantRule {
				t.Errorf("rule id = %q, want %q", p.RuleID, tc.wantRule)
			}
			if p.Algorithm != tc.wantAlg {
				t.Errorf("algorithm = %q, want %q", p.Algorithm, tc.wantAlg)
			}
			if math.Abs(p.Confidence-tc.wantConf) > eps {
				t.Errorf("confidence = %v, want %v", p.Confidence, tc.wantConf)
			}
			if p.QuantumSafety != tc.wantQS {
				t.Errorf("quantum_safety = %q, want %q", p.QuantumSafety, tc.wantQS)
			}
			if p.Severity != finding.SeverityHigh {
				t.Errorf("severity = %q, want high", p.Severity)
			}
			if p.LineNumber != tc.wantLine {
				t.Errorf("line = %d, want %d", p.LineNumber, tc.wantLine)
			}
			if p.UsageType != "handrolled" {
				t.Errorf("usage_type = %q, want handrolled", p.UsageType)
			}
			if p.Category != "handrolled-crypto" {
				t.Errorf("category = %q, want handrolled-crypto", p.Category)
			}
			// A promoted finding must be inert as promotion input.
			if again := promoteHandrolled(append(tc.in, got...)); len(again) != tc.wantN {
				t.Errorf("re-running promotion with promoted output included changed the result: %d findings", len(again))
			}
		})
	}
}
