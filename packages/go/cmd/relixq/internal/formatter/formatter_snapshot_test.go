// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// updateGoldens, when set, rewrites the testdata/fixture.* files instead of
// comparing against them. Run `go test -update ./internal/formatter/` after
// an intentional formatter change to refresh the snapshots.
var updateGoldens = flag.Bool("update", false, "rewrite golden files in testdata/")

// snapshotFixture is a deliberately diverse finding set so the goldens
// exercise mixed severities, algorithms, languages, and optional fields.
// Five findings keeps each golden small (<2 KB) while still covering the
// branches every formatter has (counts table, severity grouping, optional
// snippet / recommendation rendering).
func snapshotFixture() []model.Finding {
	rsaKey := 2048
	aesKey := 128
	ecdsaKey := 256
	mlkem := 768
	return []model.Finding{
		{
			RuleID:         "GO_RSA_GENERATE_KEY",
			Algorithm:      "RSA",
			UsageType:      "key_generation",
			QuantumSafety:  "vulnerable",
			KeySize:        &rsaKey,
			FilePath:       "services/auth/keys.go",
			LineNumber:     42,
			Severity:       "critical",
			Confidence:     0.97,
			Snippet:        "rsa.GenerateKey(rand.Reader, 2048)",
			Message:        "crypto/rsa.GenerateKey produces a quantum-vulnerable key pair.",
			Recommendation: "Migrate to ML-KEM (FIPS 203) or a hybrid X25519+ML-KEM construction.",
			References:     []string{"https://csrc.nist.gov/pubs/fips/203/final"},
			CWE:            []int{327},
		},
		{
			RuleID:         "PY_AES_ECB_MODE",
			Algorithm:      "AES",
			UsageType:      "encryption",
			QuantumSafety:  "vulnerable",
			KeySize:        &aesKey,
			FilePath:       "apps/web/crypto/legacy.py",
			LineNumber:     113,
			Severity:       "high",
			Confidence:     0.92,
			Snippet:        "Cipher(algorithms.AES(key), modes.ECB())",
			Message:        "AES in ECB mode leaks plaintext structure and is not IND-CPA secure.",
			Recommendation: "Use AES-GCM with a 256-bit key, and plan for ML-KEM-derived keys.",
			CWE:            []int{327, 696},
		},
		{
			RuleID:        "CSHARP_SHA1_CREATE",
			Algorithm:     "SHA1",
			UsageType:     "hashing",
			QuantumSafety: "vulnerable",
			FilePath:      "services/billing/Hashing.cs",
			LineNumber:    27,
			Severity:      "medium",
			Confidence:    0.99,
			Snippet:       "SHA1.Create()",
			Message:       "SHA-1 is broken against collision attacks; quantum reduces its effective security further.",
		},
		{
			RuleID:        "JAVA_ECDSA_P256_SIGN",
			Algorithm:     "ECDSA-P256",
			UsageType:     "digital_signature",
			QuantumSafety: "vulnerable",
			KeySize:       &ecdsaKey,
			FilePath:      "services/identity/src/main/java/com/relixq/Signer.java",
			LineNumber:    88,
			Severity:      "low",
			Confidence:    0.85,
			Message:       "ECDSA over P-256 is vulnerable to Shor's algorithm on a CRQC.",
		},
		{
			RuleID:        "RUST_MLKEM_KEYGEN",
			Algorithm:     "ML-KEM-768",
			UsageType:     "key_generation",
			QuantumSafety: "quantum_safe",
			KeySize:       &mlkem,
			FilePath:      "workers/pqc-bridge/src/kem.rs",
			LineNumber:    14,
			Severity:      "info",
			Confidence:    1.0,
			Message:       "ML-KEM-768 keypair generation; recorded for inventory.",
		},
	}
}

// snapshotCases enumerates the formats we lock down via golden files.
// Each case writes through the same Write dispatcher the CLI uses in
// production so the snapshot covers the wire shape, not just one helper.
var snapshotCases = []struct {
	name   string
	format string
	golden string
}{
	{"json", "json", "fixture.json"},
	{"sarif", "sarif", "fixture.sarif"},
	{"text", "text", "fixture.txt"},
}

func TestFormatterGoldens(t *testing.T) {
	for _, tc := range snapshotCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			// color=false to keep text golden free of ANSI escapes;
			// quiet=false so the summary line is exercised.
			if err := Write(tc.format, snapshotFixture(), &buf, false, false); err != nil {
				t.Fatalf("Write(%s): %v", tc.format, err)
			}
			got := buf.Bytes()
			path := filepath.Join("testdata", tc.golden)

			if *updateGoldens {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatalf("mkdir testdata: %v", err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatalf("write golden %s: %v", path, err)
				}
				t.Logf("updated %s (%d bytes)", path, len(got))
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (run `go test -update ./internal/formatter/` to create it)", path, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch for %s.\n--- want (%d bytes) ---\n%s\n--- got (%d bytes) ---\n%s\n--- end ---\nRun `go test -update ./internal/formatter/` if the change is intentional.",
					tc.golden, len(want), string(want), len(got), string(got))
			}
		})
	}
}
