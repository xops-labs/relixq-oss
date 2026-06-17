// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// sampleFindings returns a small fixture used across formatter tests.
func sampleFindings() []model.Finding {
	keySize := 2048
	return []model.Finding{
		{
			RuleID:         "GO_RSA_GENERATE_KEY",
			Algorithm:      "RSA",
			UsageType:      "key_generation",
			QuantumSafety:  "vulnerable",
			KeySize:        &keySize,
			FilePath:       "internal/auth/keys.go",
			LineNumber:     42,
			Severity:       "critical",
			Confidence:     0.97,
			Message:        "crypto/rsa.GenerateKey — RSA is quantum-vulnerable.",
			Recommendation: "Migrate to ML-KEM (FIPS 203).",
			CWE:            []int{327},
		},
		{
			RuleID:        "GO_SHA1_NEW",
			Algorithm:     "SHA1",
			UsageType:     "hashing",
			QuantumSafety: "vulnerable",
			FilePath:      "internal/hash/legacy.go",
			LineNumber:    7,
			Severity:      "high",
			Confidence:    0.97,
			Message:       "SHA-1 is cryptographically broken.",
		},
	}
}

func TestWrite_DispatchUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Write("xml", sampleFindings(), &buf, false, false)
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "xml") {
		t.Fatalf("error should mention the bad format name; got %v", err)
	}
}

func TestWrite_DispatchKnownFormats(t *testing.T) {
	cases := []string{"text", "", "json", "jsonl", "sarif", "markdown", "md", "html"}
	for _, fmtName := range cases {
		t.Run("format="+fmtName, func(t *testing.T) {
			var buf bytes.Buffer
			err := Write(fmtName, sampleFindings(), &buf, false, false)
			if err != nil {
				t.Fatalf("format %q: unexpected error %v", fmtName, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("format %q: empty output", fmtName)
			}
		})
	}
}
