// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunDeps_FlagsKnownWeakPackages(t *testing.T) {
	dir := t.TempDir()
	manifest := "pycrypto==2.6.1\necdsa>=0.18\nflask==3.0.0\n" // flask: not crypto, no finding
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := RunDeps(dir)
	if err != nil {
		t.Fatalf("RunDeps: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected dependency findings, got none")
	}

	// Conversion to the CLI model shape must preserve the key fields.
	var sawEcdsa bool
	for _, f := range findings {
		if f.RuleID == "" || f.Severity == "" || f.FilePath == "" {
			t.Errorf("finding missing core fields: %+v", f)
		}
		if f.UsageType != "dependency" {
			t.Errorf("dep finding usage_type = %q, want dependency", f.UsageType)
		}
		if f.Algorithm == "ECDSA" {
			sawEcdsa = true
			if f.QuantumSafety != "vulnerable" {
				t.Errorf("ecdsa quantum_safety = %q, want vulnerable", f.QuantumSafety)
			}
		}
	}
	if !sawEcdsa {
		t.Error("expected an ECDSA finding from the ecdsa package")
	}
}
