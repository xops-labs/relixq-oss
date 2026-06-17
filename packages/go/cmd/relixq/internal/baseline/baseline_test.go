// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

func sample() []model.Finding {
	return []model.Finding{
		{RuleID: "CSHARP_DSA_CREATE", FilePath: "Services/Sig.cs", LineNumber: 15, Snippet: "DSA.Create(2048)", Severity: "high"},
		{RuleID: "CSHARP_DSA_CREATE", FilePath: "Services/Sig.cs", LineNumber: 22, Snippet: "new DSACryptoServiceProvider()", Severity: "high"},
		{RuleID: "CSHARP_RSA_KEYSIZE_WEAK", FilePath: "Services/Rsa.cs", LineNumber: 9, Snippet: "RSA.Create(1024)", Severity: "high"},
	}
}

func TestRoundTripAndFilter(t *testing.T) {
	findings := sample()
	b := FromFindings(findings)
	if len(b.Findings) != 3 {
		t.Fatalf("expected 3 baseline entries, got %d", len(b.Findings))
	}

	path := filepath.Join(t.TempDir(), DefaultFile)
	if err := b.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// All baselined findings are suppressed; nothing new.
	newF, suppressed := loaded.Filter(findings)
	if suppressed != 3 || len(newF) != 0 {
		t.Fatalf("expected all 3 suppressed, got suppressed=%d new=%d", suppressed, len(newF))
	}

	// A new finding (different snippet) is reported; line-number drift on an
	// existing one is still suppressed (fingerprint keys on snippet, not line).
	drifted := findings[0]
	drifted.LineNumber = 999 // moved, same snippet
	added := model.Finding{RuleID: "GO_RSA_GENERATE_KEY", FilePath: "main.go", LineNumber: 3, Snippet: "rsa.GenerateKey(rand.Reader, 2048)", Severity: "critical"}
	newF, suppressed = loaded.Filter([]model.Finding{drifted, added})
	if suppressed != 1 {
		t.Fatalf("line-drifted finding should stay suppressed; suppressed=%d", suppressed)
	}
	if len(newF) != 1 || newF[0].RuleID != "GO_RSA_GENERATE_KEY" {
		t.Fatalf("expected only the genuinely new finding reported, got %+v", newF)
	}
}

func TestLoad_MissingFileErrors(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist error for missing baseline, got %v", err)
	}
}

func TestFromFindings_DedupesByFingerprint(t *testing.T) {
	f := model.Finding{RuleID: "X", FilePath: "a.cs", LineNumber: 1, Snippet: "same"}
	b := FromFindings([]model.Finding{f, f, f})
	if len(b.Findings) != 1 {
		t.Fatalf("expected dedup to 1 entry, got %d", len(b.Findings))
	}
}
