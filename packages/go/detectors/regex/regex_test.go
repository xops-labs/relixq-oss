// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package regex

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/rules"
)

func mustLoad(t *testing.T, yaml string) []*rules.Rule {
	t.Helper()
	r, err := rules.LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return r
}

func TestMatchFile_findsRsaCreate(t *testing.T) {
	rs := mustLoad(t, `
- id: CSHARP_RSA_CREATE
  language: csharp
  category: crypto-api
  severity: critical
  detector: { type: regex, pattern: '\bRSA\.Create\s*\(' }
`)
	src := `using System.Security.Cryptography;
namespace X {
    public class A {
        public RSA NewKey() { return RSA.Create(2048); }
    }
}`
	matches, err := MatchFile("a.cs", strings.NewReader(src), rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 4 {
		t.Errorf("expected line 4, got %d", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "RSA.Create") {
		t.Errorf("snippet missing RSA.Create: %q", matches[0].Snippet)
	}
	if len(matches[0].Context) == 0 {
		t.Error("expected snippet_context to be populated")
	}
}

func TestMatchFile_inlineSuppressionSkipsRule(t *testing.T) {
	rs := mustLoad(t, `
- id: SHA1
  language: csharp
  severity: high
  detector: { type: regex, pattern: 'SHA1\.Create' }
`)
	src := `// relixq-ignore: SHA1
using var sha = SHA1.Create();`
	matches, err := MatchFile("a.cs", strings.NewReader(src), rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected suppression, got %d matches", len(matches))
	}
}

func TestMatchFile_inlineSuppressionScopedDoesNotSilenceOthers(t *testing.T) {
	rs := mustLoad(t, `
- id: SHA1
  language: csharp
  severity: high
  detector: { type: regex, pattern: 'SHA1\.Create' }
- id: MD5
  language: csharp
  severity: high
  detector: { type: regex, pattern: 'MD5\.Create' }
`)
	src := `// relixq-ignore: SHA1
SHA1.Create(); MD5.Create();`
	matches, err := MatchFile("a.cs", strings.NewReader(src), rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Rule.ID != "MD5" {
		t.Fatalf("expected only MD5 to fire, got %+v", matches)
	}
}

func TestMatchFile_skipsBinaryContent(t *testing.T) {
	rs := mustLoad(t, `
- id: ANY
  language: any
  severity: low
  detector: { type: regex, pattern: 'X' }
`)
	bin := "\x00\x00\x00binary X content"
	matches, err := MatchFile("a.bin", strings.NewReader(bin), rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected binary to be skipped, got %d", len(matches))
	}
}

func TestMatchFile_fileGlobs(t *testing.T) {
	rs := mustLoad(t, `
- id: PEM_KEY
  language: any
  severity: critical
  file_globs: ["*.env"]
  detector: { type: regex, pattern: '-----BEGIN' }
`)
	src := "-----BEGIN RSA PRIVATE KEY-----"
	hitsEnv, _ := MatchFile("config/x.env", strings.NewReader(src), rs)
	hitsCs, _ := MatchFile("src/x.cs", strings.NewReader(src), rs)
	if len(hitsEnv) != 1 {
		t.Errorf("expected hit on .env, got %d", len(hitsEnv))
	}
	if len(hitsCs) != 0 {
		t.Errorf("expected no hits on .cs, got %d", len(hitsCs))
	}
}

func TestToFinding_populatesSchemaFields(t *testing.T) {
	rs := mustLoad(t, `
- id: CSHARP_RSA_CREATE
  language: csharp
  category: crypto-api
  severity: critical
  algorithm: RSA
  usage_type: key_generation
  detector: { type: regex, pattern: 'RSA\.Create' }
  message: hello
  recommendation: switch
  cwe: [327]
`)
	matches, _ := MatchFile("x.cs", strings.NewReader("RSA.Create();"), rs)
	if len(matches) != 1 {
		t.Fatalf("got %d matches", len(matches))
	}
	f := ToFinding("job-123", "x.cs", "csharp", matches[0])
	if f.RuleID != "CSHARP_RSA_CREATE" || f.Algorithm != "RSA" || f.Severity != "critical" {
		t.Errorf("unexpected finding fields: %+v", f)
	}
	if f.QuantumSafety != "vulnerable" {
		t.Errorf("expected vulnerable quantum_safety, got %q", f.QuantumSafety)
	}
}
