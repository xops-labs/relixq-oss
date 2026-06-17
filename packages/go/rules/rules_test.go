// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package rules

import (
	"os"
	"strings"
	"testing"
)

func TestLoadDir_findsAllRules(t *testing.T) {
	// The OSS rules tree lives at packages/go/rules-community.
	// Loading the real shipped pack here doubles as schema validation for
	// every community rule file.
	pack, err := LoadDir("../rules-community")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(pack.All) == 0 {
		t.Fatal("expected rules, got 0")
	}
	wantLangs := []string{"csharp", "python", "javascript", "go", "any"}
	for _, l := range wantLangs {
		if len(pack.ForLanguage(l)) == 0 {
			t.Errorf("expected rules for language %q", l)
		}
	}
}

func TestLoadBytes_listForm(t *testing.T) {
	yaml := []byte(`
- id: TEST_RULE_REGEX
  language: csharp
  category: weak-hash
  severity: high
  algorithm: SHA1
  detector:
    type: regex
    pattern: 'SHA1\.Create'
`)
	rules, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "TEST_RULE_REGEX" {
		t.Fatalf("unexpected rules: %+v", rules)
	}
	if rules[0].Compiled() == nil {
		t.Fatal("regex was not compiled")
	}
}

func TestLoadBytes_invalidSeverityRejected(t *testing.T) {
	yaml := []byte(`
- id: TEST_BAD
  language: csharp
  severity: super-bad
  detector: { type: regex, pattern: 'x' }
`)
	if _, err := LoadBytes(yaml); err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestLoadBytes_invalidRegexRejected(t *testing.T) {
	yaml := []byte(`
- id: TEST_BAD_REGEX
  language: csharp
  severity: high
  detector: { type: regex, pattern: '[broken' }
`)
	if _, err := LoadBytes(yaml); err == nil {
		t.Fatal("expected regex compile error")
	}
}

func TestLoadBytes_astWithoutQueryRejected(t *testing.T) {
	yaml := []byte(`
- id: TEST_AST_NO_QUERY
  language: csharp
  severity: high
  detector: { type: ast }
`)
	if _, err := LoadBytes(yaml); err == nil {
		t.Fatal("expected error for ast detector missing query")
	}
}

func TestForLanguage_includesAny(t *testing.T) {
	yaml := []byte(`
- id: ANY_RULE
  language: any
  severity: low
  detector: { type: regex, pattern: 'BEGIN' }
- id: CS_RULE
  language: csharp
  severity: high
  detector: { type: regex, pattern: 'RSA\.Create' }
`)
	rules, err := LoadBytes(yaml)
	if err != nil {
		t.Fatal(err)
	}
	pack := &Pack{byLanguage: map[string][]*Rule{}}
	for _, r := range rules {
		pack.byLanguage[r.Language] = append(pack.byLanguage[r.Language], r)
	}
	got := pack.ForLanguage("csharp")
	if len(got) != 2 {
		t.Fatalf("expected 2 rules (cs + any), got %d", len(got))
	}
}

// TestRuleExamples runs every rule's inline examples as self-tests: each
// examples.match line must trigger the rule's regex detector and each
// examples.no_match line must not. AST rules cannot be executed here (no
// Tree-sitter in this package), so their example lines are only required to
// be non-empty.
func TestRuleExamples(t *testing.T) {
	pack, err := LoadDir("../rules-community")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	for _, r := range pack.All {
		if r.Examples == nil {
			continue
		}
		switch r.Detector.Type {
		case DetectorRegex:
			rx := r.Compiled()
			if rx == nil {
				t.Errorf("rule %s: regex detector has no compiled pattern", r.ID)
				continue
			}
			for _, line := range r.Examples.Match {
				if !rx.MatchString(line) {
					t.Errorf("rule %s: examples.match line did NOT match the detector pattern: %q", r.ID, line)
				}
			}
			for _, line := range r.Examples.NoMatch {
				if rx.MatchString(line) {
					t.Errorf("rule %s: examples.no_match line MATCHED the detector pattern: %q", r.ID, line)
				}
			}
		case DetectorAST:
			for _, line := range r.Examples.Match {
				if strings.TrimSpace(line) == "" {
					t.Errorf("rule %s: examples.match contains an empty line", r.ID)
				}
			}
			for _, line := range r.Examples.NoMatch {
				if strings.TrimSpace(line) == "" {
					t.Errorf("rule %s: examples.no_match contains an empty line", r.ID)
				}
			}
		}
	}
}

// TestRuleExamplesRatchet enforces examples coverage as a one-way ratchet.
// examples_baseline.txt is the frozen grandfather list of regex rules that
// predate the examples requirement: a regex rule without complete examples
// (>=1 match and >=1 no_match) must be on the baseline, a baselined rule
// that gains complete examples must be removed from the baseline, and the
// baseline may not reference rule IDs that no longer exist.
func TestRuleExamplesRatchet(t *testing.T) {
	pack, err := LoadDir("../rules-community")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	data, err := os.ReadFile("examples_baseline.txt")
	if err != nil {
		t.Fatalf("read examples_baseline.txt: %v", err)
	}
	baseline := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		baseline[line] = true
	}
	known := map[string]bool{}
	for _, r := range pack.All {
		known[r.ID] = true
		if r.Detector.Type != DetectorRegex {
			continue
		}
		complete := r.Examples != nil && len(r.Examples.Match) > 0 && len(r.Examples.NoMatch) > 0
		if !complete && !baseline[r.ID] {
			t.Errorf("rule %s: regex rule has no complete examples (needs >=1 match and >=1 no_match) and is not in examples_baseline.txt — write examples for it", r.ID)
		}
		if complete && baseline[r.ID] {
			t.Errorf("rule %s: has complete examples but is still listed in examples_baseline.txt — remove from baseline", r.ID)
		}
	}
	for id := range baseline {
		if !known[id] {
			t.Errorf("examples_baseline.txt lists rule id %s which does not exist in ../rules-community", id)
		}
	}
}
