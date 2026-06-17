// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultsWhenNoYaml(t *testing.T) {
	// Use a temp dir with no relixq.yaml in it or any ancestor we can write to;
	// `findConfigFile` walks all the way up and fails when none exists, so the
	// loader falls through to defaults().
	dir := t.TempDir()

	// Make sure ambient env doesn't bleed into the test.
	t.Setenv("RELIXQ_API_URL", "")
	t.Setenv("RELIXQ_PROJECT", "")
	t.Setenv("RELIXQ_RULE_DIR", "")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("default Version = %d, want 1", cfg.Version)
	}
	if cfg.DefaultBranch != "main" {
		t.Fatalf("default branch = %q, want 'main'", cfg.DefaultBranch)
	}
	if cfg.Scan.SeverityThreshold != "medium" {
		t.Fatalf("default severity threshold = %q, want 'medium'", cfg.Scan.SeverityThreshold)
	}
	if cfg.Output.Format != "text" {
		t.Fatalf("default output format = %q, want 'text'", cfg.Output.Format)
	}
}

func TestLoad_YamlOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "relixq.yaml")
	yamlBody := `
version: 1
project: acme/payments
default_branch: develop
scan:
  severity_threshold: high
  exit_on: high
  rule_packs:
    - aws-pqc
    - go-pqc
output:
  format: sarif
remote:
  enabled: true
  api_url: https://relixq.example.com
`
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELIXQ_API_URL", "")
	t.Setenv("RELIXQ_PROJECT", "")
	t.Setenv("RELIXQ_RULE_DIR", "")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project != "acme/payments" {
		t.Fatalf("project = %q, want 'acme/payments'", cfg.Project)
	}
	if cfg.DefaultBranch != "develop" {
		t.Fatalf("default_branch = %q, want 'develop'", cfg.DefaultBranch)
	}
	if cfg.Scan.SeverityThreshold != "high" {
		t.Fatalf("severity_threshold = %q, want 'high'", cfg.Scan.SeverityThreshold)
	}
	if cfg.Output.Format != "sarif" {
		t.Fatalf("output format = %q, want 'sarif'", cfg.Output.Format)
	}
	if !cfg.Remote.Enabled || cfg.Remote.APIURL != "https://relixq.example.com" {
		t.Fatalf("remote not loaded correctly: %+v", cfg.Remote)
	}
	if len(cfg.Scan.RulePacks) != 2 {
		t.Fatalf("rule_packs not loaded: %+v", cfg.Scan.RulePacks)
	}
}

func TestLoad_EnvOverridesYaml(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
version: 1
project: from-yaml
remote:
  api_url: https://yaml.example.com
scan:
  rule_dir: /yaml/rules
`
	if err := os.WriteFile(filepath.Join(dir, "relixq.yaml"), []byte(yamlBody), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RELIXQ_API_URL", "https://env.example.com")
	t.Setenv("RELIXQ_PROJECT", "from-env")
	t.Setenv("RELIXQ_RULE_DIR", "/env/rules")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project != "from-env" {
		t.Fatalf("env should override yaml: got Project = %q", cfg.Project)
	}
	if cfg.Remote.APIURL != "https://env.example.com" {
		t.Fatalf("env should override yaml: got APIURL = %q", cfg.Remote.APIURL)
	}
	if cfg.Scan.RuleDir != "/env/rules" {
		t.Fatalf("env should override yaml: got RuleDir = %q", cfg.Scan.RuleDir)
	}
}

func TestLoad_WalksUpForYaml(t *testing.T) {
	root := t.TempDir()
	yamlBody := "version: 1\nproject: parent-project\n"
	if err := os.WriteFile(filepath.Join(root, "relixq.yaml"), []byte(yamlBody), 0o644); err != nil {
		t.Fatal(err)
	}

	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELIXQ_PROJECT", "")

	cfg, err := Load(deep)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project != "parent-project" {
		t.Fatalf("walk-up failed; got Project = %q", cfg.Project)
	}
}

func TestLoad_MalformedYamlSurfaceError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "relixq.yaml"), []byte(":\nthis is not valid yaml: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error on malformed yaml")
	}
}
