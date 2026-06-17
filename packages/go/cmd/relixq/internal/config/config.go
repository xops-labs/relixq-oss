// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version       int          `yaml:"version"`
	Project       string       `yaml:"project"`
	DefaultBranch string       `yaml:"default_branch"`
	Scan          ScanConfig   `yaml:"scan"`
	Output        OutputConfig `yaml:"output"`
	Remote        RemoteConfig `yaml:"remote"`
}

type ScanConfig struct {
	Paths             []string `yaml:"paths"`
	Exclude           []string `yaml:"exclude"`
	RulePacks         []string `yaml:"rule_packs"`
	SeverityThreshold string   `yaml:"severity_threshold"`
	ExitOn            string   `yaml:"exit_on"`
	RuleDir           string   `yaml:"rule_dir"`
}

type OutputConfig struct {
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

type RemoteConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIURL  string `yaml:"api_url"`
}

// Load walks up from dir searching for relixq.yaml, then applies env var overrides.
// Precedence: CLI flag (caller's responsibility) > env > yaml > built-in defaults.
func Load(dir string) (*Config, error) {
	cfg := defaults()

	path, err := findConfigFile(dir)
	if err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	applyEnv(cfg)
	return cfg, nil
}

func findConfigFile(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "relixq.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func defaults() *Config {
	return &Config{
		Version:       1,
		DefaultBranch: "main",
		Scan: ScanConfig{
			SeverityThreshold: "medium",
			ExitOn:            "critical",
		},
		Output: OutputConfig{Format: "text"},
		Remote: RemoteConfig{APIURL: "https://api.relixq.io"},
	}
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("RELIXQ_API_URL"); v != "" {
		cfg.Remote.APIURL = v
	}
	if v := os.Getenv("RELIXQ_PROJECT"); v != "" {
		cfg.Project = v
	}
	if v := os.Getenv("RELIXQ_RULE_DIR"); v != "" {
		cfg.Scan.RuleDir = v
	}
}
