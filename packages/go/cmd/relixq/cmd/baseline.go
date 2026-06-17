// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"os"

	"github.com/relix-q/relix-q/cmd/relixq/internal/baseline"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/scanner"
	"github.com/spf13/cobra"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline [path]",
	Short: "Record current findings as an accepted baseline",
	Long: `baseline scans a path and writes every current finding to a baseline file.

A later 'relixq scan --baseline <file>' then reports only findings absent from
the baseline, so you can adopt the scanner on a legacy codebase and gate CI on
new quantum-vulnerable cryptography without drowning in the existing backlog.

Commit the baseline file so local scans and CI share the same accepted set.
Findings are matched by a content fingerprint (rule + file + snippet) that is
resilient to line-number drift.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBaseline,
}

func runBaseline(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	cfg, _ := config.Load(path)
	rulesOverride, _ := cmd.Flags().GetString("rules")
	file, _ := cmd.Flags().GetString("file")

	scanPaths := cfg.Scan.Paths
	if len(scanPaths) == 0 {
		scanPaths = []string{path}
	}

	findings, err := scanner.RunLocal(scanPaths, cfg.Scan.Exclude, rulesOverride, cfg.Scan.RuleDir)
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	b := baseline.FromFindings(findings)
	if err := b.Save(file); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	if !quietFlag {
		fmt.Fprintf(os.Stderr, "relixq baseline: recorded %d finding(s) to %s\n", len(b.Findings), file)
	}
	return nil
}

func init() {
	baselineCmd.Flags().String("file", baseline.DefaultFile, "Baseline file to write")
	baselineCmd.Flags().String("rules", "", "Rule source override (directory path or @pack-name)")
	rootCmd.AddCommand(baselineCmd)
}
