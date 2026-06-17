// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"os"

	"github.com/relix-q/relix-q/cmd/relixq/internal/baseline"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/formatter"
	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
	"github.com/relix-q/relix-q/cmd/relixq/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a path for quantum-vulnerable cryptography",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	cfg, _ := config.Load(path)
	applyOutputFlags(cmd, cfg)

	diffRef, _ := cmd.Flags().GetString("diff")
	rulesOverride, _ := cmd.Flags().GetString("rules")

	scanPaths := cfg.Scan.Paths
	if len(scanPaths) == 0 {
		scanPaths = []string{path}
	}

	if diffRef != "" {
		changed, err := scanner.ChangedFiles(path, diffRef)
		if err != nil {
			return fmt.Errorf("--diff: %w", err)
		}
		if len(changed) == 0 {
			if !quietFlag {
				fmt.Fprintln(os.Stderr, "relixq scan: no changed files vs", diffRef)
			}
			return nil
		}
		scanPaths = changed
	}

	findings, err := scanner.RunLocal(scanPaths, cfg.Scan.Exclude, rulesOverride, cfg.Scan.RuleDir)
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	return emitFindings(cmd, cfg, findings)
}

// applyOutputFlags overlays the shared output/threshold CLI flags onto the
// loaded config (flag > env > yaml > default). Used by `scan` and `scan deps`.
func applyOutputFlags(cmd *cobra.Command, cfg *config.Config) {
	if cmd.Flags().Changed("format") {
		cfg.Output.Format, _ = cmd.Flags().GetString("format")
	}
	if cmd.Flags().Changed("output") {
		cfg.Output.File, _ = cmd.Flags().GetString("output")
	}
	if cmd.Flags().Changed("severity-threshold") {
		cfg.Scan.SeverityThreshold, _ = cmd.Flags().GetString("severity-threshold")
	}
	if cmd.Flags().Changed("exit-on") {
		cfg.Scan.ExitOn, _ = cmd.Flags().GetString("exit-on")
	}
}

// emitFindings applies the severity threshold, optional baseline suppression,
// writes the findings in the configured format, and exits non-zero when a
// finding meets the exit-on severity. Shared by `scan` and `scan deps` so both
// surfaces behave identically for CI.
func emitFindings(cmd *cobra.Command, cfg *config.Config, findings []model.Finding) error {
	threshold := model.SeverityOrder[cfg.Scan.SeverityThreshold]
	var filtered []model.Finding
	for _, f := range findings {
		if model.SeverityOrder[f.Severity] >= threshold {
			filtered = append(filtered, f)
		}
	}

	if baselineFile, _ := cmd.Flags().GetString("baseline"); baselineFile != "" {
		b, err := baseline.Load(baselineFile)
		if err != nil {
			return fmt.Errorf("--baseline: %w", err)
		}
		newFindings, suppressed := b.Filter(filtered)
		filtered = newFindings
		if !quietFlag && suppressed > 0 {
			fmt.Fprintf(os.Stderr, "relixq: %d finding(s) suppressed by baseline %s\n", suppressed, baselineFile)
		}
	}

	out := os.Stdout
	if cfg.Output.File != "" {
		f, err := os.Create(cfg.Output.File)
		if err != nil {
			return fmt.Errorf("cannot open output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	useColor := !noColorFlag && isTerminal(os.Stdout)
	if err := formatter.Write(cfg.Output.Format, filtered, out, useColor, quietFlag); err != nil {
		return err
	}

	exitLevel := model.SeverityOrder[cfg.Scan.ExitOn]
	for _, f := range filtered {
		if model.SeverityOrder[f.Severity] >= exitLevel {
			os.Exit(1)
		}
	}
	return nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func init() {
	scanCmd.Flags().String("format", "text", "Output format: text|json|jsonl|sarif|markdown|html")
	scanCmd.Flags().StringP("output", "o", "", "Write output to file instead of stdout")
	scanCmd.Flags().String("severity-threshold", "", "Filter findings below this severity (info|low|medium|high|critical)")
	scanCmd.Flags().String("exit-on", "", "Exit 1 if any finding meets or exceeds this severity")
	scanCmd.Flags().String("diff", "", "Scan only files changed since this git ref")
	scanCmd.Flags().String("rules", "", "Rule source override (directory path or @pack-name)")
	scanCmd.Flags().String("baseline", "", "Suppress findings recorded in this baseline file; report only new ones (see `relixq baseline`)")
	rootCmd.AddCommand(scanCmd)
}
