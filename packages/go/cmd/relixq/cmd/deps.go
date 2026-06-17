// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"

	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/scanner"
	"github.com/spf13/cobra"
)

var depsCmd = &cobra.Command{
	Use:   "deps [path]",
	Short: "Scan dependency manifests for quantum-vulnerable crypto libraries",
	Long: `deps walks a project's dependency manifests — requirements.txt, Pipfile,
pyproject.toml, package.json, go.mod — and flags declared packages known to
implement quantum-vulnerable cryptography, using an embedded knowledge base.
No network or lockfile resolution is required; it reads what the manifests pin.

Findings flow through the same --format / --severity-threshold / --baseline
pipeline as 'relixq scan', so 'relixq scan deps --format sarif' uploads to CI.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDeps,
}

func runDeps(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	cfg, _ := config.Load(path)
	applyOutputFlags(cmd, cfg)

	findings, err := scanner.RunDeps(path)
	if err != nil {
		return fmt.Errorf("dep scan: %w", err)
	}
	return emitFindings(cmd, cfg, findings)
}

func init() {
	depsCmd.Flags().String("format", "text", "Output format: text|json|jsonl|sarif|markdown|html")
	depsCmd.Flags().StringP("output", "o", "", "Write output to file instead of stdout")
	depsCmd.Flags().String("severity-threshold", "", "Filter findings below this severity (info|low|medium|high|critical)")
	depsCmd.Flags().String("exit-on", "", "Exit 1 if any finding meets or exceeds this severity")
	depsCmd.Flags().String("baseline", "", "Suppress findings recorded in this baseline file; report only new ones")
	scanCmd.AddCommand(depsCmd)
}
