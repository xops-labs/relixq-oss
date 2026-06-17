// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	quietFlag   bool
	noColorFlag bool
)

var rootCmd = &cobra.Command{
	Use:          "relixq",
	Short:        "Relix-Q: post-quantum crypto risk scanner",
	Long:         `relixq scans your codebase for quantum-vulnerable cryptography and reports PQC readiness.`,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "Suppress non-essential output")
	rootCmd.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "Disable ANSI colors")
}
