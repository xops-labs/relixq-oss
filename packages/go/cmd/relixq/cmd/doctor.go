// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/scanner"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose environment and configuration issues",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, cfgErr := config.Load(".")

		allOK := true
		check := func(label string, pass bool, hint string) {
			if pass {
				fmt.Printf("  ✓  %s\n", label)
			} else {
				fmt.Printf("  ✗  %s\n      hint: %s\n", label, hint)
				allOK = false
			}
		}

		fmt.Println("relixq doctor")
		fmt.Println()

		_, gitErr := exec.LookPath("git")
		check("git available", gitErr == nil, "install git and ensure it is on PATH")

		check("relixq.yaml valid", cfgErr == nil, fmt.Sprintf("%v", cfgErr))

		// Same precedence the scan path uses: env/config first, then the
		// rules bundled with a release install next to the executable.
		ruleDir := ""
		if cfg != nil && cfg.Scan.RuleDir != "" {
			ruleDir = cfg.Scan.RuleDir
		}
		if v := os.Getenv("RELIXQ_RULE_DIR"); v != "" {
			ruleDir = v
		}
		if ruleDir == "" {
			ruleDir = scanner.BundledRuleDir()
		}
		statErr := os.ErrNotExist
		if ruleDir != "" {
			_, statErr = os.Stat(ruleDir)
		}
		check("rule pack directory found", statErr == nil,
			"keep the bundled rules/ folder next to the relixq executable or set RELIXQ_RULE_DIR")

		apiURL := "https://api.relixq.io"
		if cfg != nil && cfg.Remote.APIURL != "" {
			apiURL = cfg.Remote.APIURL
		}
		hc := &http.Client{Timeout: 5 * time.Second}
		resp, httpErr := hc.Get(apiURL + "/health")
		if httpErr == nil {
			resp.Body.Close()
		}
		check("platform API reachable", httpErr == nil,
			fmt.Sprintf("cannot reach %s — check network or set RELIXQ_API_URL", apiURL))

		_, binErr := scanner.ResolveScannerBin()
		check("scanner binary available", binErr == nil,
			"keep relixq-scan-code next to the relixq executable, install it on PATH, or set RELIXQ_SCANNER_BIN")

		fmt.Println()
		if allOK {
			fmt.Println("All checks passed.")
			return nil
		}
		fmt.Println("Some checks failed. Fix the issues above and re-run relixq doctor.")
		return fmt.Errorf("doctor found issues")
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
