// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/relix-q/relix-q/cmd/relixq/internal/client"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Download a report for a completed scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID, _ := cmd.Flags().GetString("scan-id")
		if scanID == "" {
			return fmt.Errorf("--scan-id is required")
		}

		cfg, _ := config.Load(".")
		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = cfg.Output.Format
		}
		outFile, _ := cmd.Flags().GetString("output")

		c := client.New(cfg.Remote.APIURL)
		body, err := c.GetReport(scanID, format)
		if err != nil {
			return err
		}
		defer body.Close()

		out := os.Stdout
		if outFile != "" {
			f, err := os.Create(outFile)
			if err != nil {
				return fmt.Errorf("cannot open output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		if _, err := io.Copy(out, body); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		return nil
	},
}

func init() {
	reportCmd.Flags().String("scan-id", "", "Scan run ID to download the report for")
	reportCmd.Flags().String("format", "", "Report format (markdown|sarif|json|html)")
	reportCmd.Flags().StringP("output", "o", "", "Write report to file instead of stdout")
	rootCmd.AddCommand(reportCmd)
}
