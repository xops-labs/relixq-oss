// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/relix-q/relix-q/cmd/relixq/internal/client"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/formatter"
	"github.com/spf13/cobra"
)

var remoteScanCmd = &cobra.Command{
	Use:   "remote-scan",
	Short: "Trigger a server-side scan and tail progress",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		waitFlag, _ := cmd.Flags().GetBool("wait")

		project := cfg.Project
		if project == "" {
			return fmt.Errorf("no project set — run: relixq use <project-slug>")
		}

		c := client.New(cfg.Remote.APIURL)
		run, err := c.CreateScan(client.CreateScanRequest{ProjectSlug: project})
		if err != nil {
			return fmt.Errorf("remote-scan: %w", err)
		}

		if !quietFlag {
			fmt.Printf("Scan started: %s\n", run.ScanRunID)
		}

		if !waitFlag {
			fmt.Printf("Track progress: relixq report --scan-id %s\n", run.ScanRunID)
			return nil
		}

		// Poll until the scan reaches a terminal state.
		for {
			time.Sleep(3 * time.Second)
			run, err = c.GetScan(run.ScanRunID)
			if err != nil {
				return err
			}
			if !quietFlag {
				fmt.Printf("\r  status: %-12s  progress: %3d%%", run.Status, run.Progress)
			}
			switch run.Status {
			case "completed", "failed", "cancelled":
				fmt.Println()
				goto done
			}
		}
	done:
		if run.Status != "completed" {
			return fmt.Errorf("scan %s finished with status %q", run.ScanRunID, run.Status)
		}

		findings, err := c.GetFindings(run.ScanRunID)
		if err != nil {
			return err
		}

		useColor := !noColorFlag && isTerminal(os.Stdout)
		return formatter.Write(cfg.Output.Format, findings, os.Stdout, useColor, quietFlag)
	},
}

func init() {
	remoteScanCmd.Flags().Bool("wait", false, "Block until the scan completes and print findings")
	rootCmd.AddCommand(remoteScanCmd)
}
