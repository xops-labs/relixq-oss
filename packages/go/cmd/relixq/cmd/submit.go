// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/relix-q/relix-q/cmd/relixq/internal/client"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
	"github.com/spf13/cobra"
)

var submitCmd = &cobra.Command{
	Use:   "submit [findings.jsonl]",
	Short: "Upload local scan results to the platform",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")

		var findings []model.Finding
		if len(args) == 1 {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				var finding model.Finding
				if err := json.Unmarshal(sc.Bytes(), &finding); err != nil {
					return fmt.Errorf("parse %s: %w", args[0], err)
				}
				findings = append(findings, finding)
			}
		} else {
			// Read JSONL from stdin.
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				var finding model.Finding
				if err := json.Unmarshal(sc.Bytes(), &finding); err != nil {
					return fmt.Errorf("parse stdin: %w", err)
				}
				findings = append(findings, finding)
			}
		}

		body, _ := json.Marshal(findings)
		c := client.New(cfg.Remote.APIURL)
		resp, err := c.Post("/findings/ingest", bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if !quietFlag {
			fmt.Printf("Submitted %d finding(s) to %s\n", len(findings), cfg.Remote.APIURL)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(submitCmd)
}
