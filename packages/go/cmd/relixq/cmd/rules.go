// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/relix-q/relix-q/cmd/relixq/internal/client"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage rule packs",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed and available rule packs",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		c := client.New(cfg.Remote.APIURL)
		resp, err := c.Get("/rules")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var packs []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&packs); err != nil {
			return err
		}
		for _, p := range packs {
			fmt.Printf("  %-40s %s\n", p["id"], p["version"])
		}
		return nil
	},
}

var rulesInstallCmd = &cobra.Command{
	Use:   "install <pack@version>",
	Short: "Install a rule pack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		c := client.New(cfg.Remote.APIURL)
		body, _ := json.Marshal(map[string]string{"pack": args[0]})
		resp, err := c.Post("/rules/install", bytes.NewReader(body))
		if err != nil {
			return err
		}
		resp.Body.Close()
		fmt.Printf("Installed %s\n", args[0])
		return nil
	},
}

var rulesUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update all installed rule packs to latest",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		c := client.New(cfg.Remote.APIURL)
		resp, err := c.Post("/rules/update", nil)
		if err != nil {
			return err
		}
		resp.Body.Close()
		fmt.Println("Rule packs updated.")
		return nil
	},
}

var rulesShowCmd = &cobra.Command{
	Use:   "show <rule-id>",
	Short: "Show details for a rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		c := client.New(cfg.Remote.APIURL)
		resp, err := c.Get("/rules/" + args[0])
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var rule map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rule)
	},
}

func init() {
	rulesCmd.AddCommand(rulesListCmd, rulesInstallCmd, rulesUpdateCmd, rulesShowCmd)
	rootCmd.AddCommand(rulesCmd)
}
