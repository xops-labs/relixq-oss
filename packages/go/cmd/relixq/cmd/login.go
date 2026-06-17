// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"

	"github.com/relix-q/relix-q/cmd/relixq/internal/auth"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Relix-Q platform (device-code flow)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		if !quietFlag {
			fmt.Println("Opening browser to authenticate...")
		}
		return auth.Login(cfg.Remote.APIURL, func(verificationURL, userCode string) {
			fmt.Printf("\nOpen this URL in your browser:\n\n  %s\n\nEnter code: %s\n\nWaiting...\n",
				verificationURL, userCode)
		})
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.DeleteToken(); err != nil {
			return fmt.Errorf("logout: %w", err)
		}
		fmt.Println("Logged out.")
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the currently authenticated user",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := auth.GetToken()
		if err != nil {
			return err
		}
		// Token is present; a real implementation would call GET /me.
		// Print a confirmation without exposing the token value.
		_ = token
		fmt.Println("Authenticated. (run 'relixq whoami --verbose' to call /me once that endpoint is live)")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
}
