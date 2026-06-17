// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/relix-q/relix-q/cmd/relixq/internal/auth"
	"github.com/relix-q/relix-q/cmd/relixq/internal/client"
	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/spf13/cobra"
)

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Manage organization membership and context",
}

// org list ────────────────────────────────────────────────────────────────────

var orgListCmd = &cobra.Command{
	Use:   "list",
	Short: "List organizations you belong to",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load(".")
		c := client.New(cfg.Remote.APIURL)

		orgs, err := c.ListMyOrgs()
		if err != nil {
			return fmt.Errorf("org list: %w", err)
		}

		if len(orgs) == 0 {
			fmt.Println("You don't belong to any organization yet.")
			fmt.Println("Create one at: relixq.io/orgs/new")
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SLUG\tNAME\tROLE\tJOINED")
		for _, o := range orgs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				o.Slug, o.Name, o.OrgRole, o.JoinedAt.Format("2006-01-02"))
		}
		return w.Flush()
	},
}

// org use ─────────────────────────────────────────────────────────────────────

var orgUseCmd = &cobra.Command{
	Use:   "use <slug>",
	Short: "Switch your active organization context",
	Long: `Switch the active organization. The auth service re-mints your access
token scoped to the target org; the new tokens are stored in the system
keychain and used by subsequent relixq commands.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slug := args[0]
		cfg, _ := config.Load(".")
		c := client.New(cfg.Remote.APIURL)

		// Resolve slug → org ID by listing the user's orgs.
		orgs, err := c.ListMyOrgs()
		if err != nil {
			return fmt.Errorf("org use: %w", err)
		}

		var target *client.OrgEntry
		for i := range orgs {
			if orgs[i].Slug == slug {
				target = &orgs[i]
				break
			}
		}
		if target == nil {
			return fmt.Errorf("org use: organization %q not found (run 'relixq org list' to see your orgs)", slug)
		}

		tokens, err := c.SwitchOrg(target.OrganizationID)
		if err != nil {
			return fmt.Errorf("org use: %w", err)
		}

		if err := auth.SaveToken(&auth.Token{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
		}); err != nil {
			return fmt.Errorf("org use: saving tokens: %w", err)
		}

		if !quietFlag {
			fmt.Printf("Active organization switched to %q (%s)\n", target.Name, slug)
			fmt.Printf("Role: %s\n", target.OrgRole)
		}
		return nil
	},
}

func init() {
	orgCmd.AddCommand(orgListCmd)
	orgCmd.AddCommand(orgUseCmd)
	rootCmd.AddCommand(orgCmd)
}
