// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var useCmd = &cobra.Command{
	Use:   "use <project-slug>",
	Short: "Set the active project for platform commands",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		slug := args[0]
		if err := writeProjectSlug(slug); err != nil {
			return fmt.Errorf("saving project: %w", err)
		}
		fmt.Printf("Active project set to %q\n", slug)
		return nil
	},
}

// writeProjectSlug upserts the `project` field in relixq.yaml (or creates the
// file if absent). It does a targeted update so other settings are preserved.
func writeProjectSlug(slug string) error {
	const cfgFile = "relixq.yaml"

	existing := map[string]interface{}{}
	if data, err := os.ReadFile(cfgFile); err == nil {
		_ = yaml.Unmarshal(data, &existing)
	}

	existing["project"] = slug

	out, err := yaml.Marshal(existing)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(".", cfgFile), out, 0644)
}

func init() {
	rootCmd.AddCommand(useCmd)
}
