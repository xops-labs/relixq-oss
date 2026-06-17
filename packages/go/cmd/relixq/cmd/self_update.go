// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// archiveExt mirrors the release archive naming in .goreleaser.yaml:
// zip on Windows, tar.gz elsewhere.
func archiveExt() string {
	if runtime.GOOS == "windows" {
		return "zip"
	}
	return "tar.gz"
}

const releasesURL = "https://api.github.com/repos/xops-labs/relixq-oss/releases/latest"

var selfUpdateCmd = &cobra.Command{
	Use:   "self-update",
	Short: "Update relixq to the latest release",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !quietFlag {
			fmt.Println("Checking for updates...")
		}

		resp, err := http.Get(releasesURL)
		if err != nil {
			return fmt.Errorf("checking releases: %w", err)
		}
		defer resp.Body.Close()

		var release struct {
			TagName string `json:"tag_name"`
			HTMLURL string `json:"html_url"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return fmt.Errorf("parsing release info: %w", err)
		}

		// Release builds stamp Version without the leading "v" (GoReleaser
		// {{ .Version }}); tags carry it. Compare normalized.
		if strings.TrimPrefix(release.TagName, "v") == strings.TrimPrefix(Version, "v") {
			fmt.Printf("Already up to date (%s)\n", Version)
			return nil
		}

		// The actual binary replacement requires OS-specific logic (write to temp,
		// rename over self). For now we print the download URL and let the user
		// install — a full updater would use github.com/minio/selfupdate.
		fmt.Printf("New version available: %s (you have %s)\n", release.TagName, Version)
		fmt.Printf("Download: %s\n", release.HTMLURL)
		fmt.Printf("Archive for this platform: relixq_%s_%s_%s.%s\n",
			strings.TrimPrefix(release.TagName, "v"), runtime.GOOS, runtime.GOARCH, archiveExt())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(selfUpdateCmd)
}
