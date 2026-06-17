// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"fmt"
	"os"

	"github.com/relix-q/relix-q/cmd/relixq/internal/formatter"
	"github.com/relix-q/relix-q/cmd/relixq/internal/github"
	"github.com/spf13/cobra"
)

var prCommentCmd = &cobra.Command{
	Use:   "pr-comment",
	Short: "Post or update a PR comment and check run with scan results",
	Long: `Reads a SARIF file produced by 'relixq scan --format sarif', then posts or
updates an idempotent summary comment on the pull request and creates a
GitHub Check Run with inline annotations (capped at 50).

Requires GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_SHA to be set.
GITHUB_EVENT_PATH is used to auto-detect the PR number on pull_request events.`,
	RunE: runPRComment,
}

func runPRComment(cmd *cobra.Command, _ []string) error {
	sarifPath, _ := cmd.Flags().GetString("sarif")
	mode, _ := cmd.Flags().GetString("mode")
	prNumber, _ := cmd.Flags().GetInt("pr-number")

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN is not set")
	}
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return fmt.Errorf("GITHUB_REPOSITORY is not set")
	}
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" {
		return fmt.Errorf("GITHUB_SHA is not set")
	}

	if prNumber == 0 {
		if eventPath := os.Getenv("GITHUB_EVENT_PATH"); eventPath != "" {
			if n, err := github.PRNumberFromEventPayload(eventPath); err == nil {
				prNumber = n
			}
		}
	}

	findings, err := formatter.ReadSARIF(sarifPath)
	if err != nil {
		return fmt.Errorf("reading SARIF %q: %w", sarifPath, err)
	}

	client := github.NewClient(token)

	if prNumber > 0 {
		if err := client.UpsertPRComment(repo, prNumber, findings); err != nil {
			return fmt.Errorf("posting PR comment: %w", err)
		}
	}

	conclusion := github.Conclusion(mode, findings)
	if err := client.CreateCheckRun(repo, sha, conclusion, findings); err != nil {
		return fmt.Errorf("creating check run: %w", err)
	}

	if !quietFlag {
		fmt.Fprintf(os.Stderr, "relixq: posted %d finding(s) [mode=%s conclusion=%s]\n",
			len(findings), mode, conclusion)
	}
	return nil
}

func init() {
	prCommentCmd.Flags().String("sarif", "", "Path to SARIF file produced by relixq scan (required)")
	prCommentCmd.Flags().String("mode", "warn", "observe | warn | block")
	prCommentCmd.Flags().Int("pr-number", 0, "Pull request number (auto-detected from GITHUB_EVENT_PATH if omitted)")
	_ = prCommentCmd.MarkFlagRequired("sarif")
	rootCmd.AddCommand(prCommentCmd)
}
