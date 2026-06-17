// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package github

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

const commentMarker = "<!-- relixq:pr-comment v1 -->"

// UpsertPRComment finds an existing Relix-Q comment on the PR (by hidden marker)
// and updates it in place, or creates a new one if none exists.
func (c *Client) UpsertPRComment(repoFullName string, prNumber int, findings []model.Finding) error {
	body := buildCommentBody(findings)

	existingID, err := c.findExistingComment(repoFullName, prNumber)
	if err != nil {
		return fmt.Errorf("listing comments: %w", err)
	}

	if existingID != 0 {
		return c.updateComment(repoFullName, existingID, body)
	}
	return c.createComment(repoFullName, prNumber, body)
}

func (c *Client) findExistingComment(repoFullName string, prNumber int) (int64, error) {
	path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100", repoFullName, prNumber)
	resp, err := c.do("GET", path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		return 0, err
	}

	for _, cm := range comments {
		if strings.Contains(cm.Body, commentMarker) {
			return cm.ID, nil
		}
	}
	return 0, nil
}

func (c *Client) createComment(repoFullName string, prNumber int, body string) error {
	path := fmt.Sprintf("/repos/%s/issues/%d/comments", repoFullName, prNumber)
	resp, err := c.do("POST", path, map[string]string{"body": body})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *Client) updateComment(repoFullName string, commentID int64, body string) error {
	path := fmt.Sprintf("/repos/%s/issues/comments/%d", repoFullName, commentID)
	resp, err := c.do("PATCH", path, map[string]string{"body": body})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func buildCommentBody(findings []model.Finding) string {
	var sb strings.Builder
	sb.WriteString(commentMarker + "\n")
	sb.WriteString("## Relix-Q Scan Results\n\n")

	if len(findings) == 0 {
		sb.WriteString("No post-quantum-vulnerable cryptography detected.\n")
		return sb.String()
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	if n := counts["critical"]; n > 0 {
		sb.WriteString(fmt.Sprintf("**Critical:** %d  ", n))
	}
	if n := counts["high"]; n > 0 {
		sb.WriteString(fmt.Sprintf("**High:** %d  ", n))
	}
	if n := counts["medium"]; n > 0 {
		sb.WriteString(fmt.Sprintf("**Medium:** %d  ", n))
	}
	sb.WriteString("\n\n")

	sb.WriteString("| Severity | Rule | File |\n")
	sb.WriteString("|---|---|---|\n")
	limit := len(findings)
	if limit > 20 {
		limit = 20
	}
	for _, f := range findings[:limit] {
		icon := severityIcon(f.Severity)
		sb.WriteString(fmt.Sprintf("| %s %s | `%s` | `%s:%d` |\n",
			icon, f.Severity, f.RuleID, f.FilePath, f.LineNumber))
	}
	if len(findings) > 20 {
		sb.WriteString(fmt.Sprintf("\n_...and %d more findings. View the full report in the Checks tab._\n",
			len(findings)-20))
	}
	return sb.String()
}

func severityIcon(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	default:
		return "🔵"
	}
}
