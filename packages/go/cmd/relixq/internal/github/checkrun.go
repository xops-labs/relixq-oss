// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package github

import (
	"fmt"
	"strings"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

const maxAnnotations = 50

// CreateCheckRun posts a completed check run with annotations for each finding (capped at 50).
func (c *Client) CreateCheckRun(repoFullName, headSHA, conclusion string, findings []model.Finding) error {
	annotations := buildAnnotations(findings)

	payload := map[string]any{
		"name":       "Relix-Q",
		"head_sha":   headSHA,
		"status":     "completed",
		"conclusion": conclusion,
		"output": map[string]any{
			"title":       "Relix-Q Scan Results",
			"summary":     buildSummary(findings, conclusion),
			"annotations": annotations,
		},
	}

	path := fmt.Sprintf("/repos/%s/check-runs", repoFullName)
	resp, err := c.do("POST", path, payload)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Conclusion maps the action mode + findings to a GitHub check run conclusion string.
func Conclusion(mode string, findings []model.Finding) string {
	switch mode {
	case "block":
		for _, f := range findings {
			if model.SeverityOrder[f.Severity] >= model.SeverityOrder["critical"] {
				return "failure"
			}
		}
		return "success"
	default: // "observe" and "warn" both result in neutral — never block CI.
		return "neutral"
	}
}

func buildAnnotations(findings []model.Finding) []map[string]any {
	limit := len(findings)
	if limit > maxAnnotations {
		limit = maxAnnotations
	}
	out := make([]map[string]any, 0, limit)
	for _, f := range findings[:limit] {
		out = append(out, map[string]any{
			"path":             f.FilePath,
			"start_line":       f.LineNumber,
			"end_line":         f.LineNumber,
			"annotation_level": annotationLevel(f.Severity),
			"title":            fmt.Sprintf("%s (%s)", f.Algorithm, f.RuleID),
			"message":          f.Message,
		})
	}
	return out
}

func annotationLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "failure"
	case "medium":
		return "warning"
	default:
		return "notice"
	}
}

func buildSummary(findings []model.Finding, conclusion string) string {
	if len(findings) == 0 {
		return "No post-quantum-vulnerable cryptography detected."
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d finding(s).", len(findings)))
	if len(findings) > maxAnnotations {
		sb.WriteString(fmt.Sprintf(
			" Showing first %d annotations; see PR comment for full list.", maxAnnotations))
	}
	if conclusion == "failure" {
		sb.WriteString(" Critical findings require remediation before merge.")
	}
	return sb.String()
}
