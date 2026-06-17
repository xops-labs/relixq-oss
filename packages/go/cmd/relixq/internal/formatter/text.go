// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

var severityColor = map[string]func(...interface{}) string{
	"critical": color.New(color.FgRed, color.Bold).SprintFunc(),
	"high":     color.New(color.FgRed).SprintFunc(),
	"medium":   color.New(color.FgYellow).SprintFunc(),
	"low":      color.New(color.FgCyan).SprintFunc(),
	"info":     color.New(color.FgWhite).SprintFunc(),
}

// WriteText writes human-readable, optionally colored output.
func WriteText(findings []model.Finding, w io.Writer, useColor, quiet bool) error {
	color.NoColor = !useColor

	counts := countBySeverity(findings)

	if !quiet {
		summary := buildSummary(counts)
		fmt.Fprintf(w, "relixq scan: %d finding(s)%s\n\n", len(findings), summary)
	}

	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		colorFn, ok := severityColor[strings.ToLower(f.Severity)]
		if ok && useColor {
			sev = colorFn(sev)
		}

		fmt.Fprintf(w, "%-10s %s\n", sev, f.RuleID)
		fmt.Fprintf(w, "  %s:%d\n", f.FilePath, f.LineNumber)
		if f.Snippet != "" {
			fmt.Fprintf(w, "  > %s\n", f.Snippet)
		}
		if f.Message != "" {
			fmt.Fprintf(w, "  %s\n", f.Message)
		}
		if f.Recommendation != "" {
			fmt.Fprintf(w, "  Recommendation: %s\n", f.Recommendation)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func countBySeverity(findings []model.Finding) map[string]int {
	m := make(map[string]int)
	for _, f := range findings {
		m[strings.ToLower(f.Severity)]++
	}
	return m
}

func buildSummary(counts map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
