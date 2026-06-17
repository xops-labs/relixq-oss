// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"fmt"
	"io"
	"strings"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// WriteMarkdown writes a Markdown scan report suitable for PR comments or files.
func WriteMarkdown(findings []model.Finding, w io.Writer) error {
	fmt.Fprintln(w, "# Relix-Q Scan Report")
	fmt.Fprintln(w)

	counts := countBySeverity(findings)
	fmt.Fprintf(w, "**Total findings:** %d%s\n\n", len(findings), buildSummary(counts))

	bySeverity := map[string][]model.Finding{}
	for _, f := range findings {
		sev := strings.ToLower(f.Severity)
		bySeverity[sev] = append(bySeverity[sev], f)
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		group := bySeverity[sev]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s Findings\n\n", strings.Title(sev))
		for _, f := range group {
			fmt.Fprintf(w, "- **[`%s`](%s#L%d)** — %s\n", f.RuleID, f.FilePath, f.LineNumber, f.Message)
			if f.Recommendation != "" {
				fmt.Fprintf(w, "  - *Recommendation:* %s\n", f.Recommendation)
			}
		}
		fmt.Fprintln(w)
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, "_No findings above the configured severity threshold._")
	}

	return nil
}
