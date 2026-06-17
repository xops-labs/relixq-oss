// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// WriteHTML writes a self-contained HTML scan report.
func WriteHTML(findings []model.Finding, w io.Writer) error {
	fmt.Fprint(w, htmlHeader)

	counts := countBySeverity(findings)
	fmt.Fprintf(w, "<h1>Relix-Q Scan Report</h1>\n")
	fmt.Fprintf(w, "<p class=\"summary\"><strong>%d finding(s)</strong>%s</p>\n",
		len(findings), html.EscapeString(buildSummary(counts)))

	bySeverity := map[string][]model.Finding{}
	for _, f := range findings {
		bySeverity[strings.ToLower(f.Severity)] = append(bySeverity[strings.ToLower(f.Severity)], f)
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		group := bySeverity[sev]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "<h2 class=\"sev-%s\">%s Findings</h2>\n<ul>\n", sev, strings.Title(sev))
		for _, f := range group {
			fmt.Fprintf(w, "  <li><code>%s</code> — <a href=\"%s#L%d\">%s:%d</a> — %s",
				html.EscapeString(f.RuleID),
				html.EscapeString(f.FilePath), f.LineNumber,
				html.EscapeString(f.FilePath), f.LineNumber,
				html.EscapeString(f.Message))
			if f.Recommendation != "" {
				fmt.Fprintf(w, "<br><em>%s</em>", html.EscapeString(f.Recommendation))
			}
			fmt.Fprintln(w, "</li>")
		}
		fmt.Fprintln(w, "</ul>")
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, "<p><em>No findings above the configured severity threshold.</em></p>")
	}

	fmt.Fprint(w, htmlFooter)
	return nil
}

const htmlHeader = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Relix-Q Scan Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{border-bottom:2px solid #333}
.sev-critical{color:#c0392b}.sev-high{color:#e74c3c}
.sev-medium{color:#e67e22}.sev-low{color:#2980b9}.sev-info{color:#7f8c8d}
code{background:#f4f4f4;padding:2px 4px;border-radius:3px}
</style></head><body>
`

const htmlFooter = `</body></html>
`
