// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"fmt"
	"io"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// Write dispatches to the appropriate formatter.
func Write(format string, findings []model.Finding, w io.Writer, color, quiet bool) error {
	switch format {
	case "json":
		return WriteJSON(findings, w)
	case "jsonl":
		return WriteJSONL(findings, w)
	case "sarif":
		return WriteSARIF(findings, w)
	case "markdown", "md":
		return WriteMarkdown(findings, w)
	case "html":
		return WriteHTML(findings, w)
	case "text", "":
		return WriteText(findings, w, color, quiet)
	default:
		return fmt.Errorf("unknown format %q: choose text|json|jsonl|sarif|markdown|html", format)
	}
}
