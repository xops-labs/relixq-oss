// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// WriteJSON writes a JSON array of all findings.
func WriteJSON(findings []model.Finding, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// WriteJSONL writes one JSON object per line (newline-delimited JSON).
// Safe to stream — callers can pipe to jq or process line-by-line.
func WriteJSONL(findings []model.Finding, w io.Writer) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("jsonl encode: %w", err)
		}
	}
	return nil
}
