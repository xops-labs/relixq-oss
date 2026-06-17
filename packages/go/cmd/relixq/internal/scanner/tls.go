// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
	"github.com/relix-q/relix-q/tlsscanner"
)

// RunTLS scans each target endpoint (host[:port]) for quantum-vulnerable and
// weak transport crypto and returns findings in the CLI model
// shape, plus a slice of per-target error strings for endpoints that could not
// be reached or negotiated. Unreachable targets do not abort the others.
func RunTLS(ctx context.Context, targets []string, timeout time.Duration) ([]model.Finding, []string) {
	var findings []model.Finding
	var errs []string
	for _, raw := range targets {
		t, err := tlsscanner.ParseTarget(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", raw, err))
			continue
		}
		if timeout > 0 {
			t.DialTimeout = timeout
			t.HSTimeout = timeout
		}
		fs, err := tlsscanner.Scan(ctx, t)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.Endpoint(), err))
			continue
		}
		for i := range fs {
			b, err := json.Marshal(fs[i])
			if err != nil {
				continue
			}
			var m model.Finding
			if json.Unmarshal(b, &m) == nil {
				findings = append(findings, m)
			}
		}
	}
	return findings, errs
}
