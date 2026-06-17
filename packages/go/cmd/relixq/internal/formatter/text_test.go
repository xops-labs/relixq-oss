// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteText_IncludesSummaryAndFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(sampleFindings(), &buf, false /*color*/, false /*quiet*/); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()

	// Summary line at the top.
	if !strings.HasPrefix(out, "relixq scan: 2 finding(s)") {
		t.Fatalf("expected summary on first line, got:\n%s", out)
	}
	if !strings.Contains(out, "1 critical") || !strings.Contains(out, "1 high") {
		t.Fatalf("summary should break down counts; got:\n%s", out)
	}

	// Per-finding rendering.
	if !strings.Contains(out, "GO_RSA_GENERATE_KEY") {
		t.Fatalf("missing rule id in output:\n%s", out)
	}
	if !strings.Contains(out, "internal/auth/keys.go:42") {
		t.Fatalf("missing file:line in output:\n%s", out)
	}
	if !strings.Contains(out, "Recommendation: Migrate to ML-KEM") {
		t.Fatalf("missing recommendation in output:\n%s", out)
	}
}

func TestWriteText_QuietSuppressesSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(sampleFindings(), &buf, false /*color*/, true /*quiet*/); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	if strings.HasPrefix(out, "relixq scan:") {
		t.Fatalf("quiet mode should suppress the summary line; got:\n%s", out)
	}
	if !strings.Contains(out, "GO_RSA_GENERATE_KEY") {
		t.Fatalf("findings still expected in quiet mode; got:\n%s", out)
	}
}

func TestWriteText_NoColorDoesNotInjectAnsi(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(sampleFindings(), &buf, false /*color*/, false /*quiet*/); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("color=false must not write ANSI escapes; got:\n%s", buf.String())
	}
}

func TestWriteText_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(nil, &buf, false, false); err != nil {
		t.Fatalf("WriteText empty: %v", err)
	}
	if !strings.Contains(buf.String(), "0 finding(s)") {
		t.Fatalf("expected zero-findings summary; got:\n%s", buf.String())
	}
}
