// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package regex implements the regex detector backend (type=regex).
// AST detection is left as a future plug-in via the same Detector interface.
package regex

import (
	"bufio"
	"bytes"
	"io"
	"path/filepath"
	"strings"

	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
	"github.com/relix-q/relix-q/suppression"
)

// SnippetContextLines is the number of lines kept on either side of a match
// for AI explanation downstream.
const SnippetContextLines = 3

// Match represents one regex hit.
type Match struct {
	Rule    *rules.Rule
	Line    int
	Column  int
	Snippet string
	Context []string
}

// MatchFile reads the file's content from r, applies every regex rule, and
// returns the matches. Inline `relixq-ignore` directives suppress matches at
// or above the comment.
//
// path is the relative path (used for file_globs filtering).
func MatchFile(path string, r io.Reader, applicable []*rules.Rule) ([]Match, error) {
	lines, err := readAllLines(r)
	if err != nil {
		return nil, err
	}

	// Pre-scan for inline directives. A directive on line N suppresses matches
	// on line N AND line N+1 (so the directive can sit on its own line above
	// the call site).
	suppressMap := buildInlineSuppressionMap(lines)

	var hits []Match
	for _, rule := range applicable {
		if rule.Detector.Type != rules.DetectorRegex || rule.Compiled() == nil {
			continue
		}
		if !ruleAppliesToFile(rule, path) {
			continue
		}
		for i, line := range lines {
			locs := rule.Compiled().FindAllStringIndex(line, -1)
			for _, loc := range locs {
				if isSuppressed(suppressMap, i+1, rule.ID) {
					continue
				}
				hits = append(hits, Match{
					Rule:    rule,
					Line:    i + 1,
					Column:  loc[0] + 1,
					Snippet: line,
					Context: contextOf(lines, i),
				})
			}
		}
	}
	return hits, nil
}

// ToFinding converts a Match plus job-level metadata into a Finding.
func ToFinding(scanJobID, relPath string, lang string, m Match) *finding.Finding {
	rule := m.Rule
	return &finding.Finding{
		ScanJobID:      scanJobID,
		RuleID:         rule.ID,
		Language:       lang,
		Algorithm:      rule.Algorithm,
		UsageType:      rule.UsageType,
		QuantumSafety:  rule.EffectiveQuantumSafety(),
		Severity:       rule.Severity,
		KeySize:        rule.KeySize,
		FilePath:       relPath,
		LineNumber:     m.Line,
		Column:         m.Column,
		Snippet:        strings.TrimRight(m.Snippet, "\r\n"),
		SnippetContext: m.Context,
		Confidence:     rule.Confidence,
		Category:       rule.Category,
		Message:        rule.Message,
		Recommendation: rule.Recommendation,
		References:     rule.References,
		CWE:            rule.CWE,
	}
}

func ruleAppliesToFile(r *rules.Rule, path string) bool {
	if len(r.FileGlobs) == 0 {
		return true
	}
	base := filepath.Base(path)
	for _, glob := range r.FileGlobs {
		if ok, _ := filepath.Match(glob, base); ok {
			return true
		}
		if ok, _ := filepath.Match(glob, path); ok {
			return true
		}
	}
	return false
}

func readAllLines(r io.Reader) ([]string, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if !isProbablyText(buf) {
		return nil, nil
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(buf))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// isProbablyText is a cheap binary-content sniffer: a NUL byte in the first
// 8 KiB strongly suggests binary.
func isProbablyText(buf []byte) bool {
	limit := len(buf)
	if limit > 8192 {
		limit = 8192
	}
	for i := 0; i < limit; i++ {
		if buf[i] == 0 {
			return false
		}
	}
	return true
}

func contextOf(lines []string, idx int) []string {
	start := idx - SnippetContextLines
	if start < 0 {
		start = 0
	}
	end := idx + SnippetContextLines + 1
	if end > len(lines) {
		end = len(lines)
	}
	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, lines[i])
	}
	return out
}

// buildInlineSuppressionMap returns a map from line-number → directive. The
// directive applies to its own line and the next line.
func buildInlineSuppressionMap(lines []string) map[int]*suppression.InlineSuppression {
	out := map[int]*suppression.InlineSuppression{}
	for i, line := range lines {
		d := suppression.ParseInline(line)
		if d == nil {
			continue
		}
		out[i+1] = d
		out[i+2] = d
	}
	return out
}

func isSuppressed(m map[int]*suppression.InlineSuppression, line int, ruleID string) bool {
	d, ok := m[line]
	if !ok {
		return false
	}
	return d.Suppresses(ruleID)
}
