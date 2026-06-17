// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package scanner orchestrates a single scan run: walk → route → detect → emit.
// It owns no state; callers build a Scanner per job.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/relix-q/relix-q/blame"
	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/detectors/regex"
	x509det "github.com/relix-q/relix-q/detectors/x509"
	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
	"github.com/relix-q/relix-q/scanner/notebook"
	"github.com/relix-q/relix-q/suppression"
)

// Job identifies the scan run / job a Finding belongs to.
type Job struct {
	OrganizationID string
	ScanRunID      string
	ScanJobID      string
	TraceID        string
}

// ScanRequest is one invocation of Scanner.Scan.
type ScanRequest struct {
	RepoPath    string
	Pack        *rules.Pack
	Output      string              // local JSONL path
	IncludeOnly map[string]struct{} // optional, used by diff mode
}

// ScanResult is what we hand back to the worker / CLI.
type ScanResult struct {
	FilesScanned  int
	FilesSkipped  int
	FindingsCount int
	OutputPath    string
	// FilesByLanguage counts the scanned (not skipped) files per detected
	// language, so consumers can show coverage ("319 files: 120 python, …").
	FilesByLanguage map[Language]int
}

// Scanner is the per-job orchestrator.
type Scanner struct {
	Job Job
	Log *slog.Logger
}

// New constructs a Scanner with a default logger if none is provided.
func New(job Job, log *slog.Logger) *Scanner {
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return &Scanner{Job: job, Log: log}
}

// Scan walks the repo, applies rules per file, and writes JSONL findings.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if req.Pack == nil {
		return nil, fmt.Errorf("scanner: rule pack required")
	}

	walkOpts := WalkOptions{IncludeOnly: req.IncludeOnly}
	files, err := Walk(req.RepoPath, walkOpts)
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}

	writer, err := finding.NewJSONLWriter(req.Output)
	if err != nil {
		return nil, fmt.Errorf("open output: %w", err)
	}
	defer writer.Close()

	blamer := blame.Open(req.RepoPath)

	result := &ScanResult{OutputPath: req.Output}

	for _, fe := range files {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		processed, n, skipReason := s.scanFile(ctx, fe, req.Pack, writer, blamer)
		if skipReason != "" {
			result.FilesSkipped++
			s.Log.Debug("skip file", "path", fe.RelativePath, "reason", skipReason)
			continue
		}
		_ = processed
		result.FilesScanned++
		result.FindingsCount += n
		if result.FilesByLanguage == nil {
			result.FilesByLanguage = make(map[Language]int)
		}
		result.FilesByLanguage[fe.Language]++
	}

	if err := writer.Close(); err != nil {
		return result, err
	}
	return result, nil
}

// scanFile reads one file, runs all applicable rules, writes any findings.
// It deliberately swallows per-file errors so a malformed file doesn't fail
// the whole scan (LLD §8 "skip file, log, continue"). The same policy covers
// detector panics: a parser bug on one pathological file must cost that file,
// not the scan — the deferred recover converts the panic into a skip.
func (s *Scanner) scanFile(
	ctx context.Context,
	fe FileEntry,
	pack *rules.Pack,
	writer *finding.JSONLWriter,
	blamer *blame.Blamer,
) (processed bool, n int, skipReason string) {
	defer func() {
		if r := recover(); r != nil {
			s.Log.Error("detector panic — file skipped, scan continues",
				"path", fe.RelativePath, "language", string(fe.Language), "panic", r)
			processed, n, skipReason = false, 0, fmt.Sprintf("detector_panic: %v", r)
		}
	}()
	if fe.Language == LangJupyter {
		return s.scanJupyterFile(ctx, fe, pack, writer, blamer)
	}
	if fe.Language == LangX509 {
		// Certificate / key material has no YAML rules: the x509 detector
		// parses PEM/DER directly and emits synthetic findings.
		return s.scanX509File(fe, writer, blamer)
	}

	applicable := pack.ForLanguage(string(fe.Language))
	if len(applicable) == 0 {
		return false, 0, "no_rules_for_language"
	}

	// Read the file once and reuse the buffer across every detection layer
	// (regex floor, AST, sentinel). Previously the regex detector streamed the
	// file while the AST and sentinel layers each re-read it from disk; a single
	// read cuts file I/O to one read per file with byte-identical results.
	src, err := os.ReadFile(fe.AbsolutePath)
	if err != nil {
		return false, 0, "open_failed"
	}

	matches, err := regex.MatchFile(fe.RelativePath, bytes.NewReader(src), applicable)
	if err != nil {
		s.Log.Warn("regex match error", "path", fe.RelativePath, "error", err)
		return false, 0, "regex_failed"
	}

	// Collect regex findings first — they are the always-on detection floor.
	regexFindings := make([]*finding.Finding, 0, len(matches))
	for _, m := range matches {
		fnd := regex.ToFinding(s.Job.ScanJobID, fe.RelativePath, string(fe.Language), m)
		if blamer != nil {
			info := blamer.BlameLine(fe.RelativePath, m.Line)
			fnd.GitBlameAuthor = info.Author
			fnd.GitBlameCommit = info.Commit
		}
		regexFindings = append(regexFindings, fnd)
	}

	// Run the AST detector when one is registered for this language. AST is the
	// precision layer: a rule may exist in both a regex (floor) and an AST form
	// under the same id; when an AST finding covers the same (rule id, line) as
	// a regex finding it supersedes it (dedup below). With no runner available
	// the AST set is empty and the regex floor stands unchanged.
	var astFindings []*finding.Finding
	astCovers := map[string]struct{}{}
	if astRunner := astdet.Get(string(fe.Language)); astRunner != nil {
		astMatches, astErr := astRunner.Run(fe.AbsolutePath, src, applicable)
		if astErr != nil {
			s.Log.Warn("ast runner error", "path", fe.RelativePath, "error", astErr)
		}
		// Apply inline-suppression uniformly so AST findings honor
		// `// relixq-ignore: <ruleId>` directives the same way regex
		// findings already do.
		suppressMap := suppression.BuildInlineMap(strings.Split(string(src), "\n"))
		for _, m := range astMatches {
			if suppression.IsSuppressed(suppressMap, m.Line, m.Rule.ID) {
				continue
			}
			fnd := astMatchToFinding(s.Job.ScanJobID, fe.RelativePath, string(fe.Language), m)
			if blamer != nil {
				info := blamer.BlameLine(fe.RelativePath, m.Line)
				fnd.GitBlameAuthor = info.Author
				fnd.GitBlameCommit = info.Commit
			}
			astFindings = append(astFindings, fnd)
			astCovers[supersedeKey(fnd.RuleID, fnd.LineNumber)] = struct{}{}
		}
	}

	// Assemble the file's emitted set: AST findings first (precision layer),
	// then regex findings not superseded by an AST finding for the same rule
	// at the same line. With no AST runner (or no overlapping rule) astCovers
	// is empty and every regex finding is emitted — the floor is preserved.
	emitted := make([]*finding.Finding, 0, len(astFindings)+len(regexFindings))
	emitted = append(emitted, astFindings...)
	for _, fnd := range regexFindings {
		if _, superseded := astCovers[supersedeKey(fnd.RuleID, fnd.LineNumber)]; superseded {
			continue
		}
		emitted = append(emitted, fnd)
	}

	// File-level multi-signal promotion (promote.go): when >=2 distinct
	// hand-rolled / crypto-fingerprint rules agree on an algorithm within
	// this file, append one promoted high-severity finding per agreement.
	// Promoted findings flow through the same JSONL path as everything else.
	emitted = append(emitted, promoteHandrolled(emitted)...)

	// Coverage sentinel (sentinel.go): if the file demonstrably imports a
	// known CLASSICAL crypto library yet the whole stack above (regex floor,
	// AST layer, promotion) recognized NOTHING, emit one informational
	// CRYPTO_API_UNMAPPED finding so the coverage gap is visible instead of
	// silent. Files with any finding never get a sentinel; the x509 branch
	// has its own parser and is deliberately not covered.
	if len(emitted) == 0 {
		if hit, ok := detectUnmappedCrypto(string(fe.Language), src); ok {
			fnd := sentinelToFinding(s.Job.ScanJobID, fe.RelativePath, string(fe.Language), hit)
			if blamer != nil {
				info := blamer.BlameLine(fe.RelativePath, hit.Line)
				fnd.GitBlameAuthor = info.Author
				fnd.GitBlameCommit = info.Commit
			}
			emitted = append(emitted, fnd)
		}
	}

	count := 0
	for _, fnd := range emitted {
		if err := writer.Write(fnd); err != nil {
			s.Log.Error("write finding", "error", err)
			return true, count, ""
		}
		count++
	}

	return true, count, ""
}

// scanX509File handles LangX509 entries (.pem/.crt/.cer/.der/.key): the x509
// detector parses certificate / key material (PEM blocks or raw DER) and
// reports quantum-vulnerable public-key AND signature algorithms. Unparseable
// or unrecognized (future PQC) material yields zero findings, never an error.
func (s *Scanner) scanX509File(
	fe FileEntry,
	writer *finding.JSONLWriter,
	blamer *blame.Blamer,
) (bool, int, string) {
	content, err := os.ReadFile(fe.AbsolutePath)
	if err != nil {
		return false, 0, "open_failed"
	}

	matches := x509det.Detect(content)
	count := 0
	for _, m := range matches {
		fnd := x509det.ToFinding(s.Job.ScanJobID, fe.RelativePath, m)
		if blamer != nil {
			info := blamer.BlameLine(fe.RelativePath, m.Line)
			fnd.GitBlameAuthor = info.Author
			fnd.GitBlameCommit = info.Commit
		}
		if err := writer.Write(fnd); err != nil {
			s.Log.Error("write finding", "error", err)
			return true, count, ""
		}
		count++
	}
	return true, count, ""
}

// supersedeKey identifies a finding by rule id and line for regex/AST dedup.
func supersedeKey(ruleID string, line int) string {
	return fmt.Sprintf("%s\x00%d", ruleID, line)
}

// scanJupyterFile handles .ipynb files by lifting code cells into a synthesized
// Python buffer, feeding that buffer through the Python AST runner (whose
// rule pack covers the entire Jupyter detection surface — there is no separate
// "jupyter" rule pack), then translating each finding's line number back to
// the (cell, line-within-cell) coordinates a reviewer sees in the notebook.
//
// Regex matching is skipped: regex line numbers would also need translating,
// and the Python rule pack's regex tail (a small minority of rules) does not
// move the needle enough to justify the bookkeeping in v1. AST runner output
// is the dominant signal for Python and therefore for .ipynb too.
func (s *Scanner) scanJupyterFile(
	_ context.Context,
	fe FileEntry,
	pack *rules.Pack,
	writer *finding.JSONLWriter,
	blamer *blame.Blamer,
) (bool, int, string) {
	applicable := pack.ForLanguage(string(LangPython))
	if len(applicable) == 0 {
		return false, 0, "no_rules_for_language"
	}

	astRunner := astdet.Get(string(LangPython))
	if astRunner == nil {
		// pyast runner not registered (e.g. python interpreter missing); without
		// it there is no detection path that's worth running, so skip cleanly.
		return false, 0, "no_python_ast_runner"
	}

	src, readErr := os.ReadFile(fe.AbsolutePath)
	if readErr != nil {
		return false, 0, "open_failed"
	}

	synthesized, lineMap, prepErr := notebook.Preprocess(src)
	if prepErr != nil {
		s.Log.Debug("notebook preprocess failed", "path", fe.RelativePath, "error", prepErr)
		return false, 0, "jupyter_parse_failed"
	}
	if len(synthesized) == 0 {
		return true, 0, ""
	}

	astMatches, astErr := astRunner.Run(fe.AbsolutePath, synthesized, applicable)
	if astErr != nil {
		s.Log.Warn("ast runner error", "path", fe.RelativePath, "error", astErr)
	}

	count := 0
	for _, m := range astMatches {
		origLine := m.Line
		if cellIdx, cellLine, ok := notebook.TranslateLine(lineMap, m.Line); ok {
			m.Line = cellLine
			// Prefix the snippet with the cell index so reviewers can locate
			// the finding without a dedicated schema field. The canonical
			// CryptoFinding schema is unchanged.
			m.Snippet = fmt.Sprintf("[cell %d] %s", cellIdx, m.Snippet)
			_ = origLine
		}
		// Findings surface under language="python" so downstream consumers
		// (rule lookup, dashboards, exports) treat them as Python — consistent
		// with the rules they came from.
		fnd := astMatchToFinding(s.Job.ScanJobID, fe.RelativePath, string(LangPython), m)
		if blamer != nil {
			info := blamer.BlameLine(fe.RelativePath, m.Line)
			fnd.GitBlameAuthor = info.Author
			fnd.GitBlameCommit = info.Commit
		}
		if err := writer.Write(fnd); err != nil {
			s.Log.Error("write finding", "error", err)
			break
		}
		count++
	}

	return true, count, ""
}

func astMatchToFinding(scanJobID, relPath, lang string, m astdet.Match) *finding.Finding {
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
		Snippet:        m.Snippet,
		SnippetContext: m.Context,
		Confidence:     rule.Confidence,
		Category:       rule.Category,
		Message:        rule.Message,
		Recommendation: rule.Recommendation,
		References:     rule.References,
		CWE:            rule.CWE,
	}
}
