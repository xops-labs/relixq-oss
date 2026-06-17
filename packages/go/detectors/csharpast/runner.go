// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package csharpast implements a C# AST runner by talking to a long-running
// .NET Roslyn subprocess (tools/relixq-roslyn) over JSONL on stdin/stdout
// (detector.type=ast).
//
// Query format (detector.query in the rule YAML):
//
//	call:<Type>.<Method>     — matches Type.Method(...) invocations
//	new:<Type>               — matches new Type(...) constructor calls
//	using:<Namespace>        — matches using Namespace; directives
//	memberref:<Type>.<Member> — matches Type.Member member-access expressions
//
// Subprocess discovery (first wins):
//   1. $RELIXQ_ROSLYN_BIN
//   2. relixq-roslyn (or relixq-roslyn.exe on Windows) on $PATH
//   3. ../tools/relixq-roslyn/bin/relixq-roslyn(.exe) relative to current binary
//
// If no binary is found, the runner logs once to stderr and Run returns
// (nil, nil) silently so the scanner falls back to regex-only for .cs files
// without spamming a warning per file.
package csharpast

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("csharp", &runner{})
}

type runner struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      *bufio.Reader
	started     bool
	unavailable bool  // sticky: subprocess binary is not installed
	commErr     error // sticky: subprocess running but communication failed
	seq         atomic.Uint64
}

// Wire-format DTOs (mirror Protocol.cs).

type requestDTO struct {
	ID       string         `json:"id"`
	FilePath string         `json:"filePath"`
	Source   string         `json:"source"`
	Rules    []ruleQueryDTO `json:"rules"`
}

type ruleQueryDTO struct {
	ID    string `json:"id"`
	Query string `json:"query"`
}

type responseDTO struct {
	ID      string     `json:"id"`
	Matches []matchDTO `json:"matches"`
	Error   string     `json:"error"`
}

type matchDTO struct {
	RuleID  string   `json:"ruleId"`
	Line    int      `json:"line"`
	Column  int      `json:"column"`
	Snippet string   `json:"snippet"`
	Context []string `json:"context"`
}

// Run sends one request to the subprocess and returns its matches. The
// subprocess is started lazily on first invocation and reused across calls.
// Returns (nil, nil) silently when the subprocess binary is unavailable; the
// scanner then falls back to regex-only for C# files.
func (r *runner) Run(filePath string, source []byte, applicable []*rules.Rule) ([]astdet.Match, error) {
	// Pre-filter to AST rules; nothing to do if none.
	var astRules []ruleQueryDTO
	byID := make(map[string]*rules.Rule, len(applicable))
	for _, rule := range applicable {
		if rule.Detector.Type != rules.DetectorAST {
			continue
		}
		astRules = append(astRules, ruleQueryDTO{ID: rule.ID, Query: rule.Detector.Query})
		byID[rule.ID] = rule
	}
	if len(astRules) == 0 {
		return nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.unavailable {
		return nil, nil
	}
	if r.commErr != nil {
		return nil, r.commErr
	}

	if !r.started {
		if err := r.start(); err != nil {
			if errors.Is(err, astdet.ErrUnavailable) {
				fmt.Fprintf(os.Stderr,
					"csharpast: relixq-roslyn binary unavailable; C# AST rules will be skipped (set RELIXQ_ROSLYN_BIN to enable). detail: %v\n",
					err)
				r.unavailable = true
				return nil, nil
			}
			r.commErr = err
			return nil, err
		}
	}

	id := strconv.FormatUint(r.seq.Add(1), 10)
	req := requestDTO{ID: id, FilePath: filePath, Source: string(source), Rules: astRules}

	payload, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("csharpast: marshal request: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := r.stdin.Write(payload); err != nil {
		r.commErr = fmt.Errorf("csharpast: write to subprocess: %w", err)
		return nil, r.commErr
	}

	line, err := r.stdout.ReadBytes('\n')
	if err != nil {
		r.commErr = fmt.Errorf("csharpast: read from subprocess: %w", err)
		return nil, r.commErr
	}

	var resp responseDTO
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("csharpast: unmarshal response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("csharpast: subprocess error: %s", resp.Error)
	}
	if resp.ID != id {
		return nil, fmt.Errorf("csharpast: response id mismatch (want %s got %s)", id, resp.ID)
	}

	matches := make([]astdet.Match, 0, len(resp.Matches))
	for _, m := range resp.Matches {
		rule, ok := byID[m.RuleID]
		if !ok {
			continue
		}
		matches = append(matches, astdet.Match{
			Rule:    rule,
			Line:    m.Line,
			Column:  m.Column,
			Snippet: m.Snippet,
			Context: m.Context,
		})
	}
	return matches, nil
}

func (r *runner) start() error {
	binPath, err := locate()
	if err != nil {
		return err
	}

	cmd := exec.Command(binPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("csharpast: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("csharpast: stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("csharpast: start subprocess %q: %w", binPath, err)
	}

	r.cmd = cmd
	r.stdin = stdin
	r.stdout = bufio.NewReaderSize(stdout, 1<<20) // 1 MiB; some files have long lines
	r.started = true
	return nil
}

// locate resolves the relixq-roslyn binary. The first hit wins.
// Returns a wrapped astdet.ErrUnavailable if no binary is found.
func locate() (string, error) {
	if env := os.Getenv("RELIXQ_ROSLYN_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
		return "", fmt.Errorf("csharpast: RELIXQ_ROSLYN_BIN=%q does not exist: %w", env, astdet.ErrUnavailable)
	}

	name := "relixq-roslyn"
	if runtime.GOOS == "windows" {
		name = "relixq-roslyn.exe"
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	// Try ../tools/relixq-roslyn/bin/ relative to the running binary — the dev
	// layout when the worker is launched from its build output.
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), "..", "tools", "relixq-roslyn", "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("csharpast: relixq-roslyn binary not found on PATH or RELIXQ_ROSLYN_BIN: %w", astdet.ErrUnavailable)
}
