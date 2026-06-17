// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package pyast implements a Python AST runner by talking to a long-running
// CPython subprocess (tools/relixq-python/relixq_python.py) over JSONL on
// stdin/stdout (detector.type=ast).
//
// Query format (detector.query in the rule YAML):
//
//	call:<module>.<func>     — matches module.func(...) call expressions
//	import:<module>          — matches `import module` / `from module import ...`
//	attr:<module>.<name>     — matches module.Name attribute access not being called
//
// Subprocess discovery (first wins):
//  1. $RELIXQ_PYTHON_BIN points to a Python interpreter (python / python3 / pythonw / a venv).
//  2. python3 on $PATH
//  3. python on $PATH
//
// Script discovery (first wins):
//  1. $RELIXQ_PYTHON_SCRIPT points to relixq_python.py
//  2. ../tools/relixq-python/relixq_python.py relative to the running binary
//  3. tools/relixq-python/relixq_python.py relative to the current working dir
//     (covers `go test ./...` from the module root or any subdir).
//
// If either the interpreter or the script cannot be located, the runner logs
// once to stderr and Run returns (nil, nil) silently so the scanner falls
// back to regex-only for .py files without spamming a warning per file.
package pyast

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
	astdet.Register("python", &runner{})
}

type runner struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      *bufio.Reader
	started     bool
	unavailable bool  // sticky: subprocess binary or script is not installed
	commErr     error // sticky: subprocess running but communication failed
	seq         atomic.Uint64
}

// Wire-format DTOs (mirror tools/relixq-python protocol).

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
// Returns (nil, nil) silently when the subprocess interpreter or script is
// unavailable; the scanner then falls back to regex-only for Python files.
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
					"pyast: relixq-python subprocess unavailable; Python AST rules will be skipped (set RELIXQ_PYTHON_BIN to a Python interpreter to enable). detail: %v\n",
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
		return nil, fmt.Errorf("pyast: marshal request: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := r.stdin.Write(payload); err != nil {
		r.commErr = fmt.Errorf("pyast: write to subprocess: %w", err)
		return nil, r.commErr
	}

	line, err := r.stdout.ReadBytes('\n')
	if err != nil {
		r.commErr = fmt.Errorf("pyast: read from subprocess: %w", err)
		return nil, r.commErr
	}

	var resp responseDTO
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("pyast: unmarshal response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("pyast: subprocess error: %s", resp.Error)
	}
	if resp.ID != id {
		return nil, fmt.Errorf("pyast: response id mismatch (want %s got %s)", id, resp.ID)
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
	interp, err := locateInterpreter()
	if err != nil {
		return err
	}
	script, err := locateScript()
	if err != nil {
		return err
	}

	cmd := exec.Command(interp, script)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("pyast: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("pyast: stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("pyast: start subprocess %q %q: %w", interp, script, err)
	}

	r.cmd = cmd
	r.stdin = stdin
	r.stdout = bufio.NewReaderSize(stdout, 1<<20) // 1 MiB; some files have long lines
	r.started = true
	return nil
}

// locateInterpreter resolves the Python interpreter. The first hit wins.
// Returns a wrapped astdet.ErrUnavailable if no interpreter is found.
func locateInterpreter() (string, error) {
	if env := os.Getenv("RELIXQ_PYTHON_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
		// Allow $RELIXQ_PYTHON_BIN to also be a bare name like "python3" that's
		// resolvable via PATH (matches how RELIXQ_ROSLYN_BIN behaves for users
		// who set it to a name rather than a full path).
		if p, err := exec.LookPath(env); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("pyast: RELIXQ_PYTHON_BIN=%q does not exist: %w", env, astdet.ErrUnavailable)
	}

	for _, name := range pythonNames() {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("pyast: no Python interpreter found on PATH (looked for %v): %w", pythonNames(), astdet.ErrUnavailable)
}

// pythonNames returns the interpreter names to probe on $PATH, in priority
// order. python3 first so we never accidentally pick up a leftover Python 2
// on systems that still ship it as `python`.
func pythonNames() []string {
	if runtime.GOOS == "windows" {
		// Windows installs typically expose `python.exe` (the launcher routes
		// to the default 3.x install) but a parallel `python3.exe` is also
		// common via the Store package, so check both.
		return []string{"python3.exe", "python.exe", "python3", "python"}
	}
	return []string{"python3", "python"}
}

// locateScript resolves the relixq_python.py script. The first hit wins.
// Returns a wrapped astdet.ErrUnavailable if the script cannot be found.
func locateScript() (string, error) {
	if env := os.Getenv("RELIXQ_PYTHON_SCRIPT"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
		return "", fmt.Errorf("pyast: RELIXQ_PYTHON_SCRIPT=%q does not exist: %w", env, astdet.ErrUnavailable)
	}

	// Try ../tools/relixq-python/relixq_python.py relative to the running
	// binary — the dev layout when the worker is launched from its build
	// output (e.g. bin/relixq-scan-code).
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), "..", "tools", "relixq-python", "relixq_python.py")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Try walking up from the current working directory looking for
	// tools/relixq-python/relixq_python.py. Covers `go test ./...` invocations
	// from any depth inside the module.
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 8; i++ {
			candidate := filepath.Join(dir, "tools", "relixq-python", "relixq_python.py")
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", fmt.Errorf("pyast: relixq_python.py not found near binary or working directory: %w", astdet.ErrUnavailable)
}
