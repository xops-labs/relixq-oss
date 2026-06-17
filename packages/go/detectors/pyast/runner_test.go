// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package pyast

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

// findInterpreter returns the first Python interpreter present on PATH, or ""
// if none are found. Used by tests that need a real subprocess and that
// should skip cleanly on machines without Python installed.
func findInterpreter(t *testing.T) string {
	t.Helper()
	for _, name := range pythonNames() {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// findScript returns the absolute path to relixq_python.py inside this
// repository, or "" if it can't be located from the test working directory.
func findScript(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/detectors/pyast → ../../..
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	candidate := filepath.Join(root, "tools", "relixq-python", "relixq_python.py")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func TestLocateInterpreter_envVarTakesPrecedence(t *testing.T) {
	// Pretend our own test binary is the interpreter — any existing file works.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELIXQ_PYTHON_BIN", self)

	got, err := locateInterpreter()
	if err != nil {
		t.Fatalf("locateInterpreter: %v", err)
	}
	if got != self {
		t.Errorf("locateInterpreter returned %q, want %q", got, self)
	}
}

func TestLocateInterpreter_envVarMissingWrapsErrUnavailable(t *testing.T) {
	t.Setenv("RELIXQ_PYTHON_BIN", "/nonexistent/python-fake")
	// Also clear PATH so the LookPath fallback inside the env-set branch
	// can't find the bogus name.
	t.Setenv("PATH", "")
	_, err := locateInterpreter()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, astdet.ErrUnavailable) {
		t.Errorf("expected wrapped ErrUnavailable, got %v", err)
	}
}

func TestLocateInterpreter_returnsErrUnavailable_whenMissing(t *testing.T) {
	t.Setenv("RELIXQ_PYTHON_BIN", "")
	t.Setenv("PATH", "")
	// On Windows, exec.LookPath also consults PATHEXT plus the running
	// process's directory; clearing PATH alone is usually enough, but be
	// defensive and clear PATHEXT too so we don't accidentally find a
	// neighbour python.exe via the empty path entry.
	t.Setenv("PATHEXT", "")
	_, err := locateInterpreter()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, astdet.ErrUnavailable) {
		t.Errorf("expected wrapped ErrUnavailable, got %v", err)
	}
}

func TestLocateScript_envVarTakesPrecedence(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELIXQ_PYTHON_SCRIPT", self)
	got, err := locateScript()
	if err != nil {
		t.Fatalf("locateScript: %v", err)
	}
	if got != self {
		t.Errorf("locateScript returned %q, want %q", got, self)
	}
}

func TestLocateScript_envVarMissingWrapsErrUnavailable(t *testing.T) {
	t.Setenv("RELIXQ_PYTHON_SCRIPT", "/nonexistent/relixq_python.py")
	// Also chdir into a temp dir so the working-dir walk-up fallback can't
	// find the real script and mask the env-var failure.
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	_, err = locateScript()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, astdet.ErrUnavailable) {
		t.Errorf("expected wrapped ErrUnavailable, got %v", err)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("X.py", []byte("x = 1"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
	if r.started {
		t.Error("subprocess should not be started when no rules apply")
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	r := &runner{}
	regexRule := &rules.Rule{
		ID:       "X_REGEX",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	matches, err := r.Run("X.py", []byte("x = 1"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
	if r.started {
		t.Error("subprocess should not be started when no AST rules apply")
	}
}

func TestRun_unavailableBinaryReturnsNilSilently(t *testing.T) {
	t.Setenv("RELIXQ_PYTHON_BIN", "/nonexistent/python-fake")
	t.Setenv("PATH", "")
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", "")
	}

	r := &runner{}
	astRule := &rules.Rule{
		ID:       "X_AST",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:hashlib.sha1"},
	}
	matches, err := r.Run("X.py", []byte("x = 1"), []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("first Run should swallow ErrUnavailable as nil: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when interpreter unavailable, got %v", matches)
	}
	// Second call should also return (nil, nil) without retrying or logging.
	matches, err = r.Run("X.py", []byte("x = 1"), []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("second Run after unavailable: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches on second call, got %v", matches)
	}
	if !r.unavailable {
		t.Error("runner.unavailable should be true after first Run with missing interpreter")
	}
}

func TestRun_unavailableScriptReturnsNilSilently(t *testing.T) {
	// Interpreter present, script missing → same silent-fallback semantics.
	interp := findInterpreter(t)
	if interp == "" {
		t.Skip("no Python interpreter on PATH; the missing-script branch is exercised via the env-var test above")
	}
	t.Setenv("RELIXQ_PYTHON_BIN", interp)
	t.Setenv("RELIXQ_PYTHON_SCRIPT", "/nonexistent/relixq_python.py")
	// Chdir into a temp dir so the working-dir walk-up fallback can't
	// pick up the in-repo script.
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	r := &runner{}
	astRule := &rules.Rule{
		ID:       "X_AST",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:hashlib.sha1"},
	}
	matches, err := r.Run("X.py", []byte("x = 1"), []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("Run should swallow ErrUnavailable as nil: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when script unavailable, got %v", matches)
	}
	if !r.unavailable {
		t.Error("runner.unavailable should be true after Run with missing script")
	}
}

// TestRun_endToEnd exercises the full subprocess path. Skipped if Python is
// not on PATH — to run, install Python 3.8+.
func TestRun_endToEnd(t *testing.T) {
	interp := findInterpreter(t)
	if interp == "" {
		t.Skip("no Python interpreter on PATH; install Python 3.8+ to exercise this test")
	}
	script := findScript(t)
	if script == "" {
		t.Skip("relixq_python.py not found in tools/relixq-python; check repo layout")
	}
	t.Setenv("RELIXQ_PYTHON_BIN", interp)
	t.Setenv("RELIXQ_PYTHON_SCRIPT", script)

	src := []byte(`import hashlib

def hash_password(pw: bytes) -> bytes:
    return hashlib.sha1(pw).digest()
`)
	astRule := &rules.Rule{
		ID:       "PYTHON_HASHLIB_SHA1_TEST",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:hashlib.sha1"},
	}

	r := &runner{}
	matches, err := r.Run("X.py", src, []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "PYTHON_HASHLIB_SHA1_TEST" {
		t.Errorf("match.Rule.ID = %q, want PYTHON_HASHLIB_SHA1_TEST", matches[0].Rule.ID)
	}
	if matches[0].Line != 4 {
		t.Errorf("match.Line = %d, want 4", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "hashlib.sha1(pw)") {
		t.Errorf("match.Snippet = %q, want substring 'hashlib.sha1(pw)'", matches[0].Snippet)
	}
}

// TestRun_endToEndAllPythonRules verifies the converted rule pack still
// triggers the same 5 IDs against the canonical fixture.
func TestRun_endToEndAllPythonRules(t *testing.T) {
	interp := findInterpreter(t)
	if interp == "" {
		t.Skip("no Python interpreter on PATH; install Python 3.8+ to exercise this test")
	}
	script := findScript(t)
	if script == "" {
		t.Skip("relixq_python.py not found")
	}
	t.Setenv("RELIXQ_PYTHON_BIN", interp)
	t.Setenv("RELIXQ_PYTHON_SCRIPT", script)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	fixturePath := filepath.Join(root, "fixtures", "vulnerable-python", "auth.py")
	src, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("fixture %s not readable: %v", fixturePath, err)
	}

	// Mirror the queries the YAML pack will use after conversion.
	cases := []struct {
		id    string
		query string
	}{
		{"PYTHON_CRYPTOGRAPHY_RSA_GEN", "call:rsa.generate_private_key"},
		{"PYTHON_PYCRYPTO_RSA", "call:RSA.generate"},
		{"PYTHON_HASHLIB_SHA1", "call:hashlib.sha1"},
		{"PYTHON_HASHLIB_MD5", "call:hashlib.md5"},
		{"PYTHON_ECDSA_GEN", "call:ec.generate_private_key"},
	}
	var astRules []*rules.Rule
	for _, c := range cases {
		astRules = append(astRules, &rules.Rule{
			ID:       c.id,
			Detector: rules.Detector{Type: rules.DetectorAST, Query: c.query},
		})
	}

	r := &runner{}
	matches, err := r.Run(fixturePath, src, astRules)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	hit := map[string]bool{}
	for _, m := range matches {
		hit[m.Rule.ID] = true
	}
	want := []string{
		"PYTHON_CRYPTOGRAPHY_RSA_GEN",
		"PYTHON_HASHLIB_SHA1",
		"PYTHON_HASHLIB_MD5",
		"PYTHON_ECDSA_GEN",
	}
	for _, id := range want {
		if !hit[id] {
			t.Errorf("expected rule %s to fire against fixture, did not. matches=%+v", id, matches)
		}
	}
	// PYTHON_PYCRYPTO_RSA does NOT need to fire — the fixture uses cryptography.hazmat,
	// not PyCrypto. But the rule must compile and not produce a false positive either.
	if hit["PYTHON_PYCRYPTO_RSA"] {
		t.Errorf("PYTHON_PYCRYPTO_RSA should not fire against the cryptography.hazmat fixture")
	}
}
