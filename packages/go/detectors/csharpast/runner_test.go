// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package csharpast

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

// locateRoslynBin returns the path to the published relixq-roslyn binary if it
// exists under tools/relixq-roslyn/bin, or "" otherwise. Tests that need the
// real subprocess use this to t.Skip() cleanly when the binary hasn't been
// built.
func locateRoslynBin(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/detectors/csharpast → ../../..
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	name := "relixq-roslyn"
	if runtime.GOOS == "windows" {
		name = "relixq-roslyn.exe"
	}
	for _, c := range []string{
		filepath.Join(root, "tools", "relixq-roslyn", "bin", name),
		filepath.Join(root, "tools", "relixq-roslyn", "bin", "Release", "net8.0", name),
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func TestLocate_envVarTakesPrecedence(t *testing.T) {
	// Pretend our own binary is the Roslyn one — any existing file works.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELIXQ_ROSLYN_BIN", self)

	got, err := locate()
	if err != nil {
		t.Fatalf("locate: %v", err)
	}
	if got != self {
		t.Errorf("locate returned %q, want %q", got, self)
	}
}

func TestLocate_returnsErrUnavailable_whenMissing(t *testing.T) {
	t.Setenv("RELIXQ_ROSLYN_BIN", "")
	t.Setenv("PATH", "")
	_, err := locate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, astdet.ErrUnavailable) {
		t.Errorf("expected wrapped ErrUnavailable, got %v", err)
	}
}

func TestLocate_envVarMissingFileWrapsErrUnavailable(t *testing.T) {
	t.Setenv("RELIXQ_ROSLYN_BIN", "/nonexistent/relixq-roslyn-fake")
	_, err := locate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, astdet.ErrUnavailable) {
		t.Errorf("expected wrapped ErrUnavailable, got %v", err)
	}
}

func TestRun_emptyApplicableReturnsNil(t *testing.T) {
	r := &runner{}
	matches, err := r.Run("X.cs", []byte("class T {}"), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
}

func TestRun_noASTRulesReturnsNil(t *testing.T) {
	r := &runner{}
	regexRule := &rules.Rule{
		ID:       "X_REGEX",
		Detector: rules.Detector{Type: rules.DetectorRegex, Pattern: "foo"},
	}
	matches, err := r.Run("X.cs", []byte("class T {}"), []*rules.Rule{regexRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when only regex rules supplied, got %v", matches)
	}
}

func TestRun_unavailableBinaryReturnsNilSilently(t *testing.T) {
	t.Setenv("RELIXQ_ROSLYN_BIN", "/nonexistent/relixq-roslyn-fake")

	r := &runner{}
	astRule := &rules.Rule{
		ID:       "X_AST",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:RSA.Create"},
	}
	matches, err := r.Run("X.cs", []byte("class T {}"), []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("first Run should swallow ErrUnavailable as nil: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when binary unavailable, got %v", matches)
	}
	// Second call should also return (nil, nil) without retrying or logging.
	matches, err = r.Run("X.cs", []byte("class T {}"), []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("second Run after unavailable: %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches on second call, got %v", matches)
	}
	if !r.unavailable {
		t.Error("runner.unavailable should be true after first Run with missing binary")
	}
}

// TestRun_endToEnd exercises the full subprocess path. Skipped if the .NET
// binary hasn't been published — to run, `dotnet publish` in
// tools/relixq-roslyn first.
func TestRun_endToEnd(t *testing.T) {
	bin := locateRoslynBin(t)
	if bin == "" {
		t.Skip("relixq-roslyn binary not built; run `dotnet publish` in tools/relixq-roslyn to exercise this test")
	}
	t.Setenv("RELIXQ_ROSLYN_BIN", bin)

	src := []byte(`using System.Security.Cryptography;
namespace Acme;
public static class T
{
    public static RSA M() => RSA.Create(2048);
}
`)
	astRule := &rules.Rule{
		ID:       "CSHARP_RSA_CREATE_TEST",
		Detector: rules.Detector{Type: rules.DetectorAST, Query: "call:RSA.Create"},
	}

	r := &runner{}
	matches, err := r.Run("X.cs", src, []*rules.Rule{astRule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Rule.ID != "CSHARP_RSA_CREATE_TEST" {
		t.Errorf("match.Rule.ID = %q, want CSHARP_RSA_CREATE_TEST", matches[0].Rule.ID)
	}
	if matches[0].Line != 5 {
		t.Errorf("match.Line = %d, want 5", matches[0].Line)
	}
	if !strings.Contains(matches[0].Snippet, "RSA.Create(2048)") {
		t.Errorf("match.Snippet = %q, want substring 'RSA.Create(2048)'", matches[0].Snippet)
	}
}
