// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package jstsast

import (
	"testing"

	gjast "github.com/dop251/goja/ast"

	"github.com/relix-q/relix-q/rules"
)

// Regression: a try/catch with no finally clause leaves TryStatement.Finally
// as a nil *BlockStatement. Passed through walk's gjast.Node interface
// parameter it becomes a typed nil that `n == nil` cannot catch, and the
// BlockStatement case dereferenced it (SIGSEGV at walk.go:31, found scanning
// a real uploaded project on 2026-06-11).
func TestWalk_typedNilNodeIsSkipped(t *testing.T) {
	var typedNil *gjast.BlockStatement
	visited := 0
	walk(typedNil, func(gjast.Node) { visited++ }) // must not panic
	if visited != 0 {
		t.Errorf("typed-nil node was visited %d times, want 0", visited)
	}
}

func TestRun_tryCatchWithoutFinallyDoesNotPanic(t *testing.T) {
	src := []byte(`
try {
  doWork();
} catch (e) {
  console.error(e);
}
const h = crypto.createHash('md5');
`)
	r := &runner{}
	rule := mustRule("X_MD5", "call:crypto.createHash")
	matches, err := r.Run("X.js", src, []*rules.Rule{rule})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findMatch(t, matches, "X_MD5") == nil {
		t.Errorf("expected the createHash call after the try/catch to still match")
	}
}
