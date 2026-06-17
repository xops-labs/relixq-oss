// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package ast is a placeholder for the future Tree-sitter / Roslyn-backed AST
// detector (component "AST Analyzers"). v0.1 ships regex-only because
// the build environment lacks a CGO C toolchain. The Detector interface below
// is the seam a future PR fills in.
package ast

import (
	"errors"

	"github.com/relix-q/relix-q/rules"
)

// ErrUnavailable is returned by Run when no AST runtime is registered for the
// rule's language.
var ErrUnavailable = errors.New("ast detector unavailable in this build")

// Match describes one AST query hit. Mirrors the regex Match shape so the
// scanner can merge results uniformly.
type Match struct {
	Rule    *rules.Rule
	Line    int
	Column  int
	Snippet string
	Context []string
}

// Runner is the per-language AST analyzer. Implementations register themselves
// via Register(language, runner). Until then, Run returns ErrUnavailable and
// the scanner skips AST rules with a structured warn-level log.
type Runner interface {
	Run(filePath string, source []byte, applicable []*rules.Rule) ([]Match, error)
}

var registry = map[string]Runner{}

// Register installs a runner for a language. Call from a runtime-specific
// package's init() — never required by callers.
func Register(language string, r Runner) {
	registry[language] = r
}

// Get returns the registered runner for language, or nil.
func Get(language string) Runner { return registry[language] }
