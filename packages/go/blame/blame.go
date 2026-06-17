// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package blame computes per-line git blame so each finding carries author +
// commit. v0.1 uses go-git's blame API; on a non-repo path it returns empty.
package blame

import (
	"github.com/go-git/go-git/v5"
)

// Blamer caches a repo handle so we don't re-open it per file. A nil receiver
// is safe — methods return empty results.
type Blamer struct {
	repo *git.Repository
}

// Open returns a Blamer for the repo at root, or nil if the path is not a git
// working tree.
func Open(root string) *Blamer {
	repo, err := git.PlainOpen(root)
	if err != nil {
		return nil
	}
	return &Blamer{repo: repo}
}

// LineInfo carries the blame fields embedded into Finding.
type LineInfo struct {
	Author string
	Commit string
}

// BlameLine returns the author/commit for a 1-based line number in the file
// (path relative to the repo root). Errors are swallowed: blame is best-effort.
func (b *Blamer) BlameLine(relPath string, line int) LineInfo {
	if b == nil || b.repo == nil || line <= 0 {
		return LineInfo{}
	}
	head, err := b.repo.Head()
	if err != nil {
		return LineInfo{}
	}
	commit, err := b.repo.CommitObject(head.Hash())
	if err != nil {
		return LineInfo{}
	}
	br, err := git.Blame(commit, relPath)
	if err != nil {
		return LineInfo{}
	}
	if line > len(br.Lines) {
		return LineInfo{}
	}
	bl := br.Lines[line-1]
	if bl == nil {
		return LineInfo{}
	}
	return LineInfo{
		Author: bl.Author,
		Commit: bl.Hash.String(),
	}
}
