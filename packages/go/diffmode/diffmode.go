// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package diffmode implements the PR delta scan: list files
// changed between base..HEAD and (1-hop) files that import them.
package diffmode

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// Changes is the set of files in scope for a delta scan, with per-file state.
type Changes struct {
	Files map[string]string // relative path → "new" | "modified" | "removed"
}

// Compare returns the diff of base..HEAD as a Changes set. Removed files keep
// their state but won't survive the file walker.
func Compare(repoPath, baseRef string) (*Changes, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	headHash, err := repo.Head()
	if err != nil {
		return nil, err
	}
	headCommit, err := repo.CommitObject(headHash.Hash())
	if err != nil {
		return nil, err
	}

	baseHash, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		return nil, err
	}
	baseCommit, err := repo.CommitObject(*baseHash)
	if err != nil {
		return nil, err
	}

	patch, err := baseCommit.Patch(headCommit)
	if err != nil {
		return nil, err
	}

	out := &Changes{Files: map[string]string{}}
	for _, fp := range patch.FilePatches() {
		from, to := fp.Files()
		switch {
		case from == nil && to != nil:
			out.Files[filepath.ToSlash(to.Path())] = "new"
		case from != nil && to == nil:
			out.Files[filepath.ToSlash(from.Path())] = "removed"
		case from != nil && to != nil:
			out.Files[filepath.ToSlash(to.Path())] = "modified"
		}
	}
	return out, nil
}

// ImportRegexes maps a file extension to a regex that captures the imported
// module's local-path component (when applicable). 1-hop importer detection
// is best-effort: it only catches local-path imports, not package names.
var importRegexes = map[string]*regexp.Regexp{
	".js":  regexp.MustCompile(`(?m)require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]`),
	".jsx": regexp.MustCompile(`(?m)require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]`),
	".ts":  regexp.MustCompile(`(?m)require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]`),
	".tsx": regexp.MustCompile(`(?m)require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]`),
	".py":  regexp.MustCompile(`(?m)^(?:from\s+([\w\.]+)\s+import|\bimport\s+([\w\.]+))`),
	".go":  regexp.MustCompile(`(?m)^\s*"([^"]+)"`),
}

// ExpandWithImporters walks repoPath and adds (rel-path → "modified") entries
// for files that import any file already in `changes`. Caller decides whether
// to honor or ignore the expansion.
func ExpandWithImporters(repoPath string, changes *Changes) error {
	if changes == nil || len(changes.Files) == 0 {
		return nil
	}

	// Build candidate-name set: basename without extension.
	candidates := make(map[string]string, len(changes.Files))
	for f := range changes.Files {
		stem := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		if stem != "" {
			candidates[stem] = f
		}
	}

	return filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		rx, ok := importRegexes[ext]
		if !ok {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			matches := rx.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				for _, mod := range m[1:] {
					if mod == "" {
						continue
					}
					stem := filepath.Base(mod)
					if _, hit := candidates[stem]; hit {
						rel, _ := filepath.Rel(repoPath, path)
						rel = filepath.ToSlash(rel)
						if _, exists := changes.Files[rel]; !exists {
							changes.Files[rel] = "modified"
						}
					}
				}
			}
		}
		return nil
	})
}
