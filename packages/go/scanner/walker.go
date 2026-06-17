// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/relix-q/relix-q/suppression"
)

// MaxFileSize caps per-file reads at 5 MB.
const MaxFileSize int64 = 5 * 1024 * 1024

// FileEntry is a candidate file the scanner may inspect.
type FileEntry struct {
	AbsolutePath string
	RelativePath string
	Language     Language
	Size         int64
}

// WalkOptions tunes the file walker.
type WalkOptions struct {
	// IncludeOnly, if non-empty, restricts the walk to these relative paths
	// (used by diff mode).
	IncludeOnly map[string]struct{}
	// MaxFileBytes overrides the default per-file size cap.
	MaxFileBytes int64
}

// Walk yields every scannable file under root. .relixqignore / .gitignore and
// default vendored dirs are honored. Files over MaxFileSize are skipped with
// no entry (caller logs separately if needed).
func Walk(root string, opts WalkOptions) ([]FileEntry, error) {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = MaxFileSize
	}

	supSet, err := suppression.Load(root)
	if err != nil {
		return nil, err
	}

	var entries []FileEntry

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		if d.IsDir() {
			if supSet.IsExcluded(rel, true) {
				return filepath.SkipDir
			}
			return nil
		}

		if supSet.IsExcluded(rel, false) {
			return nil
		}

		if opts.IncludeOnly != nil {
			if _, ok := opts.IncludeOnly[rel]; !ok {
				return nil
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > opts.MaxFileBytes {
			return nil
		}

		lang := DetectLanguage(rel)
		if lang == LangUnknown {
			return nil
		}

		entries = append(entries, FileEntry{
			AbsolutePath: path,
			RelativePath: rel,
			Language:     lang,
			Size:         info.Size(),
		})
		return nil
	}

	if err := filepath.WalkDir(root, walkFn); err != nil {
		return nil, err
	}
	return entries, nil
}
