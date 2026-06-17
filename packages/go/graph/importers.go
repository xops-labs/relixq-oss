// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

package graph

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BuildFromRepo walks repoRoot, extracts import edges for every file
// in a supported language, and returns the assembled graph. Files in
// languages without an extractor still get registered as nodes (so the
// directory-neighbor fallback works); they simply contribute no edges.
//
// Skipped: standard noise directories (node_modules, vendor, .venv,
// .git, __pycache__, target, dist, build). These contain third-party
// code whose import edges are not interesting for blast-radius
// computation on the user's own code.
func BuildFromRepo(repoRoot string) (*Graph, error) {
	g := New()

	// First pass: enumerate all files in the repo so import-resolvers
	// have a set to match against. Without this, an `import "foo/bar"`
	// statement has no way to know if "foo/bar.go" actually exists in
	// the repo.
	fileSet := map[string]struct{}{}
	err := filepath.WalkDir(repoRoot, func(absPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := strings.ToLower(d.Name())
			if base == "node_modules" || base == "vendor" || base == ".venv" ||
				base == ".git" || base == "__pycache__" || base == "target" ||
				base == "dist" || base == "build" || base == ".idea" || base == ".vscode" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(repoRoot, absPath)
		rel = filepath.ToSlash(rel)
		fileSet[strings.ToLower(rel)] = struct{}{}
		g.AddFile(rel)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Second pass: extract edges per language.
	for relLower := range fileSet {
		absPath := filepath.Join(repoRoot, relLower)
		// fileSet is lower-cased; on case-sensitive filesystems the
		// real file may have different case. Try the lower-case path
		// first; if it fails on a case-sensitive FS, fall back to a
		// rewalk that preserves case. (For the demo on Windows /
		// macOS the lower-case path always works.)
		f, openErr := os.Open(absPath)
		if openErr != nil {
			continue
		}
		ext := strings.ToLower(filepath.Ext(relLower))
		switch ext {
		case ".go":
			extractGoImports(f, relLower, g, fileSet)
		case ".py":
			extractPythonImports(f, relLower, g, fileSet)
		case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
			extractJSTSImports(f, relLower, g, fileSet)
		}
		f.Close()
	}

	return g, nil
}

// ----------------------------------------------------------------------
// Go imports
// ----------------------------------------------------------------------

var (
	goImportSingle = regexp.MustCompile(`^\s*import\s+(?:[a-zA-Z_][\w]*\s+|\.\s+|_\s+)?"([^"]+)"`)
	goImportBlock  = regexp.MustCompile(`^\s*(?:[a-zA-Z_][\w]*\s+|\.\s+|_\s+)?"([^"]+)"`)
)

// extractGoImports reads f line-by-line, pulling import paths out of
// `import "..."` and `import (...)` blocks. Each path is then resolved
// against fileSet to find a matching file inside the repo — the
// resolution treats the import path's last segment as a directory and
// adds an edge to every .go file inside it (if any). Imports of
// third-party / stdlib packages produce no edges (no matching file
// inside the repo) which is correct.
func extractGoImports(f *os.File, fromPath string, g *Graph, fileSet map[string]struct{}) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import (") {
			inBlock = true
			continue
		}
		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			if m := goImportBlock.FindStringSubmatch(line); m != nil {
				resolveGoImport(m[1], fromPath, g, fileSet)
			}
			continue
		}
		if m := goImportSingle.FindStringSubmatch(line); m != nil {
			resolveGoImport(m[1], fromPath, g, fileSet)
		}
	}
}

// resolveGoImport maps a Go import path to in-repo .go files. We
// scan fileSet for files whose path ends in `<last-segment-of-import>/`
// — a loose heuristic that catches intra-repo imports without a full
// Go module resolver. Third-party imports (github.com/..., stdlib)
// won't match anything in fileSet and silently produce no edges,
// which is the correct outcome — blast radius is about the user's
// own code, not the transitive third-party graph.
func resolveGoImport(importPath, fromPath string, g *Graph, fileSet map[string]struct{}) {
	// Skip stdlib (no dots in the path → not a domain-style module).
	if !strings.Contains(importPath, ".") && !strings.Contains(importPath, "/") {
		return
	}
	// Take the last 2-3 path segments as a heuristic. This lets us
	// match `github.com/relix-q/relix-q/agility` to
	// any `.go` file under `internal/agility/`.
	segs := strings.Split(importPath, "/")
	if len(segs) < 1 {
		return
	}
	suffix := strings.ToLower(segs[len(segs)-1]) + "/"
	// Match any in-repo .go file whose path contains the suffix.
	for f := range fileSet {
		if !strings.HasSuffix(f, ".go") {
			continue
		}
		if strings.Contains(f, "/"+suffix) || strings.HasPrefix(f, suffix) {
			g.AddEdge(fromPath, f)
		}
	}
}

// ----------------------------------------------------------------------
// Python imports
// ----------------------------------------------------------------------

var (
	pyImport     = regexp.MustCompile(`^\s*import\s+([\w\.]+)`)
	// pyFromImport captures BOTH the module path and the imported
	// names list, because in Python `from X import Y` the Y might be
	// a submodule (X/Y.py) rather than a name defined in X. We must
	// try both shapes to resolve correctly.
	pyFromImport = regexp.MustCompile(`^\s*from\s+([\w\.]+)\s+import\s+(.+)$`)
	pyFromRel    = regexp.MustCompile(`^\s*from\s+(\.+)([\w\.]*)\s+import\s+(.+)$`)
)

// extractPythonImports handles `import foo`, `import foo.bar`, and
// `from foo.bar import baz`. Relative imports (`from . import x`,
// `from ..foo import y`) are resolved against fromPath's directory.
//
// As with Go, third-party / stdlib imports won't match a file inside
// fileSet and produce no edges. This is correct: blast radius is
// about user code dependency, not external library dependency.
func extractPythonImports(f *os.File, fromPath string, g *Graph, fileSet map[string]struct{}) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if m := pyFromRel.FindStringSubmatch(line); m != nil {
			resolvePythonRelImport(m[1], m[2], m[3], fromPath, g, fileSet)
			continue
		}
		if m := pyFromImport.FindStringSubmatch(line); m != nil {
			// Resolve the module path itself (X) AND each imported
			// name (Y_i) as a candidate submodule (X.Y_i). This is
			// load-bearing: `from lib import helper` should add an
			// edge to lib/helper.py if it exists, not only to
			// lib/__init__.py.
			resolvePythonImport(m[1], fromPath, g, fileSet)
			for _, name := range parsePyImportNames(m[2]) {
				resolvePythonImport(m[1]+"."+name, fromPath, g, fileSet)
			}
			continue
		}
		if m := pyImport.FindStringSubmatch(line); m != nil {
			resolvePythonImport(m[1], fromPath, g, fileSet)
		}
	}
}

// parsePyImportNames extracts the bare names from the right side of a
// `from X import Y` statement. Handles single names, comma-separated
// lists, `as` aliases, and parenthesised multi-line forms (we see only
// the first line per the line-by-line scan, which is acceptable for v1).
func parsePyImportNames(rhs string) []string {
	rhs = strings.TrimSpace(rhs)
	rhs = strings.Trim(rhs, "()")
	if rhs == "" || rhs == "*" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(rhs, ",") {
		part = strings.TrimSpace(part)
		// `name as alias` → take only `name`.
		if i := strings.Index(part, " as "); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		// Trim trailing backslash (line continuation), comment, etc.
		if i := strings.Index(part, "#"); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		part = strings.TrimRight(part, "\\")
		part = strings.TrimSpace(part)
		if part != "" && part != "*" {
			out = append(out, part)
		}
	}
	return out
}

func resolvePythonImport(modulePath, fromPath string, g *Graph, fileSet map[string]struct{}) {
	// Convert dotted path to slash path and try both module.py and
	// module/__init__.py shapes.
	path := strings.ReplaceAll(modulePath, ".", "/")
	candidates := []string{
		strings.ToLower(path) + ".py",
		strings.ToLower(path) + "/__init__.py",
	}
	for f := range fileSet {
		for _, c := range candidates {
			if strings.HasSuffix(f, c) {
				g.AddEdge(fromPath, f)
			}
		}
	}
}

func resolvePythonRelImport(dots, modulePath, names, fromPath string, g *Graph, fileSet map[string]struct{}) {
	dir := dirOf(fromPath)
	// Each extra dot beyond the first walks up one level.
	for i := 1; i < len(dots); i++ {
		dir = dirOf(dir)
	}
	tryPath := func(modPath string) {
		if modPath == "" {
			return
		}
		path := strings.ReplaceAll(modPath, ".", "/")
		base := strings.TrimPrefix(dir+"/"+path, "./")
		candidates := []string{
			strings.ToLower(base) + ".py",
			strings.ToLower(base) + "/__init__.py",
		}
		for f := range fileSet {
			for _, c := range candidates {
				if f == c {
					g.AddEdge(fromPath, f)
				}
			}
		}
	}
	if modulePath != "" {
		tryPath(modulePath)
		for _, name := range parsePyImportNames(names) {
			tryPath(modulePath + "." + name)
		}
	} else {
		// `from . import x` — resolve x against the current package
		// directory (no extra module path segment).
		for _, name := range parsePyImportNames(names) {
			tryPath(name)
		}
	}
}

// ----------------------------------------------------------------------
// JavaScript / TypeScript imports
// ----------------------------------------------------------------------

var (
	jsImportFrom    = regexp.MustCompile(`(?:^|\s)import\s+(?:[^'"]*\sfrom\s+)?['"]([^'"]+)['"]`)
	jsImportRequire = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

// extractJSTSImports handles ES-module `import` and CommonJS
// `require()`. Only relative imports (./ or ../) are resolved against
// fromPath's directory; bare specifiers (`import 'lodash'`) refer to
// node_modules and aren't graph-relevant for this metric.
//
// Extension resolution tries .js, .jsx, .mjs, .cjs, .ts, .tsx, .d.ts,
// and `/<dir>/index.<ext>` — matching the Node resolver's common
// fallback chain at sufficient fidelity for the blast-radius signal.
func extractJSTSImports(f *os.File, fromPath string, g *Graph, fileSet map[string]struct{}) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		for _, m := range jsImportFrom.FindAllStringSubmatch(line, -1) {
			resolveJSImport(m[1], fromPath, g, fileSet)
		}
		for _, m := range jsImportRequire.FindAllStringSubmatch(line, -1) {
			resolveJSImport(m[1], fromPath, g, fileSet)
		}
	}
}

func resolveJSImport(spec, fromPath string, g *Graph, fileSet map[string]struct{}) {
	if !strings.HasPrefix(spec, ".") {
		return // bare specifier — node_modules dep
	}
	dir := dirOf(fromPath)
	// Walk up for ../
	for strings.HasPrefix(spec, "../") {
		dir = dirOf(dir)
		spec = strings.TrimPrefix(spec, "../")
	}
	spec = strings.TrimPrefix(spec, "./")
	base := dir + "/" + spec
	base = strings.TrimPrefix(base, "./")
	base = strings.ToLower(base)

	exts := []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".d.ts"}
	// Direct hit with extension (the spec already has one).
	if _, ok := fileSet[base]; ok {
		g.AddEdge(fromPath, base)
		return
	}
	for _, ext := range exts {
		cand := base + ext
		if _, ok := fileSet[cand]; ok {
			g.AddEdge(fromPath, cand)
			return
		}
		cand = base + "/index" + ext
		if _, ok := fileSet[cand]; ok {
			g.AddEdge(fromPath, cand)
			return
		}
	}
}
