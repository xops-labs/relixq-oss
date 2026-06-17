// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package sbom

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dependency is one parsed package reference from a manifest file. The
// LineNumber points back to where the package was declared so an
// SBOM-derived finding can report the manifest line that exposed the
// risk — the same UX as an AST finding pointing at a source line.
type Dependency struct {
	Ecosystem   Ecosystem
	PackageName string
	Version     string // optional — may be empty if the manifest doesn't pin
	Manifest    string // relative path of the manifest file
	LineNumber  int
}

// ParseManifest dispatches on filename and returns the dependencies it
// declares. Unknown manifest formats return (nil, nil) — silent skip.
//
// This function does not consult the knowledge base. Callers (see
// Ingest in ingest.go) join the dependency stream against Lookup to
// decide which ones produce findings. Separation keeps the parsers
// pure-text and trivially testable.
func ParseManifest(absPath, relPath string) ([]Dependency, error) {
	base := strings.ToLower(filepath.Base(relPath))

	switch {
	// ----- Python -----
	case base == "requirements.txt",
		strings.HasPrefix(base, "requirements-") && strings.HasSuffix(base, ".txt"):
		return parseRequirementsTxt(absPath, relPath)
	case base == "pipfile":
		return parsePipfile(absPath, relPath)
	case base == "pyproject.toml":
		return parsePyprojectToml(absPath, relPath)

	// ----- JavaScript / Node -----
	case base == "package.json":
		return parsePackageJSON(absPath, relPath)

	// ----- Go -----
	case base == "go.mod":
		return parseGoMod(absPath, relPath)
	}
	return nil, nil
}

// IsManifest returns true if the file is one ParseManifest knows. Used
// by Ingest to filter the walked file list cheaply.
func IsManifest(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	switch base {
	case "requirements.txt", "pipfile", "pyproject.toml",
		"package.json", "go.mod":
		return true
	}
	if strings.HasPrefix(base, "requirements-") && strings.HasSuffix(base, ".txt") {
		return true
	}
	return false
}

// ----------------------------------------------------------------------
// Python parsers
// ----------------------------------------------------------------------

// parseRequirementsTxt handles the pip requirements.txt format. The
// format is line-oriented; each line is either a comment, blank, an
// option (-r, --index-url), or a requirement specifier like:
//
//	package
//	package==1.2.3
//	package>=1.2,<2.0
//	package[extra]==1.2.3
//	package @ https://...
//
// We extract the bare package name (before any version specifier,
// extras bracket, or URL fragment) and the version if present.
func parseRequirementsTxt(absPath, relPath string) ([]Dependency, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip pip options.
		if strings.HasPrefix(line, "-") {
			continue
		}
		// Drop trailing inline comment.
		if i := strings.Index(line, " #"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		name, version := splitRequirementsSpec(line)
		if name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem:   EcosystemPython,
			PackageName: name,
			Version:     version,
			Manifest:    relPath,
			LineNumber:  lineNo,
		})
	}
	return deps, scanner.Err()
}

// splitRequirementsSpec separates the package name from the version
// specifier in a pip requirement line. Handles:
//
//	pkg
//	pkg==1.2
//	pkg>=1
//	pkg[extra]==1.2
//	pkg @ url
//	pkg ; python_version >= "3.8"
func splitRequirementsSpec(line string) (name, version string) {
	// Drop env-marker / URL trailer.
	for _, sep := range []string{";", " @ "} {
		if i := strings.Index(line, sep); i >= 0 {
			line = line[:i]
		}
	}
	line = strings.TrimSpace(line)
	// Strip extras: pkg[a,b]==1.2 → pkg==1.2 (we don't track extras).
	if i := strings.Index(line, "["); i >= 0 {
		if j := strings.Index(line[i:], "]"); j >= 0 {
			line = line[:i] + line[i+j+1:]
		}
	}
	// Find the first version-operator character.
	idx := strings.IndexAny(line, "=<>!~ ")
	if idx < 0 {
		return strings.TrimSpace(line), ""
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx:])
}

// parsePipfile is a minimal Pipfile reader. We only extract the
// [packages] and [dev-packages] sections; the strict TOML grammar is
// overkill for the simple "name = version" patterns these sections use.
func parsePipfile(absPath, relPath string) ([]Dependency, error) {
	return parseSimpleTomlSection(absPath, relPath, EcosystemPython,
		[]string{"[packages]", "[dev-packages]"})
}

// parsePyprojectToml extracts dependencies from a pyproject.toml. v1
// only handles the PEP-621 [project.dependencies] array and the
// poetry [tool.poetry.dependencies] section. Build backends not yet
// in scope.
func parsePyprojectToml(absPath, relPath string) ([]Dependency, error) {
	// PEP-621 array form
	arrayDeps, err := parsePyprojectArrayDeps(absPath, relPath)
	if err != nil {
		return nil, err
	}
	// Poetry section form
	poetryDeps, err := parseSimpleTomlSection(absPath, relPath, EcosystemPython,
		[]string{"[tool.poetry.dependencies]", "[tool.poetry.dev-dependencies]"})
	if err != nil {
		return nil, err
	}
	return append(arrayDeps, poetryDeps...), nil
}

// parseSimpleTomlSection is a deliberately lightweight reader that
// pulls `name = "spec"` lines from a [section] in a TOML-shaped file.
// It does NOT understand TOML's full grammar (arrays, inline tables,
// multi-line strings); the trade-off is zero dependencies. If a manifest
// uses TOML constructs that defeat this parser, that manifest will
// emit no findings rather than producing wrong findings — silent
// fallback consistent with the rest of the scanner's "log + skip"
// policy on malformed input.
func parseSimpleTomlSection(absPath, relPath string, ecosystem Ecosystem, sectionHeaders []string) ([]Dependency, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	lineNo := 0
	inSection := false
	wantHeaders := map[string]struct{}{}
	for _, h := range sectionHeaders {
		wantHeaders[h] = struct{}{}
	}

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			_, inSection = wantHeaders[line]
			continue
		}
		if !inSection {
			continue
		}
		// name = "spec"  or  name = { version = "spec", ... }
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(line[:eq]), "\"'")
		if name == "" || name == "python" {
			continue
		}
		spec := strings.TrimSpace(line[eq+1:])
		version := stripQuotes(spec)
		deps = append(deps, Dependency{
			Ecosystem:   ecosystem,
			PackageName: name,
			Version:     version,
			Manifest:    relPath,
			LineNumber:  lineNo,
		})
	}
	return deps, scanner.Err()
}

// parsePyprojectArrayDeps reads the PEP-621 form:
//
//	[project]
//	dependencies = ["foo>=1.2", "bar==2.0"]
//
// Each array entry is a requirements.txt-style specifier.
func parsePyprojectArrayDeps(absPath, relPath string) ([]Dependency, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	lineNo := 0
	inProject := false
	inDepsArray := false

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inProject = (line == "[project]")
			inDepsArray = false
			continue
		}
		if !inProject {
			continue
		}
		if strings.HasPrefix(line, "dependencies") && strings.Contains(line, "=") {
			inDepsArray = true
			// Inline single-line array: dependencies = ["a", "b"]
			if i := strings.Index(line, "["); i >= 0 {
				body := line[i+1:]
				if j := strings.LastIndex(body, "]"); j >= 0 {
					body = body[:j]
					inDepsArray = false
				}
				for _, entry := range splitArrayItems(body) {
					name, version := splitRequirementsSpec(stripQuotes(entry))
					if name != "" {
						deps = append(deps, Dependency{
							Ecosystem: EcosystemPython, PackageName: name, Version: version,
							Manifest: relPath, LineNumber: lineNo,
						})
					}
				}
			}
			continue
		}
		if inDepsArray {
			if strings.HasPrefix(line, "]") {
				inDepsArray = false
				continue
			}
			// Item line like:  "foo>=1.2",
			entry := strings.TrimSuffix(strings.TrimSpace(line), ",")
			entry = stripQuotes(entry)
			name, version := splitRequirementsSpec(entry)
			if name != "" {
				deps = append(deps, Dependency{
					Ecosystem: EcosystemPython, PackageName: name, Version: version,
					Manifest: relPath, LineNumber: lineNo,
				})
			}
		}
	}
	return deps, scanner.Err()
}

func splitArrayItems(body string) []string {
	var out []string
	for _, p := range strings.Split(body, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// ----------------------------------------------------------------------
// JavaScript / Node parsers
// ----------------------------------------------------------------------

// packageJSON is the subset of npm package.json we read. node-modules
// resolution is out of scope; we trust the manifest's declared deps.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parsePackageJSON(absPath, relPath string) ([]Dependency, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		// Malformed package.json — treat as no deps, consistent with
		// the rest of the scanner's malformed-input policy. Log via
		// returning the error so the CLI surfaces it; callers may
		// choose to ignore.
		return nil, fmt.Errorf("parse %s: %w", relPath, err)
	}
	// package.json is a single JSON blob — there is no useful per-dep
	// line number in v1. We approximate by linearly scanning the raw
	// file content for each dependency name. This is O(N×M) but N×M
	// is tiny for real package.json files.
	lines := splitLines(data)
	var deps []Dependency
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for name, version := range m {
			line := findPackageJSONLine(lines, name)
			deps = append(deps, Dependency{
				Ecosystem:   EcosystemJavaScript,
				PackageName: name,
				Version:     version,
				Manifest:    relPath,
				LineNumber:  line,
			})
		}
	}
	return deps, nil
}

func splitLines(data []byte) []string {
	return strings.Split(string(data), "\n")
}

// findPackageJSONLine searches the raw file lines for the first
// occurrence of `"<name>":`. Imperfect — a comment containing the
// package name would also match — but package.json prohibits
// comments, so practical risk is zero. Returns 0 (which JSON emitters
// will render as 0 → an honest "unknown line") when not found.
func findPackageJSONLine(lines []string, name string) int {
	target := "\"" + name + "\""
	for i, line := range lines {
		if strings.Contains(line, target) {
			return i + 1
		}
	}
	return 0
}

// ----------------------------------------------------------------------
// Go parsers
// ----------------------------------------------------------------------

// parseGoMod reads a go.mod file. The grammar is small enough to read
// by hand. We extract module names from `require <module> <version>`
// lines, both single and block forms:
//
//	require example.com/foo v1.2.3
//	require (
//	    example.com/foo v1.2.3
//	    example.com/bar v0.4.5 // indirect
//	)
//
// The `// indirect` marker is preserved as-is — we don't filter
// indirect deps because crypto risk transfers through transitive
// imports regardless of whether the consumer named the dep directly.
func parseGoMod(absPath, relPath string) ([]Dependency, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	lineNo := 0
	inRequireBlock := false

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			if dep, ok := parseGoModRequireLine(line, relPath, lineNo); ok {
				deps = append(deps, dep)
			}
			continue
		}
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			if dep, ok := parseGoModRequireLine(rest, relPath, lineNo); ok {
				deps = append(deps, dep)
			}
		}
	}
	return deps, scanner.Err()
}

// parseGoModRequireLine extracts <module> <version> from a `require`
// body (with or without the leading require keyword). Trailing
// `// indirect` is stripped from the version. Returns (_, false) if the
// line is structurally not a require entry.
func parseGoModRequireLine(line, relPath string, lineNo int) (Dependency, bool) {
	// Strip trailing comment / indirect marker.
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return Dependency{}, false
	}
	return Dependency{
		Ecosystem:   EcosystemGo,
		PackageName: parts[0],
		Version:     parts[1],
		Manifest:    relPath,
		LineNumber:  lineNo,
	}, true
}
