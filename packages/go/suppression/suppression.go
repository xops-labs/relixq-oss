// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package suppression honors .relixqignore files (gitignore syntax) and
// inline `// relixq-ignore[: rule-id[, rule-id]]` comments.
package suppression

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Default vendor-ish dirs we always skip unless the user opts in.
var defaultExcludes = []string{
	".git", ".svn", ".hg",
	"node_modules", "vendor", "bower_components",
	"bin", "obj", "build", "dist", "target", "out",
	"__pycache__", ".pytest_cache", ".tox",
	".idea", ".vscode", ".vs",
	".terraform",
}

// Set is the parsed suppression rules for one repo root.
type Set struct {
	root     string
	patterns []pattern
}

type pattern struct {
	negate  bool
	dirOnly bool
	rooted  bool
	regex   *regexp.Regexp
}

// Load reads <root>/.relixqignore (and falls back to .gitignore if absent).
// A missing file is not an error.
func Load(root string) (*Set, error) {
	s := &Set{root: root}

	for _, name := range []string{".relixqignore", ".gitignore"} {
		path := filepath.Join(root, name)
		if err := s.loadFile(path); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}

	for _, def := range defaultExcludes {
		s.add("/" + def + "/")
	}
	return s, nil
}

func (s *Set) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.add(line)
	}
	return sc.Err()
}

// IsExcluded reports whether the given path (relative to the root) should be skipped.
func (s *Set) IsExcluded(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	excluded := false
	for _, p := range s.patterns {
		target := rel
		if p.dirOnly && !isDir {
			// Gitignore semantics: a dir-only pattern (`build/`) never matches
			// a file directly, but it ignores everything under a matching
			// directory — so test the file's parent path instead.
			dir := path.Dir(rel)
			if dir == "." {
				continue
			}
			target = dir
		}
		if p.regex.MatchString(target) {
			excluded = !p.negate
		}
	}
	return excluded
}

func (s *Set) add(line string) {
	p := pattern{}
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if strings.HasPrefix(line, "/") {
		p.rooted = true
		line = strings.TrimPrefix(line, "/")
	}
	rx := globToRegex(line, p.rooted)
	p.regex = regexp.MustCompile(rx)
	s.patterns = append(s.patterns, p)
}

// globToRegex converts a gitignore-style pattern into a regex anchored to the
// repo root (or any path component, when not rooted).
func globToRegex(glob string, rooted bool) string {
	var b strings.Builder
	if rooted {
		b.WriteString("^")
	} else {
		b.WriteString("(^|/)")
	}
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("(/|$)")
	return b.String()
}

// InlineMarker matches `// relixq-ignore`, `# relixq-ignore`, optionally with
// a rule-id list: `// relixq-ignore: CSHARP_RSA_CREATE, CSHARP_SHA1`.
var inlineRe = regexp.MustCompile(`relixq-ignore(?:\s*:\s*([A-Za-z0-9_\-,\s]+))?`)

// InlineSuppression captures the rule IDs suppressed by an inline comment, or
// nil to suppress all rules at that line.
type InlineSuppression struct {
	All     bool
	RuleIDs map[string]struct{}
}

// ParseInline scans a line of source for an inline relixq-ignore directive.
// Returns nil if no directive is present.
func ParseInline(line string) *InlineSuppression {
	m := inlineRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	if m[1] == "" {
		return &InlineSuppression{All: true}
	}
	out := &InlineSuppression{RuleIDs: map[string]struct{}{}}
	for _, raw := range strings.Split(m[1], ",") {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		out.RuleIDs[id] = struct{}{}
	}
	return out
}

// Suppresses reports whether the given rule id is suppressed by this directive.
func (s *InlineSuppression) Suppresses(ruleID string) bool {
	if s == nil {
		return false
	}
	if s.All {
		return true
	}
	_, ok := s.RuleIDs[ruleID]
	return ok
}

// BuildInlineMap parses every line of source for inline `relixq-ignore`
// directives and returns a map keyed by line number: a directive on line N
// applies to line N AND line N+1 (so the directive can sit immediately above
// the call site).
//
// Both the regex and AST detectors filter through this map so suppression
// semantics are uniform across detector backends.
func BuildInlineMap(lines []string) map[int]*InlineSuppression {
	out := map[int]*InlineSuppression{}
	for i, line := range lines {
		d := ParseInline(line)
		if d == nil {
			continue
		}
		out[i+1] = d
		out[i+2] = d
	}
	return out
}

// IsSuppressed reports whether the given rule ID is suppressed at the given
// line by the inline-directive map.
func IsSuppressed(m map[int]*InlineSuppression, line int, ruleID string) bool {
	if len(m) == 0 {
		return false
	}
	d, ok := m[line]
	if !ok {
		return false
	}
	return d.Suppresses(ruleID)
}
