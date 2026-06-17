// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package rustast implements a Rust-language AST runner backed by Tree-sitter
// via the smacker/go-tree-sitter CGO bindings (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Rust grammar are
// linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Rust AST detection is silently disabled.
//
// Query format (detector.query in the rule YAML):
//
//	call:<scoped::path>       — Type::method(...) or pkg::Type::method(...)
//	methodcall:<method>       — receiver.method(...); only the method name is matched
//	use:<path>                — use pkg::Type; (trailing `*` is a wildcard)
//
// Matching is syntactic — no semantic resolution, no crate-root expansion. The
// scoped path written in `call:` is matched against the literal text of the
// `scoped_identifier` (or `identifier`) callee.
package rustast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("rust", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Rust AST query forms.
type queryKind int

const (
	queryCall       queryKind = iota // call:scoped::path
	queryMethodCall                  // methodcall:method
	queryUse                         // use:path  (path may end in `*`)
)

type parsedQuery struct {
	kind queryKind
	// For call: the full scoped path (e.g. "rsa::RsaPrivateKey::new_with_exp").
	// For methodcall: the method identifier.
	// For use: the path with any trailing `*` retained (we strip+flag below).
	path       string
	wildcard   bool // use: query ends in `*`
	wildcardP  string // use: path prefix (path minus trailing `*` and optional `::`)
}

// ruleQuery pairs a rule with its pre-parsed query so we don't re-parse the
// query string per node visit.
type ruleQuery struct {
	rule  *rules.Rule
	query *parsedQuery
}

func parseQuery(q string) (*parsedQuery, error) {
	idx := strings.IndexByte(q, ':')
	if idx < 0 {
		return nil, fmt.Errorf("rustast query %q: missing kind prefix (call:|methodcall:|use:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call":
		if rest == "" {
			return nil, fmt.Errorf("rustast query %q: missing scoped path", q)
		}
		return &parsedQuery{kind: queryCall, path: rest}, nil
	case "methodcall":
		if rest == "" {
			return nil, fmt.Errorf("rustast query %q: missing method name", q)
		}
		// A method name is a plain identifier — no `::` allowed.
		if strings.Contains(rest, "::") {
			return nil, fmt.Errorf("rustast query %q: methodcall expects a bare method name, not a scoped path", q)
		}
		return &parsedQuery{kind: queryMethodCall, path: rest}, nil
	case "use":
		if rest == "" {
			return nil, fmt.Errorf("rustast query %q: missing use path", q)
		}
		pq := &parsedQuery{kind: queryUse, path: rest}
		if strings.HasSuffix(rest, "*") {
			pq.wildcard = true
			prefix := strings.TrimSuffix(rest, "*")
			prefix = strings.TrimSuffix(prefix, "::")
			pq.wildcardP = prefix
		}
		return pq, nil
	default:
		return nil, fmt.Errorf("rustast query %q: unknown kind %q (want call|methodcall|use)", q, kind)
	}
}

// Run parses source as a Rust file and returns matches for the applicable AST
// rules. Regex rules in applicable are ignored. A parse error returns a nil
// slice with no error so the caller treats it as "no findings" (consistent
// with the regex detector swallowing malformed files).
func (r *runner) Run(filePath string, source []byte, applicable []*rules.Rule) ([]astdet.Match, error) {
	// Pre-compile queries; skip rules with invalid queries silently so a single
	// bad rule doesn't sink the whole file scan.
	var rqs []ruleQuery
	for _, rule := range applicable {
		if rule.Detector.Type != rules.DetectorAST {
			continue
		}
		pq, err := parseQuery(rule.Detector.Query)
		if err != nil {
			continue
		}
		rqs = append(rqs, ruleQuery{rule: rule, query: pq})
	}
	if len(rqs) == 0 {
		return nil, nil
	}

	parser := sitter.NewParser()
	parser.SetLanguage(rust.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, source)
	if err != nil || tree == nil {
		return nil, nil
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		return nil, nil
	}

	lines := splitLines(source)
	var matches []astdet.Match
	walk(root, source, rqs, lines, &matches)
	return matches, nil
}

// walk traverses the syntax tree once and dispatches each node against the
// pre-compiled rule queries. Recursion depth is bounded by AST depth.
func walk(n *sitter.Node, src []byte, rqs []ruleQuery, lines []string, out *[]astdet.Match) {
	if n == nil {
		return
	}

	switch n.Type() {
	case "call_expression":
		// Rust grammar: call_expression has fields:
		//   function:  expression (scoped_identifier | identifier | field_expression | ...)
		//   arguments: arguments
		// We discriminate between free-function/associated calls (scoped or bare
		// identifier callee) and instance method calls (field_expression callee).
		fnNode := n.ChildByFieldName("function")
		if fnNode == nil {
			break
		}
		switch fnNode.Type() {
		case "scoped_identifier", "identifier":
			callPath := scopedIdentifierText(fnNode, src)
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if rq.query.path == callPath {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		case "field_expression":
			// Instance method call: `receiver.method(...)`. The grammar puts
			// the method name in the `field` child of the field_expression.
			fldNode := fnNode.ChildByFieldName("field")
			if fldNode == nil {
				break
			}
			methodName := fldNode.Content(src)
			for _, rq := range rqs {
				if rq.query.kind != queryMethodCall {
					continue
				}
				if rq.query.path == methodName {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}

	case "use_declaration":
		// use_declaration covers:
		//   use foo::bar::Baz;
		//   use foo::bar::*;
		//   use foo::bar::{Baz, Qux};
		//   use foo::bar::Baz as Aliased;
		// We extract every concrete path the declaration brings into scope and
		// test each against the rule. Wildcards are tracked so a `use foo::*;`
		// can satisfy a rule targeting `foo::Specific` (analogous to Java's
		// import wildcard handling).
		paths := usePathsOf(n, src)
		for _, up := range paths {
			for _, rq := range rqs {
				if rq.query.kind != queryUse {
					continue
				}
				if useMatches(rq.query, up.path, up.isWildcard) {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}
	}

	for i := uint32(0); i < n.ChildCount(); i++ {
		walk(n.Child(int(i)), src, rqs, lines, out)
	}
}

// scopedIdentifierText returns the textual scoped path of a callee. For a
// `scoped_identifier` it joins all `::`-separated segments; for a bare
// `identifier` it returns the identifier itself.
func scopedIdentifierText(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case "identifier":
		return n.Content(src)
	case "scoped_identifier":
		// scoped_identifier has fields: path (optional, recursive), name (identifier).
		// We rebuild rather than using Content() so we normalize whitespace and
		// strip turbofish (`::<T>`) tokens cleanly.
		nameNode := n.ChildByFieldName("name")
		pathNode := n.ChildByFieldName("path")
		var segs []string
		if pathNode != nil {
			segs = append(segs, scopedIdentifierText(pathNode, src))
		}
		if nameNode != nil {
			segs = append(segs, nameNode.Content(src))
		}
		if len(segs) == 0 {
			// Fallback: take raw text and strip any turbofish.
			t := n.Content(src)
			if i := strings.Index(t, "::<"); i >= 0 {
				t = t[:i]
			}
			return t
		}
		return strings.Join(segs, "::")
	}
	// Other callee shapes (e.g. generic_function) — fall back to raw text.
	return n.Content(src)
}

// usePath represents one path brought into scope by a use_declaration.
type usePath struct {
	path       string // e.g. "ring::rsa::RsaKeyPair"  or "ring::rsa"
	isWildcard bool   // true if the source path ends in `*`
}

// usePathsOf walks a use_declaration node and returns every distinct path the
// declaration imports. It handles plain paths, wildcards (`*`), use_lists
// (`{A, B}`), and `as`-aliases. Aliases are flattened to the original path so
// `use foo::Bar as Baz;` matches a rule for `foo::Bar`.
func usePathsOf(n *sitter.Node, src []byte) []usePath {
	// The use_declaration's `argument` field contains the imported tree. We
	// flatten by recursing into it with an accumulating prefix.
	arg := n.ChildByFieldName("argument")
	if arg == nil {
		return nil
	}
	var out []usePath
	collectUsePaths(arg, src, "", &out)
	return out
}

func collectUsePaths(n *sitter.Node, src []byte, prefix string, out *[]usePath) {
	switch n.Type() {
	case "identifier":
		*out = append(*out, usePath{path: joinPath(prefix, n.Content(src))})
	case "scoped_identifier":
		*out = append(*out, usePath{path: scopedIdentifierText(n, src)})
	case "scoped_use_list":
		// scoped_use_list has fields: path, list (use_list).
		pathNode := n.ChildByFieldName("path")
		listNode := n.ChildByFieldName("list")
		newPrefix := prefix
		if pathNode != nil {
			newPrefix = joinPath(prefix, scopedIdentifierText(pathNode, src))
		}
		if listNode != nil {
			for i := uint32(0); i < listNode.ChildCount(); i++ {
				collectUsePaths(listNode.Child(int(i)), src, newPrefix, out)
			}
		}
	case "use_list":
		for i := uint32(0); i < n.ChildCount(); i++ {
			collectUsePaths(n.Child(int(i)), src, prefix, out)
		}
	case "use_wildcard":
		// use_wildcard: `foo::bar::*` or just `*` after a scoped_use_list path.
		// Children include the path (if any) and the `*` token.
		var basePath string
		for i := uint32(0); i < n.ChildCount(); i++ {
			c := n.Child(int(i))
			if c == nil {
				continue
			}
			switch c.Type() {
			case "scoped_identifier", "identifier":
				basePath = scopedIdentifierText(c, src)
			}
		}
		fullPath := joinPath(prefix, basePath)
		*out = append(*out, usePath{path: fullPath, isWildcard: true})
	case "use_as_clause":
		// use_as_clause has fields: path, alias. We track the original path,
		// not the alias, so rules match the imported entity regardless of
		// how the local binding is renamed.
		pathNode := n.ChildByFieldName("path")
		if pathNode != nil {
			text := scopedIdentifierText(pathNode, src)
			*out = append(*out, usePath{path: joinPath(prefix, text)})
		}
	}
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	if name == "" {
		return prefix
	}
	return prefix + "::" + name
}

// useMatches decides whether a rule-side use path matches a source-side use.
// Mirrors the semantics of the Java importMatches helper but with `::`
// separators.
func useMatches(rule *parsedQuery, importPath string, importIsWildcard bool) bool {
	// Rule wildcard (e.g. `ring::rsa::*`): match exact prefix or any nested
	// path beneath it.
	if rule.wildcard {
		prefix := rule.wildcardP
		if prefix == "" {
			// Bare `*` — pathological; match everything.
			return true
		}
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"::")
	}
	// Specific rule path: exact match, or a wildcard source import that
	// covers it (e.g. `use ring::rsa::*;` covering `ring::rsa::RsaKeyPair`).
	if importIsWildcard {
		// `use foo::bar::*;` covers `foo::bar::X` iff rule path is exactly
		// one segment beneath the wildcard root.
		idx := strings.LastIndex(rule.path, "::")
		if idx < 0 {
			return false
		}
		return importPath == rule.path[:idx]
	}
	return importPath == rule.path
}

func appendMatch(out *[]astdet.Match, rule *rules.Rule, n *sitter.Node, lines []string) {
	startPoint := n.StartPoint()
	// Tree-sitter rows/columns are 0-based; convert to 1-based to match the
	// regex detector and the rest of the pipeline.
	line := int(startPoint.Row) + 1
	col := int(startPoint.Column) + 1
	*out = append(*out, astdet.Match{
		Rule:    rule,
		Line:    line,
		Column:  col,
		Snippet: lineAt(lines, line),
		Context: contextOf(lines, line),
	})
}

func splitLines(src []byte) []string {
	return strings.Split(string(src), "\n")
}

func lineAt(lines []string, lineNo int) string {
	if lineNo < 1 || lineNo > len(lines) {
		return ""
	}
	return strings.TrimRight(lines[lineNo-1], "\r")
}

const contextLines = 3

func contextOf(lines []string, lineNo int) []string {
	start := lineNo - 1 - contextLines
	if start < 0 {
		start = 0
	}
	end := lineNo - 1 + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}
	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, strings.TrimRight(lines[i], "\r"))
	}
	return out
}
