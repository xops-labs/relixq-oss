// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package swiftast implements a Swift-language AST runner backed by Tree-sitter
// via the smacker/go-tree-sitter CGO bindings (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Swift grammar
// (alex-pinkus/tree-sitter-swift, vendored via smacker/go-tree-sitter/swift)
// are linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Swift AST detection is silently disabled.
//
// Query format (detector.query in the rule YAML):
//
//	call:<dotted.path>        — Type(...), Type.method(...), pkg.Type.method(...)
//	                            or a free function such as CC_MD5(...). The
//	                            dotted path is matched against the literal
//	                            textual form of the call target (a
//	                            simple_identifier or a navigation_expression
//	                            chain of simple_identifiers).
//	init:<Type>               — Swift initializer call `Type(...)`. Semantically
//	                            identical to `call:Type` (Swift has no `new`
//	                            keyword) but exists for rule-author clarity.
//	                            Single dotted segments are allowed
//	                            (`init:Insecure.MD5`).
//	import:<Module>           — `import Module` or `import Module.Submodule`.
//	                            The path is matched against the dotted module
//	                            identifier in the source. A trailing wildcard
//	                            on the rule side (`import:Foundation.*`) is
//	                            supported and matches any submodule beneath.
//	memberref:<dotted.path>   — `Type.member` navigation NOT in call position
//	                            (e.g. `kSecAttrKeyTypeRSA` referenced as an
//	                            attribute value, or `Insecure.MD5` used as a
//	                            type). The path must be at least two segments.
//
// Free-function note: Swift has many top-level C-shim functions exposed by
// CommonCrypto (e.g. `CC_MD5`, `CC_SHA1`). They are syntactically identical to
// initializer calls — both parse as a `call_expression` whose `target` is a
// bare `simple_identifier`. Rule authors write `call:CC_MD5` for both; the
// `init:` form is purely a documentation aid for initializer calls.
//
// Matching is syntactic — no semantic resolution, no module-root expansion,
// no name imports. The dotted path written in the rule must match the literal
// text the developer wrote at the call site (modulo whitespace).
package swiftast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/swift"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("swift", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Swift AST query forms.
type queryKind int

const (
	queryCall      queryKind = iota // call:Type.method  or  call:freeFunction
	queryInit                       // init:Type  (alias for call:Type)
	queryImport                     // import:Module  or  import:Foundation.*
	queryMemberRef                  // memberref:Type.member (not in call position)
)

type parsedQuery struct {
	kind queryKind
	// path holds the dotted path for call/init/memberref/import (in import's
	// case any trailing `.*` is stripped and `wildcard` is set).
	path     string
	wildcard bool // import: rule ends in `.*`
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
		return nil, fmt.Errorf("swiftast query %q: missing kind prefix (call:|init:|import:|memberref:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call":
		if rest == "" {
			return nil, fmt.Errorf("swiftast query %q: missing call path", q)
		}
		return &parsedQuery{kind: queryCall, path: rest}, nil
	case "init":
		if rest == "" {
			return nil, fmt.Errorf("swiftast query %q: missing init type", q)
		}
		return &parsedQuery{kind: queryInit, path: rest}, nil
	case "import":
		if rest == "" {
			return nil, fmt.Errorf("swiftast query %q: missing import path", q)
		}
		pq := &parsedQuery{kind: queryImport, path: rest}
		if strings.HasSuffix(rest, ".*") {
			pq.wildcard = true
			pq.path = strings.TrimSuffix(rest, ".*")
		}
		return pq, nil
	case "memberref":
		if rest == "" {
			return nil, fmt.Errorf("swiftast query %q: missing memberref path", q)
		}
		if !strings.Contains(rest, ".") {
			return nil, fmt.Errorf("swiftast query %q: memberref expects at least Type.member", q)
		}
		return &parsedQuery{kind: queryMemberRef, path: rest}, nil
	default:
		return nil, fmt.Errorf("swiftast query %q: unknown kind %q (want call|init|import|memberref)", q, kind)
	}
}

// Run parses source as a Swift file and returns matches for the applicable AST
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
	parser.SetLanguage(swift.GetLanguage())

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
		// alex-pinkus/tree-sitter-swift: call_expression has a target field
		// (the function expression) and a call_suffix child holding the
		// argument list. We resolve the textual dotted form of the target.
		tgt := n.ChildByFieldName("target")
		if tgt == nil {
			// Fallback: some grammar paths put the target as the first named
			// child without a field name.
			if c := n.NamedChild(0); c != nil {
				tgt = c
			}
		}
		if tgt != nil {
			path := dottedTargetText(tgt, src)
			if path != "" {
				for _, rq := range rqs {
					switch rq.query.kind {
					case queryCall, queryInit:
						if rq.query.path == path {
							appendMatch(out, rq.rule, n, lines)
						}
					}
				}
			}
		}

	case "import_declaration":
		// import_declaration covers `import Module`, `import Module.Submodule`,
		// and import-kind variants (`import struct Module.X`). We extract the
		// final dotted identifier path and test it against import rules.
		importPath := importPathOf(n, src)
		if importPath != "" {
			for _, rq := range rqs {
				if rq.query.kind != queryImport {
					continue
				}
				if importMatches(rq.query, importPath) {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}

	case "navigation_expression":
		// memberref: `Type.member` reference NOT in call position. If the
		// parent is a call_expression and this navigation is its target, the
		// call_expression handler already considered it — skip to avoid
		// double-firing memberref rules on legitimate calls.
		if isCallTarget(n) {
			break
		}
		path := dottedTargetText(n, src)
		if path != "" && strings.Contains(path, ".") {
			for _, rq := range rqs {
				if rq.query.kind != queryMemberRef {
					continue
				}
				if rq.query.path == path {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}
	}

	for i := uint32(0); i < n.ChildCount(); i++ {
		walk(n.Child(int(i)), src, rqs, lines, out)
	}
}

// dottedTargetText resolves the textual dotted form of a call target or a
// navigation expression. For a bare simple_identifier it returns the
// identifier itself. For a navigation_expression it walks the chain of
// `target` / `suffix` children joining each segment with `.`.
//
// Unrecognized node shapes (function references, closures, subscripts) return
// "" so they harmlessly fail to match — we don't want to invent a textual
// form that no rule author would predict.
func dottedTargetText(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "simple_identifier", "identifier", "type_identifier":
		return n.Content(src)
	case "user_type":
		// user_type wraps one or more type_identifier nodes. Take the joined
		// dotted text via NamedChild traversal.
		if c := n.NamedChild(0); c != nil {
			return dottedTargetText(c, src)
		}
		return strings.TrimSpace(n.Content(src))
	case "navigation_expression":
		// navigation_expression has fields:
		//   target: <expression>
		//   suffix: navigation_suffix(.<simple_identifier>)
		// We rebuild rather than using raw Content() because the source may
		// have whitespace/newlines between segments.
		tgt := n.ChildByFieldName("target")
		suf := n.ChildByFieldName("suffix")
		// Fallbacks for grammar variants that don't expose the fields.
		if tgt == nil {
			tgt = n.NamedChild(0)
		}
		if suf == nil && n.NamedChildCount() >= 2 {
			suf = n.NamedChild(int(n.NamedChildCount() - 1))
		}
		left := dottedTargetText(tgt, src)
		right := navigationSuffixName(suf, src)
		if left == "" || right == "" {
			// Fall back to trimmed raw text. This still gives rule authors a
			// chance to match exotic call targets verbatim.
			return strings.TrimSpace(n.Content(src))
		}
		return left + "." + right
	case "navigation_suffix":
		return navigationSuffixName(n, src)
	}
	// Unknown shape: don't synthesize a path.
	return ""
}

// navigationSuffixName returns the identifier name inside a navigation_suffix
// node (e.g. `.hash` -> "hash").
func navigationSuffixName(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	if n.Type() != "navigation_suffix" {
		// Defensive: if a caller already passed the identifier, return it.
		if n.Type() == "simple_identifier" || n.Type() == "identifier" {
			return n.Content(src)
		}
		return ""
	}
	for i := uint32(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(int(i))
		if c == nil {
			continue
		}
		switch c.Type() {
		case "simple_identifier", "identifier":
			return c.Content(src)
		}
	}
	// Last resort: strip the leading dot from the raw text.
	t := strings.TrimSpace(n.Content(src))
	return strings.TrimPrefix(t, ".")
}

// isCallTarget reports whether n is the `target` of an enclosing
// call_expression. Used to suppress memberref rules from firing on the
// receiver of a member call (which is already handled by the call branch).
func isCallTarget(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil {
		return false
	}
	if parent.Type() != "call_expression" {
		return false
	}
	tgt := parent.ChildByFieldName("target")
	if tgt != nil {
		return tgt == n
	}
	// No field — assume the first named child is the target.
	first := parent.NamedChild(0)
	return first == n
}

// importPathOf returns the dotted module path declared by an import_declaration
// node. Handles `import Module`, `import Module.Submodule`, and import-kind
// modifiers (`import struct Foo.Bar`). Returns "" if no module identifier was
// found.
func importPathOf(n *sitter.Node, src []byte) string {
	// The grammar's child sequence varies by import variant. The simplest and
	// most robust approach: walk named children and pick the last navigable
	// dotted-identifier expression; ignore the leading import-kind keyword
	// (`struct`/`class`/etc).
	var path string
	for i := uint32(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(int(i))
		if c == nil {
			continue
		}
		switch c.Type() {
		case "identifier", "simple_identifier", "type_identifier":
			path = c.Content(src)
		case "navigation_expression":
			if p := dottedTargetText(c, src); p != "" {
				path = p
			}
		}
	}
	if path != "" {
		return path
	}
	// Fallback: derive from raw text by stripping `import` and any kind keyword.
	text := strings.TrimSpace(n.Content(src))
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	for _, kw := range []string{"struct ", "class ", "enum ", "protocol ", "func ", "let ", "var ", "typealias "} {
		text = strings.TrimPrefix(text, kw)
	}
	// Trim any trailing comment or attribute noise.
	if idx := strings.IndexAny(text, " \t/"); idx >= 0 {
		text = text[:idx]
	}
	return strings.TrimSpace(text)
}

// importMatches decides whether a rule-side import path matches a source-side
// import declaration. Swift imports are dotted; we mirror Java's semantics:
//
//	rule wildcard `Foundation.*` -> matches `Foundation` or `Foundation.X[.Y]`
//	specific rule path           -> exact match
func importMatches(rule *parsedQuery, importPath string) bool {
	if rule.wildcard {
		prefix := rule.path
		if prefix == "" {
			return true
		}
		return importPath == prefix || strings.HasPrefix(importPath, prefix+".")
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
