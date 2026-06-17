// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package kotlinast implements a Kotlin-language AST runner backed by
// Tree-sitter via the smacker/go-tree-sitter CGO bindings
// (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Kotlin grammar
// are linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Kotlin AST detection is silently disabled.
//
// Kotlin is a JVM language that consumes the JCA/JCE crypto APIs directly,
// so this runner mirrors javaast's query DSL one-for-one. The only language
// shape that differs meaningfully is constructor invocation — Kotlin has no
// `new` keyword; `Foo(...)` is just a function call. The `new:<Type>` query
// therefore matches a call_expression whose callee is a bare simple identifier
// equal to <Type>. That is the same syntactic shape Kotlin uses for both
// constructor calls and top-level function calls, so a few well-named regular
// functions could theoretically false-positive against `new:<Type>` rules —
// rule authors should keep the type names PascalCase as the constructor
// convention dictates.
//
// Query format (detector.query in the rule YAML):
//
//	call:<Type>.<method>      — Type.method(...) or receiver.method(...)
//	new:<Type>                — Type(...) constructor invocation (no `new` kw)
//	import:<package.Class>    — import package.Class (also matches package.*)
//	fieldref:<Type>.<field>   — Type.field member access NOT in call position
//
// Matching is syntactic — no semantic resolution, no qualified-name expansion.
// `Type` is matched against the literal identifier that appears in source.
package kotlinast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/kotlin"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("kotlin", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Kotlin AST query forms.
type queryKind int

const (
	queryCall     queryKind = iota // call:Type.method
	queryNew                       // new:Type
	queryImport                    // import:pkg.Class
	queryFieldRef                  // fieldref:Type.field
)

type parsedQuery struct {
	kind queryKind
	typ  string // for call/new/fieldref — the receiver/type identifier
	name string // for call/fieldref — the method or field name
	path string // for import — the dotted package path (may end in .*)
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
		return nil, fmt.Errorf("kotlinast query %q: missing kind prefix (call:|new:|import:|fieldref:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call", "fieldref":
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("kotlinast query %q: expected Type.Identifier form", q)
		}
		k := queryCall
		if kind == "fieldref" {
			k = queryFieldRef
		}
		return &parsedQuery{kind: k, typ: rest[:dot], name: rest[dot+1:]}, nil
	case "new":
		if rest == "" {
			return nil, fmt.Errorf("kotlinast query %q: missing type", q)
		}
		return &parsedQuery{kind: queryNew, typ: rest}, nil
	case "import":
		if rest == "" {
			return nil, fmt.Errorf("kotlinast query %q: missing import path", q)
		}
		return &parsedQuery{kind: queryImport, path: rest}, nil
	default:
		return nil, fmt.Errorf("kotlinast query %q: unknown kind %q (want call|new|import|fieldref)", q, kind)
	}
}

// Run parses source as a Kotlin file and returns matches for the applicable
// AST rules. Regex rules in applicable are ignored. A parse error returns a
// nil slice with no error so the caller treats it as "no findings" (consistent
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
	parser.SetLanguage(kotlin.GetLanguage())

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
//
// The Kotlin grammar from tree-sitter-kotlin (smacker) does not expose named
// fields the way the Java grammar does, so this walker navigates by positional
// named children. Shapes (per the upstream test fixture and grammar.js):
//
//	MessageDigest.getInstance("MD5")
//	  call_expression
//	    navigation_expression
//	      simple_identifier            (receiver)
//	      navigation_suffix
//	        simple_identifier          (method name)
//	    call_suffix
//	      value_arguments ...
//
//	MyClass()                          // Kotlin has no `new` keyword
//	  call_expression
//	    simple_identifier              (type name)
//	    call_suffix
//
//	import java.security.MessageDigest
//	  import_header
//	    identifier
//	      simple_identifier x N        (one per dotted segment)
//	    [wildcard_import]              (present for `import foo.*`)
//
//	Foo.BAR                            // not in call position
//	  navigation_expression            (parent is NOT call_expression)
//	    simple_identifier
//	    navigation_suffix
//	      simple_identifier
func walk(n *sitter.Node, src []byte, rqs []ruleQuery, lines []string, out *[]astdet.Match) {
	if n == nil {
		return
	}

	switch n.Type() {
	case "call_expression":
		handleCallExpression(n, src, rqs, lines, out)

	case "navigation_expression":
		// Only treat as a fieldref hit if the navigation_expression is NOT the
		// callee of an enclosing call_expression. The call_expression branch
		// already covers that case as a call.
		if !isCalleeOfCallExpression(n) {
			handleFieldRef(n, src, rqs, lines, out)
		}

	case "import_header":
		importPath, isWildcard := importPathOf(n, src)
		if importPath != "" {
			for _, rq := range rqs {
				if rq.query.kind != queryImport {
					continue
				}
				if importMatches(rq.query.path, importPath, isWildcard) {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}
	}

	for i := uint32(0); i < n.ChildCount(); i++ {
		walk(n.Child(int(i)), src, rqs, lines, out)
	}
}

// handleCallExpression matches both `call:Type.method` (qualified) and
// `new:Type` (bare constructor invocation, since Kotlin has no `new`).
func handleCallExpression(n *sitter.Node, src []byte, rqs []ruleQuery, lines []string, out *[]astdet.Match) {
	callee := firstNamedChild(n)
	if callee == nil {
		return
	}
	switch callee.Type() {
	case "navigation_expression":
		// Type.method(...) form
		recv, method, ok := navParts(callee, src)
		if !ok {
			return
		}
		for _, rq := range rqs {
			if rq.query.kind != queryCall {
				continue
			}
			if rq.query.name != method {
				continue
			}
			if rq.query.typ != recv {
				continue
			}
			appendMatch(out, rq.rule, n, lines)
		}
	case "simple_identifier":
		// Bare call — in Kotlin this is both a free-function call AND a
		// constructor invocation. We dispatch as `new:<Type>`.
		name := callee.Content(src)
		for _, rq := range rqs {
			if rq.query.kind != queryNew {
				continue
			}
			if rq.query.typ != name {
				continue
			}
			appendMatch(out, rq.rule, n, lines)
		}
	}
}

// handleFieldRef matches `fieldref:Type.field` against a navigation_expression
// whose immediate parent is NOT a call_expression — i.e. the navigation is a
// value reference, not a method receiver.
func handleFieldRef(n *sitter.Node, src []byte, rqs []ruleQuery, lines []string, out *[]astdet.Match) {
	recv, field, ok := navParts(n, src)
	if !ok {
		return
	}
	for _, rq := range rqs {
		if rq.query.kind != queryFieldRef {
			continue
		}
		if rq.query.typ != recv {
			continue
		}
		if rq.query.name != field {
			continue
		}
		appendMatch(out, rq.rule, n, lines)
	}
}

// navParts extracts (receiver, suffix) from a navigation_expression of the
// shape `<simple_identifier> . <navigation_suffix(simple_identifier)>`. Returns
// ok=false if the receiver isn't a simple identifier (e.g. chained navigations
// like `a.b.c` — we deliberately don't try to synthesize a qualified-name
// match for those; rule authors writing `Type.x` mean the literal text Type).
func navParts(nav *sitter.Node, src []byte) (recv, name string, ok bool) {
	if nav == nil || nav.Type() != "navigation_expression" {
		return "", "", false
	}
	var recvNode, suffixNode *sitter.Node
	for i := uint32(0); i < nav.NamedChildCount(); i++ {
		c := nav.NamedChild(int(i))
		if c == nil {
			continue
		}
		switch c.Type() {
		case "navigation_suffix":
			suffixNode = c
		default:
			if recvNode == nil {
				recvNode = c
			}
		}
	}
	if recvNode == nil || suffixNode == nil {
		return "", "", false
	}
	if recvNode.Type() != "simple_identifier" {
		return "", "", false
	}
	// navigation_suffix wraps a simple_identifier (the method/field name).
	var suffixIdent *sitter.Node
	for i := uint32(0); i < suffixNode.NamedChildCount(); i++ {
		c := suffixNode.NamedChild(int(i))
		if c != nil && c.Type() == "simple_identifier" {
			suffixIdent = c
			break
		}
	}
	if suffixIdent == nil {
		return "", "", false
	}
	return recvNode.Content(src), suffixIdent.Content(src), true
}

// firstNamedChild returns the first named child of n, or nil. Convenience over
// NamedChild(0) that tolerates a missing child.
func firstNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

// isCalleeOfCallExpression reports whether n is the callee position of a
// surrounding call_expression — i.e. its parent is a call_expression and n is
// that call_expression's first named child.
func isCalleeOfCallExpression(n *sitter.Node) bool {
	p := n.Parent()
	if p == nil || p.Type() != "call_expression" {
		return false
	}
	return firstNamedChild(p) == n
}

// importPathOf returns the dotted import path declared by an import_header
// node and whether it ends in `.*`. Returns ("","false") if the path can't be
// extracted.
//
// We use the raw source text rather than reconstructing from named children
// because:
//   - the upstream grammar represents the dotted name as nested simple_identifier
//     nodes under an `identifier` node, which is easy to walk but the text-based
//     approach also handles `import foo.bar.*` and `import foo.bar as Baz`.
//   - the import_alias (`as`) part should be stripped — we care about the
//     imported FQN, not the local alias.
func importPathOf(n *sitter.Node, src []byte) (string, bool) {
	text := strings.TrimSpace(n.Content(src))
	// Kotlin has no trailing semicolons on imports, but tolerate them.
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	if text == "" {
		return "", false
	}
	// Strip any `as Alias` suffix.
	if i := strings.Index(text, " as "); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	if strings.HasSuffix(text, ".*") {
		return strings.TrimSuffix(text, ".*"), true
	}
	return text, false
}

// importMatches decides whether a rule-side import path matches a source-side
// import declaration.
func importMatches(rulePath, importPath string, importIsWildcard bool) bool {
	// Rule wildcard: `javax.crypto.*` matches any import under that package.
	if strings.HasSuffix(rulePath, ".*") {
		prefix := strings.TrimSuffix(rulePath, ".*")
		return importPath == prefix || strings.HasPrefix(importPath, prefix+".")
	}
	// Specific rule path: exact match, or a wildcard import that covers it.
	if importIsWildcard {
		dot := strings.LastIndexByte(rulePath, '.')
		if dot < 0 {
			return false
		}
		return importPath == rulePath[:dot]
	}
	return importPath == rulePath
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
