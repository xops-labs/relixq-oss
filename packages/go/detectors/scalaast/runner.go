// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package scalaast implements a Scala-language AST runner backed by Tree-sitter
// via the smacker/go-tree-sitter CGO bindings (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Scala grammar are
// linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Scala AST detection is silently disabled.
//
// The binding is github.com/smacker/go-tree-sitter/scala, which embeds the
// upstream tree-sitter-scala grammar
// (https://github.com/tree-sitter/tree-sitter-scala) covering Scala 2 and
// Scala 3 syntax.
//
// Query format (detector.query in the rule YAML):
//
//	call:<Type>.<method>      — Type.method(...) or receiver.method(...)
//	new:<Type>                — new Type(...) instance construction
//	apply:<Type>              — Type(...) companion-apply sugar (Scala-specific:
//	                            sugar for Type.apply(...) — matches call_expression
//	                            whose function is a bare identifier of Type)
//	import:<package.Class>    — import package.Class
//	                            (also matches package._ wildcard and
//	                             import package.{Class, Other} selector lists)
//	memberref:<Type>.<member> — Type.member access NOT in call position
//
// Scala-specific handling notes:
//
//   - Method calls take two AST shapes. The standard `obj.method(args)` form
//     compiles to a call_expression whose function is a field_expression
//     (value=receiver, field=method-name). Companion-object apply sugar
//     `ClassName(args)` compiles to a call_expression whose function is a bare
//     identifier — this is matched by `apply:Type`.
//   - Infix method calls (`receiver method args`) are rare in crypto code and
//     are NOT covered — match on the dotted form only.
//   - The `new` keyword wraps an instance_expression. For `new Foo(args)` the
//     instance_expression contains a nested call_expression whose function is
//     a type_identifier. The walker picks up the type from whichever child
//     surfaces the identifier first.
//   - Imports are parsed textually from the import_declaration's source text,
//     matching the Java runner's approach. This sidesteps the variability in
//     Scala's import_declaration AST (path + namespace_selectors + wildcard)
//     and produces stable results for the common shapes:
//
//     import java.security.MessageDigest
//     import javax.crypto.{Cipher, KeyGenerator}
//     import javax.crypto._
//
// Matching is syntactic — no semantic resolution, no qualified-name expansion.
// `Type` is matched against the literal identifier that appears in source.
package scalaast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/scala"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("scala", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Scala AST query forms.
type queryKind int

const (
	queryCall      queryKind = iota // call:Type.method
	queryNew                        // new:Type
	queryApply                      // apply:Type  (Scala companion-apply sugar)
	queryImport                     // import:pkg.Class
	queryMemberRef                  // memberref:Type.member
)

type parsedQuery struct {
	kind queryKind
	typ  string // for call/new/apply/memberref — the receiver/type identifier
	name string // for call/memberref — the method or member name
	path string // for import — the dotted package path
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
		return nil, fmt.Errorf("scalaast query %q: missing kind prefix (call:|new:|apply:|import:|memberref:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call", "memberref":
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("scalaast query %q: expected Type.Identifier form", q)
		}
		k := queryCall
		if kind == "memberref" {
			k = queryMemberRef
		}
		return &parsedQuery{kind: k, typ: rest[:dot], name: rest[dot+1:]}, nil
	case "new":
		if rest == "" {
			return nil, fmt.Errorf("scalaast query %q: missing type", q)
		}
		return &parsedQuery{kind: queryNew, typ: rest}, nil
	case "apply":
		if rest == "" {
			return nil, fmt.Errorf("scalaast query %q: missing type", q)
		}
		return &parsedQuery{kind: queryApply, typ: rest}, nil
	case "import":
		if rest == "" {
			return nil, fmt.Errorf("scalaast query %q: missing import path", q)
		}
		return &parsedQuery{kind: queryImport, path: rest}, nil
	default:
		return nil, fmt.Errorf("scalaast query %q: unknown kind %q (want call|new|apply|import|memberref)", q, kind)
	}
}

// Run parses source as a Scala file and returns matches for the applicable AST
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
	parser.SetLanguage(scala.GetLanguage())

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
		// Scala grammar: call_expression has fields:
		//   function:  expression (field_expression | identifier | instance_expression | ...)
		//   arguments: arguments
		//
		// Two shapes matter for crypto detection:
		//   1. obj.method(args)        → function is field_expression
		//      Used for: MessageDigest.getInstance("MD5"), cipher.doFinal(b), ...
		//   2. ClassName(args)         → function is a bare identifier
		//      Used for: companion-apply sugar — Cipher("DES") desugars to
		//      Cipher.apply("DES"). We surface these via apply:Type.
		fnNode := n.ChildByFieldName("function")
		if fnNode == nil {
			// Fallback: some grammar revisions don't expose the function as a
			// named field; the first named child is the callee in all
			// observed cases.
			fnNode = n.NamedChild(0)
		}
		if fnNode == nil {
			break
		}
		switch fnNode.Type() {
		case "field_expression":
			// field_expression has named children: value (receiver) and field
			// (member-name identifier). We match `call:Type.method` when the
			// receiver is a simple identifier equal to Type and the field
			// equals method.
			recv, fld := fieldExpressionParts(fnNode, src)
			if fld != "" {
				for _, rq := range rqs {
					if rq.query.kind != queryCall {
						continue
					}
					if rq.query.name != fld {
						continue
					}
					if rq.query.typ != recv {
						continue
					}
					appendMatch(out, rq.rule, n, lines)
				}
			}
		case "identifier":
			// Bare-identifier callee → companion-apply sugar.
			// Match `apply:Type` when the identifier == Type.
			name := fnNode.Content(src)
			for _, rq := range rqs {
				if rq.query.kind != queryApply {
					continue
				}
				if rq.query.typ == name {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		case "type_identifier":
			// In `new Foo(args)` the inner call_expression's function is a
			// type_identifier. This is handled at the instance_expression
			// level (queryNew); skip here to avoid double-matching.
		}

	case "instance_expression":
		// instance_expression covers `new Foo(...)`, `new Foo`, and
		// `new Foo { body }`. We dive into the children to find the first
		// type-bearing identifier so the rule writer can target `new:Foo`
		// without caring about whether args are present.
		typName := instanceTypeName(n, src)
		if typName != "" {
			for _, rq := range rqs {
				if rq.query.kind != queryNew {
					continue
				}
				if rq.query.typ != typName {
					continue
				}
				appendMatch(out, rq.rule, n, lines)
			}
		}

	case "import_declaration":
		// Scala imports are parsed textually from the import_declaration's
		// source text — see package doc for the rationale. Returns every
		// concrete dotted path the declaration brings into scope plus a flag
		// for trailing `_` wildcard.
		paths := importPathsOf(n, src)
		for _, ip := range paths {
			for _, rq := range rqs {
				if rq.query.kind != queryImport {
					continue
				}
				if importMatches(rq.query.path, ip.path, ip.isWildcard) {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}

	case "field_expression":
		// Member reference NOT in call position. The grammar still emits a
		// field_expression as the function of a call_expression for
		// `Type.method(...)`, so we skip those by walking up to the parent.
		// Tree-sitter doesn't expose parent traversal cheaply from this
		// context; instead we check whether this field_expression's parent
		// is a call_expression where this node is the `function` field.
		if isCallReceiver(n) {
			break
		}
		recv, fld := fieldExpressionParts(n, src)
		if recv != "" && fld != "" {
			for _, rq := range rqs {
				if rq.query.kind != queryMemberRef {
					continue
				}
				if rq.query.typ != recv {
					continue
				}
				if rq.query.name != fld {
					continue
				}
				appendMatch(out, rq.rule, n, lines)
			}
		}
	}

	for i := uint32(0); i < n.ChildCount(); i++ {
		walk(n.Child(int(i)), src, rqs, lines, out)
	}
}

// fieldExpressionParts returns (receiver, field) for a field_expression node.
// The receiver is only returned when it is a simple identifier — qualified
// receivers like `pkg.Type.method` produce an empty receiver string. This
// matches the Java runner's lenient strategy where rule authors write the
// simple name.
func fieldExpressionParts(n *sitter.Node, src []byte) (string, string) {
	// Common field names exposed by tree-sitter-scala for field_expression:
	//   value   — receiver expression
	//   field   — member identifier
	// Fallbacks accommodate grammar revisions that use different field names.
	valNode := n.ChildByFieldName("value")
	if valNode == nil {
		valNode = n.ChildByFieldName("base")
	}
	fldNode := n.ChildByFieldName("field")
	if fldNode == nil {
		fldNode = n.ChildByFieldName("name")
	}
	if fldNode == nil {
		fldNode = n.ChildByFieldName("selector")
	}
	// Last-resort: walk named children — first is receiver, last is name.
	if valNode == nil || fldNode == nil {
		count := n.NamedChildCount()
		if count >= 2 {
			if valNode == nil {
				valNode = n.NamedChild(0)
			}
			if fldNode == nil {
				fldNode = n.NamedChild(int(count) - 1)
			}
		}
	}
	if fldNode == nil {
		return "", ""
	}
	fld := fldNode.Content(src)
	recv := ""
	if valNode != nil && (valNode.Type() == "identifier" || valNode.Type() == "type_identifier") {
		recv = valNode.Content(src)
	}
	return recv, fld
}

// instanceTypeName extracts the bare type name from an instance_expression node
// (`new Foo(...)`, `new Foo`, `new Foo { body }`, `new pkg.Foo(...)`). It walks
// the immediate descendants looking for the first identifier-bearing node.
func instanceTypeName(n *sitter.Node, src []byte) string {
	// Try direct children first.
	for i := uint32(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(int(i))
		if c == nil {
			continue
		}
		switch c.Type() {
		case "type_identifier", "identifier":
			return c.Content(src)
		case "call_expression":
			// `new Foo(args)` → instance_expression wraps a call_expression
			// whose function is the type identifier.
			fn := c.ChildByFieldName("function")
			if fn == nil {
				fn = c.NamedChild(0)
			}
			if fn != nil {
				return simpleNameOf(fn, src)
			}
		case "generic_type":
			if g := c.NamedChild(0); g != nil {
				return simpleNameOf(g, src)
			}
		case "stable_type_identifier", "stable_identifier":
			// Dotted name — take the last segment.
			full := c.Content(src)
			if i := strings.LastIndexByte(full, '.'); i >= 0 {
				return full[i+1:]
			}
			return full
		}
	}
	return ""
}

// simpleNameOf reduces an arbitrary type/identifier node to a bare identifier.
func simpleNameOf(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case "identifier", "type_identifier":
		return n.Content(src)
	case "stable_type_identifier", "stable_identifier", "scoped_identifier":
		full := n.Content(src)
		if i := strings.LastIndexByte(full, '.'); i >= 0 {
			return full[i+1:]
		}
		return full
	case "generic_type":
		if g := n.NamedChild(0); g != nil {
			return simpleNameOf(g, src)
		}
	}
	return ""
}

// isCallReceiver reports whether the given node is the `function` slot of a
// call_expression — in which case the walker has already handled it as a call,
// not a memberref.
func isCallReceiver(n *sitter.Node) bool {
	p := n.Parent()
	if p == nil {
		return false
	}
	if p.Type() != "call_expression" {
		return false
	}
	fn := p.ChildByFieldName("function")
	if fn == nil {
		fn = p.NamedChild(0)
	}
	return fn != nil && fn.Equal(n)
}

// importPath represents one path brought into scope by an import_declaration.
type importPath struct {
	path       string // dotted path, no trailing wildcard
	isWildcard bool   // true if source imports `pkg._`
}

// importPathsOf parses a Scala import_declaration's source text and returns
// every concrete path it imports. Handles:
//
//	import java.security.MessageDigest
//	import javax.crypto.{Cipher, KeyGenerator}
//	import javax.crypto._
//	import javax.crypto.{Cipher => C}
//
// The textual approach mirrors the Java runner and tolerates grammar drift in
// the import_declaration / namespace_selectors subtree.
func importPathsOf(n *sitter.Node, src []byte) []importPath {
	text := strings.TrimSpace(n.Content(src))
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	// Selector form: `pkg.{A, B => C, _}`
	if openIdx := strings.IndexByte(text, '{'); openIdx >= 0 {
		closeIdx := strings.LastIndexByte(text, '}')
		if closeIdx < openIdx {
			return nil
		}
		prefix := strings.TrimSpace(text[:openIdx])
		prefix = strings.TrimSuffix(prefix, ".")
		prefix = strings.TrimSpace(prefix)
		inner := text[openIdx+1 : closeIdx]
		var out []importPath
		for _, sel := range strings.Split(inner, ",") {
			sel = strings.TrimSpace(sel)
			if sel == "" {
				continue
			}
			// Strip `as`/`=>` aliases — keep the original name.
			if i := strings.Index(sel, "=>"); i >= 0 {
				sel = strings.TrimSpace(sel[:i])
			} else if i := strings.Index(sel, " as "); i >= 0 {
				sel = strings.TrimSpace(sel[:i])
			}
			if sel == "_" || sel == "*" {
				out = append(out, importPath{path: prefix, isWildcard: true})
				continue
			}
			out = append(out, importPath{path: joinDot(prefix, sel)})
		}
		return out
	}

	// Wildcard form: `pkg._` (Scala 2) or `pkg.*` (Scala 3 alternative).
	if strings.HasSuffix(text, "._") {
		return []importPath{{path: strings.TrimSuffix(text, "._"), isWildcard: true}}
	}
	if strings.HasSuffix(text, ".*") {
		return []importPath{{path: strings.TrimSuffix(text, ".*"), isWildcard: true}}
	}

	// Simple form: `pkg.Class` — may also include an `as`/`=>` alias.
	if i := strings.Index(text, "=>"); i >= 0 {
		text = strings.TrimSpace(text[:i])
	} else if i := strings.Index(text, " as "); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	return []importPath{{path: text}}
}

func joinDot(prefix, name string) string {
	if prefix == "" {
		return name
	}
	if name == "" {
		return prefix
	}
	return prefix + "." + name
}

// importMatches decides whether a rule-side import path matches a source-side
// import. Mirrors the Java runner's semantics.
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
