// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package javaast implements a Java-language AST runner backed by Tree-sitter
// via the smacker/go-tree-sitter CGO bindings (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Java grammar are
// linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Java AST detection is silently disabled.
//
// Query format (detector.query in the rule YAML):
//
//	call:<Type>.<method>      — Type.method(...) or receiver.method(...)
//	new:<Type>                — new Type(...) object creation
//	import:<package.Class>    — import package.Class; (also matches package.*)
//	fieldref:<Type>.<field>   — Type.field member access NOT in call position
//
// Matching is syntactic — no semantic resolution, no qualified-name expansion.
// `Type` is matched against the literal identifier that appears in source.
package javaast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("java", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Java AST query forms.
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
		return nil, fmt.Errorf("javaast query %q: missing kind prefix (call:|new:|import:|fieldref:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call", "fieldref":
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("javaast query %q: expected Type.Identifier form", q)
		}
		k := queryCall
		if kind == "fieldref" {
			k = queryFieldRef
		}
		return &parsedQuery{kind: k, typ: rest[:dot], name: rest[dot+1:]}, nil
	case "new":
		if rest == "" {
			return nil, fmt.Errorf("javaast query %q: missing type", q)
		}
		return &parsedQuery{kind: queryNew, typ: rest}, nil
	case "import":
		if rest == "" {
			return nil, fmt.Errorf("javaast query %q: missing import path", q)
		}
		return &parsedQuery{kind: queryImport, path: rest}, nil
	default:
		return nil, fmt.Errorf("javaast query %q: unknown kind %q (want call|new|import|fieldref)", q, kind)
	}
}

// Run parses source as a Java file and returns matches for the applicable AST
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
	parser.SetLanguage(java.GetLanguage())

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
	case "method_invocation":
		// Java grammar: method_invocation has named children:
		//   object: <expression>   (optional — absent for unqualified calls)
		//   name:   identifier
		obj := n.ChildByFieldName("object")
		nameNode := n.ChildByFieldName("name")
		if nameNode != nil {
			methodName := nameNode.Content(src)
			// receiver identifier; "" when object is missing or not a simple identifier
			recv := ""
			if obj != nil && obj.Type() == "identifier" {
				recv = obj.Content(src)
			}
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if rq.query.name != methodName {
					continue
				}
				if rq.query.typ != recv {
					continue
				}
				appendMatch(out, rq.rule, n, lines)
			}
		}

	case "object_creation_expression":
		// Java grammar: object_creation_expression has named field:
		//   type: <type_identifier> | <scoped_type_identifier> | <generic_type>
		typNode := n.ChildByFieldName("type")
		if typNode != nil {
			typName := simpleTypeName(typNode, src)
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
		// import_declaration child sequence is roughly:
		//   "import" [scoped_identifier | identifier] ["." "*"] ";"
		// We extract the dotted text minus the trailing "*" (if any).
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

	case "field_access":
		// field_access named children:
		//   object: <expression>
		//   field:  identifier
		// We deliberately do not filter parent kind here: a field_access that
		// is the function-receiver of a method_invocation (e.g. `Foo.bar.baz()`
		// — `Foo.bar` is the object) is still a legitimate fieldref hit. The
		// `Foo.bar()` shape never produces a field_access at all (the AST uses
		// method_invocation with `object=Foo`, `name=bar`).
		objNode := n.ChildByFieldName("object")
		fldNode := n.ChildByFieldName("field")
		if objNode != nil && fldNode != nil && objNode.Type() == "identifier" {
			typ := objNode.Content(src)
			fld := fldNode.Content(src)
			for _, rq := range rqs {
				if rq.query.kind != queryFieldRef {
					continue
				}
				if rq.query.typ != typ {
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

// simpleTypeName returns the printable form of a type expression — the bare
// identifier for type_identifier nodes and the source text for generic/scoped
// variants. Matching is intentionally lenient: rule authors write the simple
// name (`RSAPrivateKey`), and we accept `RSAPrivateKey`, `RSAPrivateKey<...>`,
// and `pkg.RSAPrivateKey`.
func simpleTypeName(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case "type_identifier", "identifier":
		return n.Content(src)
	case "generic_type":
		// generic_type wraps a (scoped_)type_identifier and type_arguments;
		// the first named child is the underlying type.
		if c := n.NamedChild(0); c != nil {
			return simpleTypeName(c, src)
		}
	case "scoped_type_identifier", "scoped_identifier":
		// scoped_identifier(pkg.Sub.Type) — take the last segment as the
		// "simple" name so rule authors can write `RSAPrivateKey` and still
		// match `java.security.interfaces.RSAPrivateKey`.
		full := n.Content(src)
		if i := strings.LastIndexByte(full, '.'); i >= 0 {
			return full[i+1:]
		}
		return full
	}
	return n.Content(src)
}

// importPathOf returns the dotted import path declared by an import_declaration
// node and whether it ends in `.*`. Returns ("","false") if the path can't be
// extracted.
func importPathOf(n *sitter.Node, src []byte) (string, bool) {
	text := strings.TrimSpace(n.Content(src))
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "static")
	text = strings.TrimSpace(text)
	if text == "" {
		return "", false
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
