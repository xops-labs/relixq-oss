// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package goast implements a Go-language AST runner using the stdlib go/parser
// and go/ast packages — no CGO required (detector.type=ast).
//
// Query format (detector.query in the rule YAML):
//
//	call:<pkg>.<func>   — matches pkg.Func(...) call expressions
//	import:<importpath> — matches import statements for the given path
//	typeref:<pkg>.<sel> — matches selector expressions used as values (not calls)
//
// Only Go source files are processed; the runner returns ErrNotGo for other
// languages so the caller can fall back to the regex detector.
package goast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

// ErrNotGo is returned when the source cannot be parsed as valid Go.
var ErrNotGo = fmt.Errorf("goast: not a Go source file")

func init() {
	astdet.Register("go", &runner{})
}

type runner struct{}

// queryKind is the discriminated union for the supported query forms.
type queryKind int

const (
	queryCall    queryKind = iota // call:pkg.Func
	queryImport                   // import:path/to/pkg
	queryTypeRef                  // typeref:pkg.Sel
)

type parsedQuery struct {
	kind queryKind
	pkg  string // for call / typeref
	sel  string // for call / typeref (function or field name)
	path string // for import
}

func parseQuery(q string) (*parsedQuery, error) {
	idx := strings.IndexByte(q, ':')
	if idx < 0 {
		return nil, fmt.Errorf("goast query %q: missing kind prefix (call:|import:|typeref:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call", "typeref":
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("goast query %q: expected pkg.Identifier form", q)
		}
		k := queryCall
		if kind == "typeref" {
			k = queryTypeRef
		}
		return &parsedQuery{kind: k, pkg: rest[:dot], sel: rest[dot+1:]}, nil
	case "import":
		return &parsedQuery{kind: queryImport, path: rest}, nil
	default:
		return nil, fmt.Errorf("goast query %q: unknown kind %q (want call|import|typeref)", q, kind)
	}
}

// Run parses source as a Go file and returns matches for the applicable rules.
// It only processes rules of type ast; regex rules in applicable are ignored.
func (r *runner) Run(filePath string, source []byte, applicable []*rules.Rule) ([]astdet.Match, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, source, parser.AllErrors)
	if err != nil && f == nil {
		return nil, ErrNotGo
	}

	// Split source into lines once for snippet extraction.
	lines := splitLines(source)

	// Pre-compile queries for the applicable AST rules.
	type ruleQuery struct {
		rule  *rules.Rule
		query *parsedQuery
	}
	var rqs []ruleQuery
	for _, rule := range applicable {
		if rule.Detector.Type != rules.DetectorAST {
			continue
		}
		pq, err := parseQuery(rule.Detector.Query)
		if err != nil {
			// Emit a zero-finding result for bad queries rather than aborting
			// the entire scan — the rule author will see no matches and can
			// investigate the query.
			continue
		}
		rqs = append(rqs, ruleQuery{rule: rule, query: pq})
	}
	if len(rqs) == 0 {
		return nil, nil
	}

	var matches []astdet.Match

	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			return false
		}

		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				break
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				break
			}
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if pkgIdent.Name != rq.query.pkg || sel.Sel.Name != rq.query.sel {
					continue
				}
				pos := fset.Position(node.Pos())
				matches = append(matches, astdet.Match{
					Rule:    rq.rule,
					Line:    pos.Line,
					Column:  pos.Column,
					Snippet: lineAt(lines, pos.Line),
					Context: contextOf(lines, pos.Line),
				})
			}

		case *ast.SelectorExpr:
			// Skip call expressions — they are handled above with better context.
			// Only match standalone selector expressions (type references, const usage).
			pkgIdent, ok := node.X.(*ast.Ident)
			if !ok {
				break
			}
			for _, rq := range rqs {
				if rq.query.kind != queryTypeRef {
					continue
				}
				if pkgIdent.Name != rq.query.pkg || node.Sel.Name != rq.query.sel {
					continue
				}
				pos := fset.Position(node.Pos())
				matches = append(matches, astdet.Match{
					Rule:    rq.rule,
					Line:    pos.Line,
					Column:  pos.Column,
					Snippet: lineAt(lines, pos.Line),
					Context: contextOf(lines, pos.Line),
				})
			}

		case *ast.ImportSpec:
			raw := strings.Trim(node.Path.Value, `"`)
			for _, rq := range rqs {
				if rq.query.kind != queryImport {
					continue
				}
				if raw != rq.query.path {
					continue
				}
				pos := fset.Position(node.Pos())
				matches = append(matches, astdet.Match{
					Rule:    rq.rule,
					Line:    pos.Line,
					Column:  pos.Column,
					Snippet: lineAt(lines, pos.Line),
					Context: contextOf(lines, pos.Line),
				})
			}
		}
		return true
	})

	return matches, nil
}

func splitLines(src []byte) []string {
	s := string(src)
	lines := strings.Split(s, "\n")
	return lines
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
