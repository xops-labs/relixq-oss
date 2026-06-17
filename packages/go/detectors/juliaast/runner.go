// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package juliaast implements a Julia-language AST runner backed by Tree-sitter
// via CGO (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Julia grammar are
// linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Julia AST detection is silently disabled.
//
// Runtime composition. smacker/go-tree-sitter (the runtime everywhere else in
// this codebase) does NOT vendor a Julia grammar. The upstream tree-sitter-julia
// module ships its own Go binding that hands back the grammar's C language
// pointer as unsafe.Pointer; that pointer is ABI-compatible with smacker's
// `*C.TSLanguage` wrapper, so we feed it to sitter.NewLanguage to get a
// smacker-shaped *sitter.Language and reuse the rest of the parser/walker
// machinery. The same trick is what unlocks juliaast without a fork or a
// second tree-sitter runtime in the binary.
//
// Query format (detector.query in the rule YAML):
//
//	call:<Module>.<func>    — Module.func(...) — call_expression whose callee
//	                          is a field_expression with matching value+field.
//	call:<func>             — bare func(...) — call_expression whose callee is
//	                          a single identifier.
//	using:<Module>          — `using Module` / `using A.B` / `using Foo: bar`;
//	                          matches when Module is the first identifier of
//	                          the using_statement's first import_path or a
//	                          direct identifier child.
//	import:<Module>         — same shape, against import_statement.
//
// Matching is syntactic — no semantic resolution, no qualified-name expansion.
// Receiver/module text is matched against the literal identifier in source.
// Argument-value matching (e.g. `Nettle.Hasher("md5")` vs `"sha256"`) is
// intentionally NOT in the DSL — those rules stay on the regex detector.
package juliaast

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	sitter "github.com/smacker/go-tree-sitter"
	tree_sitter_julia "github.com/tree-sitter/tree-sitter-julia/bindings/go"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("julia", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Julia AST query forms.
type queryKind int

const (
	queryCall   queryKind = iota // call:Module.func or call:func
	queryUsing                   // using:Module
	queryImport                  // import:Module
)

type parsedQuery struct {
	kind queryKind
	// For call — receiver module (e.g. "SHA"). Empty for bare-callee form.
	receiver string
	// For call — function name (e.g. "sha256", "md5", or bare "MD5").
	function string
	// For using/import — module name (top of the dotted path).
	module string
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
		return nil, fmt.Errorf("juliaast query %q: missing kind prefix (call:|using:|import:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call":
		if rest == "" {
			return nil, fmt.Errorf("juliaast query %q: missing callee", q)
		}
		// Split on the LAST `.` so dotted module paths (e.g. `A.B.func`) keep
		// the dots in the receiver portion. Today the runner only checks the
		// last segment of the receiver against field_expression.value, but the
		// dotted form is preserved so a future field_expression-walking pass
		// can match deeper paths.
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			// Bare callee — `call_expression(identifier=<name>)`.
			return &parsedQuery{kind: queryCall, function: rest}, nil
		}
		recv := rest[:dot]
		fn := rest[dot+1:]
		if recv == "" || fn == "" {
			return nil, fmt.Errorf("juliaast query %q: receiver and function both required", q)
		}
		return &parsedQuery{kind: queryCall, receiver: recv, function: fn}, nil
	case "using":
		if rest == "" {
			return nil, fmt.Errorf("juliaast query %q: missing module", q)
		}
		return &parsedQuery{kind: queryUsing, module: rest}, nil
	case "import":
		if rest == "" {
			return nil, fmt.Errorf("juliaast query %q: missing module", q)
		}
		return &parsedQuery{kind: queryImport, module: rest}, nil
	default:
		return nil, fmt.Errorf("juliaast query %q: unknown kind %q (want call|using|import)", q, kind)
	}
}

// Run parses source as a Julia file and returns matches for the applicable AST
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
	parser.SetLanguage(juliaLanguage())

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

// juliaLanguage returns a smacker *sitter.Language wrapping the Julia grammar
// pointer published by the upstream tree-sitter-julia Go binding. The cast goes
// through unsafe.Pointer because the two runtimes spell their `*C.TSLanguage`
// types in unrelated CGO packages — the underlying pointer ABI matches.
func juliaLanguage() *sitter.Language {
	return sitter.NewLanguage(unsafe.Pointer(tree_sitter_julia.Language()))
}

// walk traverses the syntax tree once and dispatches each node against the
// pre-compiled rule queries.
func walk(n *sitter.Node, src []byte, rqs []ruleQuery, lines []string, out *[]astdet.Match) {
	if n == nil {
		return
	}

	switch n.Type() {
	case "call_expression":
		// Julia call_expression layout:
		//   (call_expression <callee> (argument_list ...))
		// callee may be:
		//   - identifier            → bare call, `foo(x)`
		//   - field_expression      → `Module.func(x)` (value=Module, field=func)
		//   - other (macro, index)  → ignored
		if n.NamedChildCount() == 0 {
			break
		}
		callee := n.NamedChild(0)
		if callee == nil {
			break
		}
		switch callee.Type() {
		case "identifier":
			fnName := callee.Content(src)
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				// Bare-callee rule only.
				if rq.query.receiver != "" {
					continue
				}
				if rq.query.function == fnName {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		case "field_expression":
			recv, field := splitFieldExpression(callee, src)
			if recv == "" || field == "" {
				break
			}
			recvShort := lastDotSegment(recv)
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if rq.query.receiver == "" {
					// Bare-callee rule — field-expression callees aren't bare.
					continue
				}
				if rq.query.function != field {
					continue
				}
				// Match if either:
				//   - rule receiver == source receiver-last-segment, or
				//   - rule receiver == source receiver text exactly.
				if rq.query.receiver == recv || rq.query.receiver == recvShort {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}

	case "using_statement", "import_statement":
		isUsing := n.Type() == "using_statement"
		mods := collectStatementModules(n, src)
		for _, mod := range mods {
			short := lastDotSegment(mod)
			for _, rq := range rqs {
				if isUsing && rq.query.kind != queryUsing {
					continue
				}
				if !isUsing && rq.query.kind != queryImport {
					continue
				}
				if rq.query.module == mod || rq.query.module == short {
					appendMatch(out, rq.rule, n, lines)
				}
			}
		}
	}

	for i := uint32(0); i < n.NamedChildCount(); i++ {
		walk(n.NamedChild(int(i)), src, rqs, lines, out)
	}
}

// splitFieldExpression returns the dotted-path receiver text and the trailing
// field name from a `field_expression` node. For nested forms (`A.B.c`) the
// receiver text retains the inner dots ("A.B"). Returns empty strings when the
// shape is unexpected.
func splitFieldExpression(n *sitter.Node, src []byte) (recv, field string) {
	if n == nil || n.Type() != "field_expression" {
		return "", ""
	}
	// The grammar gives `value` as a named field; the trailing field name comes
	// from a named child that is NOT the value. Walking named children covers
	// both `(field_expression (identifier) (identifier))` and
	// `(field_expression (field_expression ...) (identifier))`.
	if n.NamedChildCount() < 2 {
		return "", ""
	}
	valueNode := n.ChildByFieldName("value")
	if valueNode == nil {
		valueNode = n.NamedChild(0)
	}
	// Last named child is the field.
	fieldNode := n.NamedChild(int(n.NamedChildCount()) - 1)
	if fieldNode == nil || valueNode == nil || fieldNode == valueNode {
		return "", ""
	}
	switch valueNode.Type() {
	case "identifier":
		recv = valueNode.Content(src)
	case "field_expression":
		// Recursive: rebuild dotted path for nested field expressions.
		innerRecv, innerField := splitFieldExpression(valueNode, src)
		if innerRecv != "" && innerField != "" {
			recv = innerRecv + "." + innerField
		} else {
			recv = strings.TrimSpace(valueNode.Content(src))
		}
	default:
		recv = strings.TrimSpace(valueNode.Content(src))
	}
	if fieldNode.Type() == "identifier" {
		field = fieldNode.Content(src)
	} else {
		field = strings.TrimSpace(fieldNode.Content(src))
	}
	return recv, field
}

// collectStatementModules walks a using_statement/import_statement and returns
// each module reference it carries — `using A` returns ["A"]; `using A.B`
// returns ["A.B"]; `using A, B` returns ["A","B"]; `using Foo: bar` returns
// ["Foo"] (we only track the imported module, not the symbols). Relative
// paths (`..Foo`) are normalized to "Foo".
func collectStatementModules(n *sitter.Node, src []byte) []string {
	if n == nil {
		return nil
	}
	var out []string
	for i := uint32(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(int(i))
		if c == nil {
			continue
		}
		switch c.Type() {
		case "identifier":
			// `using Sockets` — bare identifier child.
			out = append(out, c.Content(src))
		case "import_path":
			// `using A.B.C` — dotted path; collect joined form.
			if p := importPathText(c, src); p != "" {
				out = append(out, p)
			}
		case "selected_import":
			// `using Foo: bar, baz` — first child is the module; remaining
			// children are imported symbols (which we don't track here).
			if c.NamedChildCount() == 0 {
				continue
			}
			head := c.NamedChild(0)
			if head == nil {
				continue
			}
			switch head.Type() {
			case "identifier":
				out = append(out, head.Content(src))
			case "import_path":
				if p := importPathText(head, src); p != "" {
					out = append(out, p)
				}
			}
		case "import_alias":
			// `import Foo as F` — first child is the module.
			if c.NamedChildCount() == 0 {
				continue
			}
			head := c.NamedChild(0)
			if head == nil {
				continue
			}
			switch head.Type() {
			case "identifier":
				out = append(out, head.Content(src))
			case "import_path":
				if p := importPathText(head, src); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// importPathText flattens an `import_path` to a dotted source form
// ("A.B.C"). Leading-dot relative segments are emitted by the grammar as
// `operator` tokens that aren't named children, so they don't appear here.
func importPathText(n *sitter.Node, src []byte) string {
	if n == nil || n.Type() != "import_path" {
		return ""
	}
	var parts []string
	for i := uint32(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(int(i))
		if c == nil || c.Type() != "identifier" {
			continue
		}
		parts = append(parts, c.Content(src))
	}
	return strings.Join(parts, ".")
}

// lastDotSegment returns the final `.`-separated segment of a dotted Julia
// module path (e.g. "C" for "A.B.C"). For an already-bare name it returns the
// input unchanged.
func lastDotSegment(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	return path
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
