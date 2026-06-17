// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package cppast implements a single AST runner that handles both C and C++
// source files, backed by Tree-sitter via the smacker/go-tree-sitter CGO
// bindings (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled C and C++
// grammars are linked at build time. Builds without CGO compile the no-op
// stub in runner_stub.go instead, and C/C++ AST detection is silently
// disabled.
//
// One runner instance is registered for both "c" and "cpp" languages, and
// the grammar to parse with is chosen per-call from the file extension —
// `.c` / `.h` use the C grammar, anything else (`.cpp`, `.cc`, `.cxx`,
// `.hpp`, `.hxx`) uses the C++ grammar. The two grammars share nearly every
// node type the OpenSSL-focused rules care about (call_expression,
// identifier, field_expression, preproc_include), so a single walker covers
// both.
//
// Query format (detector.query in the rule YAML):
//
//	call:<name>              — bare function call, e.g. RSA_generate_key_ex(...)
//	call:<Class::method>     — C++ qualified call, e.g. OpenSSL::Hash::compute(...)
//	methodcall:<method>      — instance method call, e.g. obj.method(...)
//	                            or obj->method(...); receiver type is ignored
//	include:<path>           — #include <path> or #include "path"
//	ident:<name>             — bare identifier reference (constants like
//	                            RSA_PKCS1_PADDING); call callees and
//	                            declarators are not matched
//
// Matching is syntactic — no semantic resolution, no preprocessor expansion.
package cppast

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	tsc "github.com/smacker/go-tree-sitter/c"
	tscpp "github.com/smacker/go-tree-sitter/cpp"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	r := &runner{}
	astdet.Register("c", r)
	astdet.Register("cpp", r)
}

type runner struct{}

// queryKind enumerates the supported C/C++ AST query forms.
type queryKind int

const (
	queryCall       queryKind = iota // call:Name or call:A::B
	queryMethodCall                  // methodcall:method
	queryInclude                     // include:path
	queryIdent                       // ident:Name
)

type parsedQuery struct {
	kind queryKind
	// For call (bare): name only. For call (qualified C++): full "A::B" text.
	// For methodcall: method name only. For ident: identifier name.
	// For include: header path.
	value string
}

// ruleQuery pairs a rule with its pre-parsed query so we don't re-parse on
// every node visit.
type ruleQuery struct {
	rule  *rules.Rule
	query *parsedQuery
}

func parseQuery(q string) (*parsedQuery, error) {
	idx := strings.IndexByte(q, ':')
	if idx < 0 {
		return nil, fmt.Errorf("cppast query %q: missing kind prefix (call:|methodcall:|include:|ident:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	if rest == "" {
		return nil, fmt.Errorf("cppast query %q: missing value", q)
	}
	switch kind {
	case "call":
		return &parsedQuery{kind: queryCall, value: rest}, nil
	case "methodcall":
		return &parsedQuery{kind: queryMethodCall, value: rest}, nil
	case "include":
		return &parsedQuery{kind: queryInclude, value: rest}, nil
	case "ident":
		return &parsedQuery{kind: queryIdent, value: rest}, nil
	default:
		return nil, fmt.Errorf("cppast query %q: unknown kind %q (want call|methodcall|include|ident)", q, kind)
	}
}

// languageFor selects the Tree-sitter grammar based on file extension.
// `.c` and `.h` use the C grammar; everything else (`.cpp`, `.cc`, `.cxx`,
// `.hpp`, `.hxx`) uses the C++ grammar. Caveat: `.h` files that actually
// contain C++ get routed to the C parser. The C grammar tolerates most C
// declarations and call sites, and the OpenSSL APIs we target use plain C
// linkage, so this is acceptable for the rules in the v1 pack. Projects
// with C++-only `.h` headers can rename them to `.hpp`.
func languageFor(filePath string) *sitter.Language {
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".c", ".h":
		return tsc.GetLanguage()
	default:
		return tscpp.GetLanguage()
	}
}

// Run parses source with the C or C++ grammar (chosen by filePath extension)
// and returns matches for the applicable AST rules. Regex rules in
// `applicable` are ignored. Parse failures return (nil, nil) so the caller
// treats them as "no findings", consistent with the regex detector.
func (r *runner) Run(filePath string, source []byte, applicable []*rules.Rule) ([]astdet.Match, error) {
	// Pre-compile queries. Rules with a malformed query are skipped silently
	// so a single bad rule doesn't sink the whole file scan.
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
	parser.SetLanguage(languageFor(filePath))

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
		// Tree-sitter C/C++ grammar: call_expression has a named field
		// `function` (the callee) and `arguments`. The callee can be:
		//   - `identifier`            — bare function call: foo(...)
		//   - `field_expression`      — instance call: obj.foo(...) or obj->foo(...)
		//   - `qualified_identifier`  — C++ scoped call: A::B::foo(...)
		// We dispatch on the callee's node type and emit:
		//   - queryCall       for identifier and qualified_identifier
		//   - queryMethodCall for field_expression (record method name only)
		callee := n.ChildByFieldName("function")
		if callee == nil {
			break
		}
		switch callee.Type() {
		case "identifier":
			name := callee.Content(src)
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if rq.query.value != name {
					continue
				}
				appendMatch(out, rq.rule, n, lines)
			}
		case "qualified_identifier", "template_function":
			// `A::B` or `A::B<T>`. Render as the literal source text so a
			// rule author writing `call:OpenSSL::Hash::compute` matches it.
			// template_function wraps a qualified or plain name plus
			// template_argument_list; we strip everything from `<` onward
			// so generic instantiation suffixes don't break matching.
			full := stripTemplateSuffix(callee.Content(src))
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if rq.query.value != full {
					continue
				}
				appendMatch(out, rq.rule, n, lines)
			}
		case "field_expression":
			// obj.method(...) or obj->method(...).
			// field_expression has a named child `field` which is the
			// member name. Receiver type is intentionally not constrained
			// — the rule's query is `methodcall:<method>` only.
			fld := callee.ChildByFieldName("field")
			if fld == nil {
				break
			}
			methodName := fld.Content(src)
			for _, rq := range rqs {
				if rq.query.kind != queryMethodCall {
					continue
				}
				if rq.query.value != methodName {
					continue
				}
				appendMatch(out, rq.rule, n, lines)
			}
		}

	case "preproc_include":
		// #include <openssl/rsa.h>   — child is `system_lib_string` (e.g. "<openssl/rsa.h>")
		// #include "openssl/rsa.h"   — child is `string_literal`     (e.g. "\"openssl/rsa.h\"")
		// We extract the inner path (no quotes / angle brackets) and match
		// against the rule's value verbatim.
		path := includePathOf(n, src)
		if path == "" {
			break
		}
		for _, rq := range rqs {
			if rq.query.kind != queryInclude {
				continue
			}
			if rq.query.value != path {
				continue
			}
			appendMatch(out, rq.rule, n, lines)
		}

	case "identifier":
		// Bare identifier reference. We only fire if there is at least one
		// queryIdent rule waiting for this name AND the identifier is being
		// used as a value (not a declarator, not the function callee of a
		// call_expression — those are handled above and would double-fire).
		//
		// Filtering rule: skip identifiers whose immediate parent is a
		// `call_expression` with this identifier as the `function` field,
		// any kind of declarator node, or a function/parameter definition
		// header. This is a heuristic, but it cleanly removes the noisy
		// matches without semantic analysis.
		if !hasIdentRule(rqs) {
			break
		}
		if shouldSkipIdent(n) {
			break
		}
		name := n.Content(src)
		for _, rq := range rqs {
			if rq.query.kind != queryIdent {
				continue
			}
			if rq.query.value != name {
				continue
			}
			appendMatch(out, rq.rule, n, lines)
		}
	}

	for i := uint32(0); i < n.ChildCount(); i++ {
		walk(n.Child(int(i)), src, rqs, lines, out)
	}
}

// hasIdentRule reports whether any of the pre-compiled rule queries is an
// `ident:` form. Used to short-circuit the identifier visit when no ident
// rules are active — the C/C++ grammar produces an `identifier` node for
// every name reference, so this check matters for performance.
func hasIdentRule(rqs []ruleQuery) bool {
	for _, rq := range rqs {
		if rq.query.kind == queryIdent {
			return true
		}
	}
	return false
}

// shouldSkipIdent decides whether a bare `identifier` node is in a context
// that we do NOT want to flag for an `ident:` rule. We skip:
//
//   - call_expression.function — already covered by queryCall
//   - field_expression.field   — already covered by queryMethodCall
//   - qualified_identifier internals — part of an A::B path
//   - declarator-shaped parents — function/variable/parameter declarations
//   - preproc_def / preproc_function_def — macro names being defined
//
// This is a syntactic filter; it does not catch every possible declaration
// site, but it removes the cases that would otherwise fire spuriously on
// every C/C++ source file.
func shouldSkipIdent(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil {
		return false
	}
	switch parent.Type() {
	case "call_expression":
		// identifier-as-callee — covered by queryCall on the call_expression.
		if fn := parent.ChildByFieldName("function"); fn != nil && fn.Equal(n) {
			return true
		}
	case "field_expression":
		// foo.bar — bar is the field (covered by methodcall when in a call
		// position); foo is the receiver and is technically a value
		// reference, but flagging it as ident on every member access is too
		// noisy. Skip both children.
		return true
	case "qualified_identifier", "template_function", "template_type":
		// part of A::B path or template instantiation — ident: targets
		// stand-alone references.
		return true
	case "function_declarator", "init_declarator", "pointer_declarator",
		"array_declarator", "reference_declarator", "parameter_declaration",
		"struct_specifier", "class_specifier", "union_specifier",
		"enum_specifier", "type_definition", "field_declaration",
		"preproc_def", "preproc_function_def", "preproc_params":
		// Declaration / definition sites — not a value reference.
		return true
	}
	return false
}

// stripTemplateSuffix trims `<...>` from a qualified call rendering so rules
// match by base name regardless of template instantiation. e.g. "Foo<T>::bar"
// → "Foo<T>::bar" (untouched, since the suffix is part of the type name we
// keep) but "Foo::bar<T>" → "Foo::bar". We only strip a trailing `<...>`
// segment when it appears AFTER the final `::`, leaving qualifier templates
// intact.
func stripTemplateSuffix(s string) string {
	lastSep := strings.LastIndex(s, "::")
	tail := s
	prefix := ""
	if lastSep >= 0 {
		prefix = s[:lastSep+2]
		tail = s[lastSep+2:]
	}
	if i := strings.IndexByte(tail, '<'); i >= 0 {
		tail = tail[:i]
	}
	return prefix + tail
}

// includePathOf returns the bare path of a `#include` directive. Handles both
// `#include <foo.h>` (where the child is system_lib_string carrying `<foo.h>`)
// and `#include "foo.h"` (child is string_literal carrying `"foo.h"`). The
// surrounding `<>` or `""` are trimmed.
func includePathOf(n *sitter.Node, src []byte) string {
	// Walk named children — the path token is the only thing besides the
	// `#include` keyword.
	for i := uint32(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(int(i))
		if c == nil {
			continue
		}
		text := c.Content(src)
		switch c.Type() {
		case "system_lib_string":
			// "<path>"
			text = strings.TrimPrefix(text, "<")
			text = strings.TrimSuffix(text, ">")
			return strings.TrimSpace(text)
		case "string_literal":
			// `"path"` — string_literal's content includes the quote chars.
			// Some grammar versions wrap the contents in a `string_content`
			// child; either way we just strip surrounding quotes.
			text = strings.TrimSpace(text)
			text = strings.Trim(text, "\"")
			return text
		}
	}
	// Fallback: scan the literal text of the directive.
	raw := strings.TrimSpace(n.Content(src))
	raw = strings.TrimPrefix(raw, "#include")
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		first, last := raw[0], raw[len(raw)-1]
		if (first == '<' && last == '>') || (first == '"' && last == '"') {
			return raw[1 : len(raw)-1]
		}
	}
	return ""
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
