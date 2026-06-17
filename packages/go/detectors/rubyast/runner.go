// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build cgo

// Package rubyast implements a Ruby-language AST runner backed by Tree-sitter
// via the smacker/go-tree-sitter CGO bindings (detector.type=ast).
//
// CGO is required — the Tree-sitter C runtime and the bundled Ruby grammar are
// linked at build time. Builds without CGO compile the no-op stub in
// runner_stub.go instead, and Ruby AST detection is silently disabled.
//
// Query format (detector.query in the rule YAML):
//
//	call:<Receiver>.<method>   — Receiver.method(...) OR receiver.method(...);
//	                             Receiver may be a simple constant ("Cipher"),
//	                             a scoped constant path ("OpenSSL::Cipher"),
//	                             or a bare identifier (receiver variable name).
//	                             A rule that writes the short final segment
//	                             ("MD5.new") also matches the fully scoped form
//	                             ("Digest::MD5.new").
//	new:<Const::Path>          — Const.new(...) or Const::Path.new(...);
//	                             sugar for call:<Const::Path>.new with the
//	                             same short/long matching semantics.
//	const:<Const::Path>        — bare constant reference (Digest::MD5,
//	                             OpenSSL::PKey::RSA) NOT in call-receiver
//	                             position; surfaces dependency-level signals
//	                             without double-counting call sites.
//	require:<lib>              — require 'lib' / require_relative 'lib';
//	                             matches the literal string argument.
//
// `::` and `.` distinction. Ruby spells namespace lookup with `::`
// (scope_resolution) and instance/class method dispatch with `.` (call). The
// grammar reflects this with two different node shapes, but semantically both
// are message sends. The DSL collapses them: `call:Digest::MD5.new` matches
// `Digest::MD5.new(...)` AND `MD5.new(...)` when `MD5` is a bare receiver.
// Rule authors can write either the simple final segment or the fully scoped
// path; matching tries both. This is intentionally permissive — Ruby code
// regularly opens a module and refers to constants by short name.
//
// Matching is syntactic — no semantic resolution, no constant-path expansion,
// no `include`/`open class`/refinement tracking. The receiver written in
// `call:` is matched against the literal text of the source receiver.
package rubyast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/ruby"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	astdet.Register("ruby", &runner{})
}

type runner struct{}

// queryKind enumerates the supported Ruby AST query forms.
type queryKind int

const (
	queryCall    queryKind = iota // call:Receiver.method
	queryNew                      // new:Const::Path
	queryConst                    // const:Const::Path
	queryRequire                  // require:lib
)

type parsedQuery struct {
	kind queryKind
	// For call/new — receiver constant path (e.g. "Digest::MD5", "OpenSSL::Cipher").
	receiver string
	// For call/new — last segment of receiver (e.g. "MD5" for "Digest::MD5").
	// Pre-computed so we can match short receivers cheaply at walk time.
	receiverShort string
	// For call — the method name (e.g. "hexdigest", "new").
	method string
	// For const — the full constant path.
	constPath string
	// For const — the last segment of the path, used as a permissive fallback.
	constShort string
	// For require — the literal library name (no quotes).
	libName string
}

// ruleQuery pairs a rule with its pre-parsed query so we don't re-parse the
// query string per node visit.
type ruleQuery struct {
	rule  *rules.Rule
	query *parsedQuery
}

// lastSegment returns the final `::`-separated segment of a Ruby constant path
// (e.g. "MD5" for "Digest::MD5"). For an already-bare name it returns the
// input unchanged.
func lastSegment(path string) string {
	if i := strings.LastIndex(path, "::"); i >= 0 {
		return path[i+2:]
	}
	return path
}

func parseQuery(q string) (*parsedQuery, error) {
	idx := strings.IndexByte(q, ':')
	if idx < 0 {
		return nil, fmt.Errorf("rubyast query %q: missing kind prefix (call:|new:|const:|require:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call":
		// Split on the LAST "." so a scoped receiver like "OpenSSL::Cipher.new"
		// keeps its `::` segments intact in the receiver portion.
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("rubyast query %q: expected Receiver.method form", q)
		}
		recv := rest[:dot]
		meth := rest[dot+1:]
		if recv == "" || meth == "" {
			return nil, fmt.Errorf("rubyast query %q: receiver and method both required", q)
		}
		return &parsedQuery{
			kind:          queryCall,
			receiver:      recv,
			receiverShort: lastSegment(recv),
			method:        meth,
		}, nil
	case "new":
		if rest == "" {
			return nil, fmt.Errorf("rubyast query %q: missing constant path", q)
		}
		return &parsedQuery{
			kind:          queryNew,
			receiver:      rest,
			receiverShort: lastSegment(rest),
			method:        "new",
		}, nil
	case "const":
		if rest == "" {
			return nil, fmt.Errorf("rubyast query %q: missing constant path", q)
		}
		return &parsedQuery{
			kind:       queryConst,
			constPath:  rest,
			constShort: lastSegment(rest),
		}, nil
	case "require":
		if rest == "" {
			return nil, fmt.Errorf("rubyast query %q: missing library name", q)
		}
		return &parsedQuery{kind: queryRequire, libName: rest}, nil
	default:
		return nil, fmt.Errorf("rubyast query %q: unknown kind %q (want call|new|const|require)", q, kind)
	}
}

// Run parses source as a Ruby file and returns matches for the applicable AST
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
	parser.SetLanguage(ruby.GetLanguage())

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
	walk(root, nil, source, rqs, lines, &matches)
	return matches, nil
}

// walk traverses the syntax tree once and dispatches each node against the
// pre-compiled rule queries. We carry the parent pointer so we can suppress
// const-ref matches whose parent is a call (those constants are already the
// receiver of a method call and should be reported via the call: rule, not
// const: as well).
func walk(n, parent *sitter.Node, src []byte, rqs []ruleQuery, lines []string, out *[]astdet.Match) {
	if n == nil {
		return
	}

	switch n.Type() {
	case "call":
		// tree-sitter-ruby `call` node fields:
		//   receiver: <expression> (optional — absent for bare calls like `require ...`)
		//   method:   identifier | constant | operator | ...
		//   arguments: argument_list (optional)
		//   block:    block | do_block (optional)
		//
		// Three shapes we care about:
		//   1. `Digest::MD5.new(x)` — receiver is scope_resolution, method=identifier("new")
		//   2. `obj.hexdigest(x)`   — receiver is identifier, method=identifier("hexdigest")
		//   3. `require 'openssl'`  — no receiver, method=identifier("require"), arg is string
		recvNode := n.ChildByFieldName("receiver")
		methNode := n.ChildByFieldName("method")
		argsNode := n.ChildByFieldName("arguments")

		methName := ""
		if methNode != nil {
			methName = methNode.Content(src)
		}

		// require / require_relative — a call with no receiver and a string arg.
		if recvNode == nil && (methName == "require" || methName == "require_relative") {
			lib := extractStringLiteral(argsNode, src)
			if lib != "" {
				for _, rq := range rqs {
					if rq.query.kind != queryRequire {
						continue
					}
					if rq.query.libName == lib {
						appendMatch(out, rq.rule, n, lines)
					}
				}
			}
		}

		// call:Receiver.method and new:Receiver — both fire on `call` nodes with
		// a receiver. We compute the receiver text once and try every applicable
		// rule against it.
		if recvNode != nil && methName != "" {
			recvFull := receiverText(recvNode, src)
			recvShort := lastSegment(recvFull)
			for _, rq := range rqs {
				switch rq.query.kind {
				case queryCall, queryNew:
					if rq.query.method != methName {
						continue
					}
					if receiverMatches(rq.query, recvFull, recvShort) {
						appendMatch(out, rq.rule, n, lines)
					}
				}
			}
		}

	case "scope_resolution":
		// `Digest::MD5` (or longer `OpenSSL::PKey::RSA`) — a bare constant
		// reference. We only fire const: rules here; if this scope_resolution
		// is the receiver of a call, the call: rule (above) is the right hook
		// for that site, so suppress to avoid double-reporting.
		if parent != nil && parent.Type() == "call" {
			// Receiver of a call — let the call branch handle it.
			break
		}
		path := scopeResolutionText(n, src)
		short := lastSegment(path)
		for _, rq := range rqs {
			if rq.query.kind != queryConst {
				continue
			}
			if rq.query.constPath == path || rq.query.constShort == short {
				appendMatch(out, rq.rule, n, lines)
			}
		}
	}

	for i := uint32(0); i < n.ChildCount(); i++ {
		walk(n.Child(int(i)), n, src, rqs, lines, out)
	}
}

// receiverText returns the printable form of a `call` receiver, normalized for
// rule matching. For a `scope_resolution` node it returns the full `A::B::C`
// path; for a bare `constant` or `identifier` it returns the name.
func receiverText(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case "scope_resolution":
		return scopeResolutionText(n, src)
	case "constant", "identifier":
		return n.Content(src)
	}
	// Fallback for less common shapes (method chains, self, etc.) — use raw
	// text. This may include whitespace; we don't currently match on these.
	return strings.TrimSpace(n.Content(src))
}

// scopeResolutionText flattens a (possibly nested) scope_resolution node to its
// dotted-by-`::` source form. Recursive: `scope_resolution(scope=scope_resolution(...),
// name=constant)` rebuilds the full path.
func scopeResolutionText(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	if n.Type() != "scope_resolution" {
		return strings.TrimSpace(n.Content(src))
	}
	scopeNode := n.ChildByFieldName("scope")
	nameNode := n.ChildByFieldName("name")
	var head string
	switch {
	case scopeNode == nil:
		// Top-level `::Foo` — no scope.
		head = ""
	case scopeNode.Type() == "scope_resolution":
		head = scopeResolutionText(scopeNode, src)
	default:
		head = strings.TrimSpace(scopeNode.Content(src))
	}
	tail := ""
	if nameNode != nil {
		tail = nameNode.Content(src)
	}
	switch {
	case head == "" && tail == "":
		return strings.TrimSpace(n.Content(src))
	case head == "":
		return tail
	case tail == "":
		return head
	default:
		return head + "::" + tail
	}
}

// receiverMatches decides whether a source-side receiver satisfies a call/new
// rule. The rule matches if EITHER:
//   - the rule's full receiver path matches the source path exactly, OR
//   - the rule's last segment matches the source's last segment (permissive —
//     covers `Digest::MD5` rule vs `MD5` source when the module is opened).
func receiverMatches(q *parsedQuery, srcFull, srcShort string) bool {
	if q.receiver == srcFull {
		return true
	}
	// Permissive short-segment fallback: only useful when at least one side is
	// scoped. If both sides are already bare names, the exact check above
	// already handled it; the fallback would just repeat the work.
	if q.receiverShort != "" && q.receiverShort == srcShort {
		return true
	}
	return false
}

// extractStringLiteral pulls the literal text of the first string argument from
// an argument_list, e.g. `'openssl'` -> `openssl`. Returns "" if the arg list
// is missing, empty, or the first arg is not a plain string.
func extractStringLiteral(argList *sitter.Node, src []byte) string {
	if argList == nil {
		return ""
	}
	for i := uint32(0); i < argList.NamedChildCount(); i++ {
		c := argList.NamedChild(int(i))
		if c == nil {
			continue
		}
		if c.Type() != "string" {
			// First positional arg isn't a string — give up; require'd libs
			// are always string literals in practice.
			return ""
		}
		// `string` wraps `string_content` (and the quote tokens are unnamed).
		// Concatenating named children gives us the unquoted body without
		// dealing with the `'` or `"` tokens.
		var b strings.Builder
		for j := uint32(0); j < c.NamedChildCount(); j++ {
			cc := c.NamedChild(int(j))
			if cc == nil {
				continue
			}
			if cc.Type() == "string_content" {
				b.WriteString(cc.Content(src))
			}
		}
		return b.String()
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
