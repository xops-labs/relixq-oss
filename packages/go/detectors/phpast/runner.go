// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package phpast implements an in-process PHP AST runner using
// github.com/z7zmey/php-parser (pure Go — no CGO, no external PHP runtime
// required). The same *runner is registered for the "php" language.
//
// z7zmey/php-parser supports both PHP 5 and PHP 7 syntax; we hand it the
// version string "7.4" by default, which is a superset of legacy PHP features
// our crypto rules need to see (mcrypt_* is still present in pre-7.2 source
// we must scan even though it was removed at runtime in PHP 7.2). The version
// only affects a handful of edge tokens — for our detection purposes any
// modern PHP file parses cleanly.
//
// Query format (detector.query in the rule YAML):
//
//	call:<name>                 — free function call `name(...)`. PHP has many
//	                              standalone crypto functions (md5, sha1, crypt,
//	                              hash, openssl_*, mcrypt_*, sodium_*), so the
//	                              bare-function form is the workhorse.
//	method:<Class>.<method>     — covers both `$obj->method(...)` where the
//	                              receiver variable is named `$Class` (case-
//	                              sensitive match against the variable name) AND
//	                              `Class::method(...)` static calls (match
//	                              against the literal class identifier — no full
//	                              type resolution).
//	new:<Class>                 — `new Class(...)` or `new \Foo\Bar(...)`. The
//	                              query value is matched against the dotted
//	                              form of the class name (we render PHP's `\`
//	                              namespace separator as `.` so rules read
//	                              consistently across languages).
//	use:<namespace.Class>       — `use Namespace\Class;`, `use Namespace\Class
//	                              as Alias;`, group uses, and the wildcard form
//	                              `use Namespace\*;`. Rule path uses `.` as the
//	                              separator; a trailing `.*` is a wildcard.
//	const:<NAME>                — bare constant reference such as
//	                              `OPENSSL_KEYTYPE_RSA` or `MCRYPT_DES`. PHP
//	                              uses ALL_CAPS module constants extensively;
//	                              the AST node is `expr.ConstFetch` wrapping a
//	                              `name.Name` whose single part is the const.
//
// Matching is syntactic — no full type resolution, no semantic alias chasing.
// Rule authors write the simple identifier (`RSA`) and we accept any
// occurrence of `RSA`, `Crypt\RSA`, or `\phpseclib3\Crypt\RSA` by rendering
// the AST name as a dotted string and comparing against the trailing segment
// (or the whole string for fully-qualified rules). See classNameMatches and
// useMatches for the exact comparison rules.
package phpast

import (
	"fmt"
	"strings"

	"github.com/z7zmey/php-parser/node"
	"github.com/z7zmey/php-parser/node/expr"
	"github.com/z7zmey/php-parser/node/name"
	"github.com/z7zmey/php-parser/node/stmt"
	"github.com/z7zmey/php-parser/parser"
	"github.com/z7zmey/php-parser/position"
	"github.com/z7zmey/php-parser/walker"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

// defaultPHPVersion is handed to z7zmey/php-parser. 7.4 parses the vast
// majority of legacy PHP code (including mcrypt_* references that the runtime
// removed in 7.2 but that still appear in real-world source). PHP 8 syntax
// that the parser doesn't recognize (e.g. enums, named args, readonly props)
// surfaces as parse errors which the runner treats as "no findings" rather
// than panicking — consistent with every other language detector.
const defaultPHPVersion = "7.4"

func init() {
	astdet.Register("php", &runner{})
}

type runner struct{}

// queryKind enumerates the supported PHP AST query forms.
type queryKind int

const (
	queryCall   queryKind = iota // call:<name>             — free function
	queryMethod                  // method:<Class>.<method> — $obj->m / C::m
	queryNew                     // new:<Class>             — new C(...)
	queryUse                     // use:<dotted.path>       — use ...;
	queryConst                   // const:<NAME>            — bare const ref
)

type parsedQuery struct {
	kind queryKind
	// For call: the bare function identifier.
	// For new / method (class portion): the class identifier (last segment of
	// any namespace) or the dotted fully-qualified form.
	name string
	// For method: the method name (after the dot).
	method string
	// For use: the full dotted path; wildcard set true when the path ends `.*`.
	path     string
	wildcard bool
	// For use: the path prefix with `.*` stripped (and trailing `.` removed).
	wildcardPrefix string
}

func parseQuery(q string) (*parsedQuery, error) {
	idx := strings.IndexByte(q, ':')
	if idx < 0 {
		return nil, fmt.Errorf("phpast query %q: missing kind prefix (call:|method:|new:|use:|const:)", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	if rest == "" {
		return nil, fmt.Errorf("phpast query %q: empty value", q)
	}
	switch kind {
	case "call":
		return &parsedQuery{kind: queryCall, name: rest}, nil
	case "method":
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("phpast query %q: expected Class.method form", q)
		}
		return &parsedQuery{kind: queryMethod, name: rest[:dot], method: rest[dot+1:]}, nil
	case "new":
		return &parsedQuery{kind: queryNew, name: rest}, nil
	case "use":
		if strings.HasSuffix(rest, ".*") {
			prefix := strings.TrimSuffix(rest, ".*")
			return &parsedQuery{kind: queryUse, path: rest, wildcard: true, wildcardPrefix: prefix}, nil
		}
		return &parsedQuery{kind: queryUse, path: rest}, nil
	case "const":
		return &parsedQuery{kind: queryConst, name: rest}, nil
	default:
		return nil, fmt.Errorf("phpast query %q: unknown kind %q (want call|method|new|use|const)", q, kind)
	}
}

// ruleQuery pairs a rule with its pre-parsed query so we don't re-parse the
// query string per node visit.
type ruleQuery struct {
	rule  *rules.Rule
	query *parsedQuery
}

// Run parses source as a PHP file and returns matches for the applicable AST
// rules. Regex rules in applicable are ignored. A parse error returns a nil
// slice with no error so the caller treats it as "no findings" (consistent
// with the rest of the AST detector family).
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

	// Empty source: nothing to do.
	if len(strings.TrimSpace(string(source))) == 0 {
		return nil, nil
	}

	// Ensure the source starts with a PHP open tag — z7zmey/php-parser treats
	// content outside `<?php` as inline HTML and won't surface call/new/use
	// nodes for it. Test fixtures often omit the tag, so prepend one if the
	// source doesn't already have one. We track the prepend so line numbers
	// remain aligned with the user's source.
	src, linesAdded := ensurePHPOpenTag(source)

	p, err := parser.NewParser(src, defaultPHPVersion)
	if err != nil {
		return nil, nil
	}
	p.Parse()

	root := p.GetRootNode()
	if root == nil {
		return nil, nil
	}

	origLines := strings.Split(string(source), "\n")
	v := &visitor{
		rqs:        rqs,
		origLines:  origLines,
		linesAdded: linesAdded,
	}
	root.Walk(v)
	return v.matches, nil
}

// ensurePHPOpenTag prepends `<?php\n` to source if no `<?` tag is present at
// the beginning of the file. Returns the (possibly modified) bytes and the
// number of lines added so the visitor can subtract them from reported
// positions to keep them aligned with the user's original source.
func ensurePHPOpenTag(source []byte) ([]byte, int) {
	// Skip a leading BOM/whitespace for the lookahead.
	probe := source
	if len(probe) >= 3 && probe[0] == 0xEF && probe[1] == 0xBB && probe[2] == 0xBF {
		probe = probe[3:]
	}
	probe = []byte(strings.TrimLeft(string(probe), " \t\r\n"))
	if len(probe) >= 2 && probe[0] == '<' && probe[1] == '?' {
		return source, 0
	}
	out := make([]byte, 0, len(source)+6)
	out = append(out, []byte("<?php\n")...)
	out = append(out, source...)
	return out, 1
}

// visitor implements walker.Visitor. It walks the entire PHP AST once and
// dispatches every visited node against the pre-compiled rule queries.
type visitor struct {
	rqs        []ruleQuery
	origLines  []string
	linesAdded int
	matches    []astdet.Match
}

// EnterNode is the only callback we use. We always return true so the walk
// continues into the node's children; this keeps the dispatch one-pass and
// matches the goja/javaast convention.
func (v *visitor) EnterNode(w walker.Walkable) bool {
	switch n := w.(type) {

	case *expr.FunctionCall:
		// PHP `name(...)` — n.Function is a *name.Name for free-function calls
		// and a *name.FullyQualified when written as `\name(...)`. Both yield
		// the same simple identifier when we render their parts. Method calls
		// and dynamic calls land in MethodCall / StaticCall / Variable nodes
		// and are NOT routed here, so this case is unambiguous.
		fn := renderName(n.Function)
		if fn == "" {
			break
		}
		// The bare name we compare against is the last segment after `.` (the
		// dotted render of the namespace path). `\md5(...)` and `md5(...)`
		// match the same rule.
		simple := lastSegment(fn)
		for _, rq := range v.rqs {
			if rq.query.kind != queryCall {
				continue
			}
			if rq.query.name != simple && rq.query.name != fn {
				continue
			}
			v.appendMatch(rq.rule, n.Position)
		}

	case *expr.MethodCall:
		// $obj->method(...) — the receiver is a *expr.Variable wrapping a
		// *node.Identifier whose Value is the variable name (without the `$`).
		// We match against that variable name so rule authors can write a
		// query like `method:rsa.encrypt` and have it match `$rsa->encrypt()`
		// regardless of full type. This is intentionally syntactic — true
		// type resolution would require building a symbol table.
		recv := variableName(n.Variable)
		methodName := identifierValue(n.Method)
		if methodName == "" {
			break
		}
		for _, rq := range v.rqs {
			if rq.query.kind != queryMethod {
				continue
			}
			if rq.query.method != methodName {
				continue
			}
			if rq.query.name != recv {
				continue
			}
			v.appendMatch(rq.rule, n.Position)
		}

	case *expr.StaticCall:
		// Class::method(...) — n.Class is a *name.Name (or FullyQualified). We
		// route the SAME `method:` queries here so the rule author can pick
		// either the dynamic OR the static form using one query.
		clsRendered := renderName(n.Class)
		clsSimple := lastSegment(clsRendered)
		methodName := identifierValue(n.Call)
		if methodName == "" {
			break
		}
		for _, rq := range v.rqs {
			if rq.query.kind != queryMethod {
				continue
			}
			if rq.query.method != methodName {
				continue
			}
			if classNameMatches(rq.query.name, clsRendered, clsSimple) {
				v.appendMatch(rq.rule, n.Position)
			}
		}

	case *expr.New:
		// new Class(...) — n.Class is a *name.Name or *name.FullyQualified for
		// the common static-class case. (Dynamic `new $cls(...)` would put a
		// Variable here; we ignore that — there's no class name to match.)
		clsRendered := renderName(n.Class)
		if clsRendered == "" {
			break
		}
		clsSimple := lastSegment(clsRendered)
		for _, rq := range v.rqs {
			if rq.query.kind != queryNew {
				continue
			}
			if classNameMatches(rq.query.name, clsRendered, clsSimple) {
				v.appendMatch(rq.rule, n.Position)
			}
		}

	case *stmt.UseList:
		// `use Foo\Bar; use Foo\Baz as X;` parses as a single UseList whose
		// Uses slice holds one *stmt.Use per declaration. We process the list
		// here directly; further descent would re-encounter the same Use
		// children without additional context.
		for _, u := range n.Uses {
			use, ok := u.(*stmt.Use)
			if !ok {
				continue
			}
			usePath := renderName(use.Use)
			if usePath == "" {
				continue
			}
			for _, rq := range v.rqs {
				if rq.query.kind != queryUse {
					continue
				}
				if useMatches(rq.query, usePath) {
					v.appendMatch(rq.rule, use.Position)
				}
			}
		}

	case *stmt.GroupUse:
		// `use Foo\{Bar, Baz};` — prefix + a list of Uses each contributing a
		// trailing segment. We synthesize the full path per inner use.
		prefix := renderName(n.Prefix)
		for _, u := range n.UseList {
			use, ok := u.(*stmt.Use)
			if !ok {
				continue
			}
			tail := renderName(use.Use)
			full := prefix
			if full != "" && tail != "" {
				full = full + "." + tail
			} else if tail != "" {
				full = tail
			}
			if full == "" {
				continue
			}
			for _, rq := range v.rqs {
				if rq.query.kind != queryUse {
					continue
				}
				if useMatches(rq.query, full) {
					v.appendMatch(rq.rule, use.Position)
				}
			}
		}

	case *expr.ConstFetch:
		// Bare constant reference: `OPENSSL_KEYTYPE_RSA`, `MCRYPT_DES`, etc.
		// n.Constant is a *name.Name; the simple identifier is the last part.
		constName := renderName(n.Constant)
		if constName == "" {
			break
		}
		simple := lastSegment(constName)
		for _, rq := range v.rqs {
			if rq.query.kind != queryConst {
				continue
			}
			if rq.query.name != simple && rq.query.name != constName {
				continue
			}
			v.appendMatch(rq.rule, n.Position)
		}
	}
	return true
}

// LeaveNode / EnterChildNode / LeaveChildNode / EnterChildList /
// LeaveChildList are no-ops — we only need the pre-order EnterNode callback.
func (v *visitor) LeaveNode(w walker.Walkable)                  {}
func (v *visitor) EnterChildNode(key string, w walker.Walkable) {}
func (v *visitor) LeaveChildNode(key string, w walker.Walkable) {}
func (v *visitor) EnterChildList(key string, w walker.Walkable) {}
func (v *visitor) LeaveChildList(key string, w walker.Walkable) {}

// renderName returns the dotted form of a *name.Name / *name.FullyQualified
// node, or the textual value of a *node.Identifier. Returns "" if the node
// isn't one of those two shapes (e.g. a dynamic class expression).
func renderName(n node.Node) string {
	switch v := n.(type) {
	case *name.Name:
		return joinNameParts(v.Parts)
	case *name.FullyQualified:
		return joinNameParts(v.Parts)
	case *name.Relative:
		return joinNameParts(v.Parts)
	case *node.Identifier:
		return v.Value
	}
	return ""
}

// joinNameParts concatenates the Value of every *name.NamePart in the slice
// with "." separators. The PHP namespace separator is "\" but we render with
// "." so rule queries read the same as Java/Python/etc. ("use:phpseclib3.Crypt.RSA").
func joinNameParts(parts []node.Node) string {
	out := ""
	for _, p := range parts {
		np, ok := p.(*name.NamePart)
		if !ok {
			continue
		}
		if out == "" {
			out = np.Value
		} else {
			out = out + "." + np.Value
		}
	}
	return out
}

// lastSegment returns the substring after the final "." separator, or the
// whole string when none is present. Used to lift `\Foo\Bar\Baz` to `Baz` for
// short-form rule matching.
func lastSegment(dotted string) string {
	if i := strings.LastIndexByte(dotted, '.'); i >= 0 {
		return dotted[i+1:]
	}
	return dotted
}

// classNameMatches decides whether a rule-side class identifier matches the
// AST-side rendered class name. Rules MAY be written as the simple identifier
// (`RSA`) — in which case any source-side class whose final segment is `RSA`
// matches — OR as the fully-qualified dotted form (`phpseclib3.Crypt.RSA`),
// in which case we require an exact match on the full rendered name.
func classNameMatches(rulePath, fullyRendered, lastPart string) bool {
	if strings.ContainsRune(rulePath, '.') {
		return rulePath == fullyRendered
	}
	return rulePath == lastPart
}

// useMatches decides whether a rule-side use query matches a source-side
// `use ...;` path. Wildcard rules (`Foo.Bar.*`) match any path whose prefix
// is `Foo.Bar`. Non-wildcard rules require an exact match.
func useMatches(q *parsedQuery, usePath string) bool {
	if q.wildcard {
		prefix := q.wildcardPrefix
		return usePath == prefix || strings.HasPrefix(usePath, prefix+".")
	}
	return q.path == usePath
}

// variableName extracts the bare name of a `$var` expression. Returns "" if
// the node isn't a *expr.Variable wrapping a *node.Identifier (which covers
// the dynamic / nested-variable cases the rule DSL doesn't support).
func variableName(n node.Node) string {
	v, ok := n.(*expr.Variable)
	if !ok {
		return ""
	}
	id, ok := v.VarName.(*node.Identifier)
	if !ok {
		return ""
	}
	return id.Value
}

// identifierValue returns the Value of a *node.Identifier or "" otherwise.
func identifierValue(n node.Node) string {
	id, ok := n.(*node.Identifier)
	if !ok {
		return ""
	}
	return id.Value
}

// appendMatch records a finding at the given position, adjusting line numbers
// to compensate for the `<?php\n` prefix we may have prepended.
func (v *visitor) appendMatch(rule *rules.Rule, pos *position.Position) {
	line := 1
	col := 1
	if pos != nil {
		line = pos.StartLine - v.linesAdded
		if line < 1 {
			line = 1
		}
	}
	v.matches = append(v.matches, astdet.Match{
		Rule:    rule,
		Line:    line,
		Column:  col,
		Snippet: lineAt(v.origLines, line),
		Context: contextOf(v.origLines, line),
	})
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
