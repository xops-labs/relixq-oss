// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package jstsast implements an in-process AST runner for JavaScript and
// TypeScript using github.com/dop251/goja/parser (pure Go, no Node.js
// runtime). Source is pre-processed with github.com/evanw/esbuild so:
//
//   - TypeScript-specific syntax (type annotations, interfaces, enums, `as`
//     casts, generics) is stripped — goja itself only understands ECMAScript.
//   - ES-module `import`/`export` declarations are lowered to CommonJS
//     `require`/`module.exports` calls — goja's parser does not implement
//     ESM module syntax.
//
// Line/column positions in match output are remapped back to the ORIGINAL
// source using the source map esbuild emits, so findings always point at the
// user's code, not the transformed JS.
//
// Query format (detector.query in the rule YAML):
//
//	call:<obj>.<method>      — matches obj.method(...) call expressions
//	new:<Class>              — matches new Class(...) constructor calls
//	import:<module>          — matches `import ... from 'module'`, bare
//	                            `import 'module'`, or require('module')
//	memberref:<obj>.<member> — matches obj.member NOT in call position
//
// The same *runner is registered for both "javascript" and "typescript";
// the file extension on Run's filePath argument decides whether to invoke
// the TS loader path (Loader=TS) vs JS loader path (Loader=JS).
package jstsast

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	gjast "github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	esbuild "github.com/evanw/esbuild/pkg/api"
	"github.com/go-sourcemap/sourcemap"

	astdet "github.com/relix-q/relix-q/detectors/ast"
	"github.com/relix-q/relix-q/rules"
)

func init() {
	r := &runner{}
	astdet.Register("javascript", r)
	astdet.Register("typescript", r)
}

type runner struct{}

// queryKind is the discriminated union for the supported query forms.
type queryKind int

const (
	queryCall queryKind = iota
	queryNew
	queryImport
	queryMemberRef
)

type parsedQuery struct {
	kind queryKind
	// For call / memberref:
	obj    string
	member string
	// For new:
	class string
	// For import:
	path string
}

func parseQuery(q string) (*parsedQuery, error) {
	idx := strings.IndexByte(q, ':')
	if idx < 0 {
		return nil, fmt.Errorf("jstsast query %q: missing kind prefix", q)
	}
	kind := q[:idx]
	rest := q[idx+1:]
	switch kind {
	case "call", "memberref":
		dot := strings.LastIndexByte(rest, '.')
		if dot < 0 {
			return nil, fmt.Errorf("jstsast query %q: expected obj.member form", q)
		}
		k := queryCall
		if kind == "memberref" {
			k = queryMemberRef
		}
		return &parsedQuery{kind: k, obj: rest[:dot], member: rest[dot+1:]}, nil
	case "new":
		return &parsedQuery{kind: queryNew, class: rest}, nil
	case "import":
		return &parsedQuery{kind: queryImport, path: rest}, nil
	default:
		return nil, fmt.Errorf("jstsast query %q: unknown kind %q", q, kind)
	}
}

// loaderFor picks the right esbuild Loader for the given file extension.
func loaderFor(filePath string) esbuild.Loader {
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".ts", ".cts", ".mts":
		return esbuild.LoaderTS
	case ".tsx":
		return esbuild.LoaderTSX
	case ".jsx":
		return esbuild.LoaderJSX
	default:
		return esbuild.LoaderJS
	}
}

// transformResult holds the post-transform JS plus a (line, col) remapper.
type transformResult struct {
	js []byte
	// remap converts a 1-based (line, col) in the transformed JS back to the
	// 1-based (line, col) in the original source.
	remap func(line, col int) (int, int)
}

// transformSource runs esbuild Transform to strip TypeScript-only syntax
// (type annotations, interfaces, enums, generics) and emit ECMAScript that
// goja can parse. Imports and exports are kept in ES-module form so the
// scanner's `new:` and `call:` detectors see the user's original identifier
// names (esbuild's FormatCommonJS would rewrite `NodeRSA` to
// `import_node_rsa.default`, defeating the detector). `import` declarations
// are stripped later by stripImportLines before the source reaches goja —
// goja's parser does not implement ESM module syntax.
//
// The returned remap function maps transformed positions back to original
// positions via esbuild's emitted source map.
func transformSource(filePath string, source []byte) (*transformResult, error) {
	result := esbuild.Transform(string(source), esbuild.TransformOptions{
		Loader:    loaderFor(filePath),
		Format:    esbuild.FormatDefault,
		Target:    esbuild.ES2020,
		Sourcemap: esbuild.SourceMapExternal,
		// Disable tree-shaking so unused identifiers and constructions are
		// NOT dropped — the scanner needs to see every crypto API call even
		// in code paths that look dead to the optimizer.
		TreeShaking: esbuild.TreeShakingFalse,
		// Keep original function/class names so debug-style `.name` is
		// preserved. Identifier bindings themselves are already preserved
		// when Format is left as the default.
		KeepNames:  true,
		Sourcefile: filepath.Base(filePath),
	})
	if len(result.Errors) > 0 {
		var msgs []string
		for _, e := range result.Errors {
			msgs = append(msgs, e.Text)
		}
		return nil, fmt.Errorf("esbuild transform failed: %s", strings.Join(msgs, "; "))
	}

	// Build remapper from the source map.
	var smap *sourcemap.Consumer
	if len(result.Map) > 0 {
		if s, err := sourcemap.Parse(filePath, result.Map); err == nil {
			smap = s
		}
	}

	remap := func(line, col int) (int, int) {
		if smap == nil {
			return line, col
		}
		_, _, origLine, origCol, ok := smap.Source(line, col)
		if !ok || origLine <= 0 {
			return line, col
		}
		return origLine, origCol
	}

	return &transformResult{js: result.Code, remap: remap}, nil
}

// stripImportLines replaces every line that starts an `import` or `export`
// declaration with whitespace of the same length so subsequent line numbers
// in the transformed JS stay aligned with the pre-strip JS. goja's parser
// rejects ESM syntax, so we hide it from goja while keeping every other
// statement intact.
//
// The regex is intentionally simple: it targets lines that BEGIN (after
// optional whitespace) with `import` or `export`. Multi-line import
// statements are handled by continuing to strip until a terminating
// semicolon or backtick-less close is detected on a subsequent line.
func stripImportLines(src []byte) []byte {
	lines := splitLines(src)
	out := make([][]byte, len(lines))
	inImport := false
	for i, line := range lines {
		ls := string(line)
		trimmed := strings.TrimLeft(ls, " \t")
		switch {
		case inImport:
			// Continue blanking until a line terminates the import.
			if strings.Contains(ls, ";") || strings.HasSuffix(strings.TrimRight(ls, " \t"), ")") {
				inImport = false
			}
			out[i] = blankLine(line)
		case importStartRe.MatchString(trimmed):
			// Multi-line import? Detect a terminator on the same line.
			if !strings.Contains(ls, ";") && !endsImportInline(ls) {
				inImport = true
			}
			out[i] = blankLine(line)
		default:
			out[i] = line
		}
	}
	return joinLines(out)
}

var importStartRe = regexp.MustCompile(`^(import|export)\b`)

// endsImportInline returns true if an import/export line clearly ends on
// the same line (matched braces and parens). Conservative: if unsure, the
// caller assumes multi-line and continues blanking.
func endsImportInline(line string) bool {
	// A line that opens `{` without closing `}` is multi-line.
	if strings.Count(line, "{") > strings.Count(line, "}") {
		return false
	}
	// A line that opens `(` without closing `)` (e.g. dynamic import) is
	// multi-line.
	if strings.Count(line, "(") > strings.Count(line, ")") {
		return false
	}
	return true
}

func blankLine(line []byte) []byte {
	b := make([]byte, len(line))
	for i := range b {
		b[i] = ' '
	}
	return b
}

func splitLines(src []byte) [][]byte {
	// Preserve trailing empty line semantics so joinLines is exact.
	var out [][]byte
	start := 0
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			out = append(out, src[start:i])
			start = i + 1
		}
	}
	out = append(out, src[start:])
	return out
}

func joinLines(lines [][]byte) []byte {
	var total int
	for _, l := range lines {
		total += len(l) + 1
	}
	out := make([]byte, 0, total)
	for i, l := range lines {
		out = append(out, l...)
		if i < len(lines)-1 {
			out = append(out, '\n')
		}
	}
	return out
}

// importScanRegexes is the set of patterns we use to detect import/require
// declarations directly in the ORIGINAL source. Goja cannot parse ESM
// `import` declarations, and even `require('mod')` calls in the transformed
// source may have been rewritten, so the most reliable place to detect them
// is the original. Each regex captures:
//
//	group 1 — the module specifier (string literal contents, no quotes)
//
// The line number of the match is taken from the byte offset of the regex
// hit in the original source.
var importScanRegexes = []*regexp.Regexp{
	// ES module: `import ... from 'X'`
	regexp.MustCompile(`(?m)^\s*import\s+(?:[^'"\n;]*?\s+from\s+)?['"]([^'"\n]+)['"]`),
	// CommonJS: `require('X')` anywhere on a line.
	regexp.MustCompile(`require\s*\(\s*['"]([^'"\n]+)['"]\s*\)`),
}

// scanImports returns a slice of (module, line) tuples found in source.
// Line numbers are 1-based and reflect the ORIGINAL source.
func scanImports(source []byte) []importHit {
	var hits []importHit
	for _, re := range importScanRegexes {
		for _, m := range re.FindAllSubmatchIndex(source, -1) {
			if len(m) < 4 {
				continue
			}
			modStart, modEnd := m[2], m[3]
			module := string(source[modStart:modEnd])
			// Line of the match start.
			line := byteOffsetToLine(source, m[0])
			hits = append(hits, importHit{module: module, line: line, col: 1})
		}
	}
	return hits
}

type importHit struct {
	module string
	line   int
	col    int
}

// byteOffsetToLine returns the 1-based line number of byte offset off in src.
func byteOffsetToLine(src []byte, off int) int {
	if off <= 0 {
		return 1
	}
	if off > len(src) {
		off = len(src)
	}
	line := 1
	for i := 0; i < off; i++ {
		if src[i] == '\n' {
			line++
		}
	}
	return line
}

// Run parses source as JS (after esbuild normalization) and returns matches
// for the applicable AST rules. Regex rules are ignored. Empty or unparseable
// source returns (nil, nil) gracefully.
func (r *runner) Run(filePath string, source []byte, applicable []*rules.Rule) ([]astdet.Match, error) {
	// Pre-compile queries for applicable AST rules.
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
			// Bad query: skip this rule rather than aborting the whole file.
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

	tr, err := transformSource(filePath, source)
	if err != nil {
		// Graceful: a transform error on user code means we cannot run AST
		// rules for this file. Caller falls back to regex matches only.
		return nil, nil
	}

	// Strip ESM `import`/`export` lines from the transformed JS so goja's
	// non-ESM parser accepts the source. Blanked lines preserve line counts
	// so the post-strip code still aligns with the esbuild source map.
	bodyJS := stripImportLines(tr.js)

	prog, err := parser.ParseFile(nil, filePath, string(bodyJS), 0)
	if err != nil || prog == nil {
		return nil, nil
	}

	// Pre-split the ORIGINAL source for snippet extraction.
	origLines := strings.Split(string(source), "\n")

	var matches []astdet.Match

	// Phase 1 — import detection on the ORIGINAL source. We can't rely on
	// the transformed AST for this because esbuild keeps imports in ESM
	// form (which goja drops) and require() calls may have been rewritten.
	for _, rq := range rqs {
		if rq.query.kind != queryImport {
			continue
		}
		for _, hit := range scanImports(source) {
			if hit.module != rq.query.path {
				continue
			}
			matches = appendMatch(matches, rq.rule, hit.line, hit.col, origLines)
		}
	}

	// Track DotExpressions used as call callees so the memberref pass below
	// does not double-fire on them. This must be a SECOND walk because we
	// need full traversal before we know which dot-expressions are calls.
	calleeDots := map[*gjast.DotExpression]struct{}{}
	walk(prog, func(n gjast.Node) {
		call, ok := n.(*gjast.CallExpression)
		if !ok {
			return
		}
		if dot, ok := call.Callee.(*gjast.DotExpression); ok {
			calleeDots[dot] = struct{}{}
		}
	})

	pos := func(idx file.Idx) (int, int) {
		// prog.File.Position takes the absolute offset; file.Idx is 1-based.
		p := prog.File.Position(int(idx))
		origLine, origCol := tr.remap(p.Line, p.Column)
		return origLine, origCol
	}

	walk(prog, func(n gjast.Node) {
		switch node := n.(type) {

		case *gjast.CallExpression:
			// obj.method(...) — match queryCall. require('module') is
			// handled by Phase 1 (text scan on the original source).
			c, ok := node.Callee.(*gjast.DotExpression)
			if !ok {
				return
			}
			objName, ok := identifierName(c.Left)
			if !ok {
				return
			}
			memberName := string(c.Identifier.Name)
			for _, rq := range rqs {
				if rq.query.kind != queryCall {
					continue
				}
				if objName != rq.query.obj || memberName != rq.query.member {
					continue
				}
				line, col := pos(node.Idx0())
				matches = appendMatch(matches, rq.rule, line, col, origLines)
			}

		case *gjast.NewExpression:
			className, ok := identifierName(node.Callee)
			if !ok {
				return
			}
			for _, rq := range rqs {
				if rq.query.kind != queryNew {
					continue
				}
				if className != rq.query.class {
					continue
				}
				line, col := pos(node.Idx0())
				matches = appendMatch(matches, rq.rule, line, col, origLines)
			}

		case *gjast.DotExpression:
			// memberref: only match standalone dot-expressions (not call
			// callees). Calls are already handled above.
			if _, isCallee := calleeDots[node]; isCallee {
				return
			}
			objName, ok := identifierName(node.Left)
			if !ok {
				return
			}
			memberName := string(node.Identifier.Name)
			for _, rq := range rqs {
				if rq.query.kind != queryMemberRef {
					continue
				}
				if objName != rq.query.obj || memberName != rq.query.member {
					continue
				}
				line, col := pos(node.Idx0())
				matches = appendMatch(matches, rq.rule, line, col, origLines)
			}
		}
	})

	return matches, nil
}

func appendMatch(matches []astdet.Match, rule *rules.Rule, line, col int, lines []string) []astdet.Match {
	return append(matches, astdet.Match{
		Rule:    rule,
		Line:    line,
		Column:  col,
		Snippet: lineAt(lines, line),
		Context: contextOf(lines, line),
	})
}

// identifierName extracts the textual name of an identifier expression.
// Returns false if the expression is not a plain identifier.
func identifierName(e gjast.Expression) (string, bool) {
	switch v := e.(type) {
	case *gjast.Identifier:
		return string(v.Name), true
	}
	return "", false
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
