// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package jstsast

import (
	"reflect"

	gjast "github.com/dop251/goja/ast"
)

// walk performs a pre-order traversal of a goja AST and calls visit on every
// node. The goja/ast package does not ship a Walk helper, so we provide one
// scoped to the node types the detector queries care about. Unknown node
// kinds are skipped — adding a new query kind that targets a new node type
// requires adding the corresponding case below.
func walk(n gjast.Node, visit func(gjast.Node)) {
	if n == nil {
		return
	}
	// goja's AST stores some optional children as concrete pointer types
	// (e.g. TryStatement.Finally is *BlockStatement, nil when absent). Passed
	// through the gjast.Node interface parameter they become typed nils that
	// the n == nil check above cannot catch, and the type switch below would
	// dereference them. Guard with reflection so every optional child is safe.
	if v := reflect.ValueOf(n); v.Kind() == reflect.Pointer && v.IsNil() {
		return
	}
	visit(n)

	switch v := n.(type) {

	case *gjast.Program:
		for _, s := range v.Body {
			walk(s, visit)
		}

	// --- Statements ---

	case *gjast.BlockStatement:
		for _, s := range v.List {
			walk(s, visit)
		}
	case *gjast.ExpressionStatement:
		walk(v.Expression, visit)
	case *gjast.IfStatement:
		walk(v.Test, visit)
		walk(v.Consequent, visit)
		walk(v.Alternate, visit)
	case *gjast.ReturnStatement:
		walk(v.Argument, visit)
	case *gjast.SwitchStatement:
		walk(v.Discriminant, visit)
		for _, c := range v.Body {
			walk(c, visit)
		}
	case *gjast.CaseStatement:
		walk(v.Test, visit)
		for _, s := range v.Consequent {
			walk(s, visit)
		}
	case *gjast.ThrowStatement:
		walk(v.Argument, visit)
	case *gjast.TryStatement:
		walk(v.Body, visit)
		if v.Catch != nil {
			walk(v.Catch, visit)
		}
		if v.Finally != nil {
			walk(v.Finally, visit)
		}
	case *gjast.CatchStatement:
		walk(v.Body, visit)
	case *gjast.WhileStatement:
		walk(v.Test, visit)
		walk(v.Body, visit)
	case *gjast.DoWhileStatement:
		walk(v.Test, visit)
		walk(v.Body, visit)
	case *gjast.ForStatement:
		if v.Initializer != nil {
			walkForInit(v.Initializer, visit)
		}
		walk(v.Test, visit)
		walk(v.Update, visit)
		walk(v.Body, visit)
	case *gjast.ForInStatement:
		walkForInto(v.Into, visit)
		walk(v.Source, visit)
		walk(v.Body, visit)
	case *gjast.ForOfStatement:
		walkForInto(v.Into, visit)
		walk(v.Source, visit)
		walk(v.Body, visit)
	case *gjast.LabelledStatement:
		walk(v.Statement, visit)
	case *gjast.VariableStatement:
		for _, b := range v.List {
			walkBinding(b, visit)
		}
	case *gjast.LexicalDeclaration:
		for _, b := range v.List {
			walkBinding(b, visit)
		}
	case *gjast.FunctionDeclaration:
		if v.Function != nil {
			walk(v.Function, visit)
		}
	case *gjast.ClassDeclaration:
		if v.Class != nil {
			walk(v.Class, visit)
		}
	case *gjast.WithStatement:
		walk(v.Object, visit)
		walk(v.Body, visit)
	case *gjast.BranchStatement, *gjast.DebuggerStatement, *gjast.EmptyStatement,
		*gjast.BadStatement:
		// no children we care about

	// --- Expressions ---

	case *gjast.CallExpression:
		walk(v.Callee, visit)
		for _, a := range v.ArgumentList {
			walk(a, visit)
		}
	case *gjast.NewExpression:
		walk(v.Callee, visit)
		for _, a := range v.ArgumentList {
			walk(a, visit)
		}
	case *gjast.DotExpression:
		walk(v.Left, visit)
	case *gjast.PrivateDotExpression:
		walk(v.Left, visit)
	case *gjast.BracketExpression:
		walk(v.Left, visit)
		walk(v.Member, visit)
	case *gjast.BinaryExpression:
		walk(v.Left, visit)
		walk(v.Right, visit)
	case *gjast.UnaryExpression:
		walk(v.Operand, visit)
	case *gjast.AssignExpression:
		walk(v.Left, visit)
		walk(v.Right, visit)
	case *gjast.ConditionalExpression:
		walk(v.Test, visit)
		walk(v.Consequent, visit)
		walk(v.Alternate, visit)
	case *gjast.SequenceExpression:
		for _, e := range v.Sequence {
			walk(e, visit)
		}
	case *gjast.YieldExpression:
		walk(v.Argument, visit)
	case *gjast.AwaitExpression:
		walk(v.Argument, visit)
	case *gjast.SpreadElement:
		walk(v.Expression, visit)
	case *gjast.OptionalChain:
		walk(v.Expression, visit)
	case *gjast.Optional:
		walk(v.Expression, visit)
	case *gjast.TemplateLiteral:
		for _, e := range v.Expressions {
			walk(e, visit)
		}
		walk(v.Tag, visit)
	case *gjast.ArrayLiteral:
		for _, e := range v.Value {
			walk(e, visit)
		}
	case *gjast.ObjectLiteral:
		for _, p := range v.Value {
			walkProperty(p, visit)
		}
	case *gjast.FunctionLiteral:
		walk(v.Body, visit)
	case *gjast.ArrowFunctionLiteral:
		walk(v.Body, visit)
	case *gjast.ClassLiteral:
		walk(v.SuperClass, visit)
		for _, e := range v.Body {
			walkClassElement(e, visit)
		}
	case *gjast.ExpressionBody:
		walk(v.Expression, visit)

		// Leaf or value nodes: nothing to recurse into.
	case *gjast.Identifier, *gjast.StringLiteral, *gjast.NumberLiteral,
		*gjast.BooleanLiteral, *gjast.NullLiteral, *gjast.RegExpLiteral,
		*gjast.ThisExpression, *gjast.SuperExpression, *gjast.PrivateIdentifier,
		*gjast.MetaProperty, *gjast.BadExpression, *gjast.TemplateElement:
		// no children
	}
}

func walkBinding(b *gjast.Binding, visit func(gjast.Node)) {
	if b == nil {
		return
	}
	walkBindingTarget(b.Target, visit)
	walk(b.Initializer, visit)
}

func walkBindingTarget(t gjast.BindingTarget, visit func(gjast.Node)) {
	switch v := t.(type) {
	case *gjast.Identifier:
		walk(v, visit)
	case *gjast.ArrayPattern:
		for _, e := range v.Elements {
			walk(e, visit)
		}
		walk(v.Rest, visit)
	case *gjast.ObjectPattern:
		for _, p := range v.Properties {
			walkProperty(p, visit)
		}
		walk(v.Rest, visit)
	}
}

func walkProperty(p gjast.Property, visit func(gjast.Node)) {
	switch v := p.(type) {
	case *gjast.PropertyKeyed:
		walk(v.Key, visit)
		walk(v.Value, visit)
	case *gjast.PropertyShort:
		walk(&v.Name, visit)
		walk(v.Initializer, visit)
	case *gjast.SpreadElement:
		walk(v.Expression, visit)
	}
}

func walkClassElement(e gjast.ClassElement, visit func(gjast.Node)) {
	switch v := e.(type) {
	case *gjast.FieldDefinition:
		walk(v.Key, visit)
		walk(v.Initializer, visit)
	case *gjast.MethodDefinition:
		walk(v.Key, visit)
		if v.Body != nil {
			walk(v.Body, visit)
		}
	case *gjast.ClassStaticBlock:
		walk(v.Block, visit)
	}
}

func walkForInit(i gjast.ForLoopInitializer, visit func(gjast.Node)) {
	switch v := i.(type) {
	case *gjast.ForLoopInitializerExpression:
		walk(v.Expression, visit)
	case *gjast.ForLoopInitializerVarDeclList:
		for _, b := range v.List {
			walkBinding(b, visit)
		}
	case *gjast.ForLoopInitializerLexicalDecl:
		for _, b := range v.LexicalDeclaration.List {
			walkBinding(b, visit)
		}
	}
}

func walkForInto(i gjast.ForInto, visit func(gjast.Node)) {
	switch v := i.(type) {
	case *gjast.ForIntoVar:
		walkBinding(v.Binding, visit)
	case *gjast.ForIntoExpression:
		walk(v.Expression, visit)
	case *gjast.ForDeclaration:
		walkBindingTarget(v.Target, visit)
	}
}
