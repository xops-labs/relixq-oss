// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Relixq.Roslyn;

/// <summary>
/// Query DSL forms (one per detector.query in the rule YAML):
///   call:&lt;Type&gt;.&lt;Method&gt;       — Type.Method(...) invocations
///   new:&lt;Type&gt;                  — new Type(...) constructor calls
///   using:&lt;Namespace&gt;           — using Namespace; directives
///   memberref:&lt;Type&gt;.&lt;Member&gt;   — Type.Member member-access expressions
///                                  (e.g. SslProtocols.Tls11, CipherMode.ECB)
/// </summary>
internal enum QueryKind
{
    Call,
    New,
    Using,
    MemberRef,
}

internal sealed class ParsedQuery
{
    public QueryKind Kind { get; init; }
    public string Type { get; init; } = "";    // for call, new, memberref
    public string Member { get; init; } = "";  // for call, memberref
    public string Namespace { get; init; } = ""; // for using
}

internal static class QueryParser
{
    public static ParsedQuery Parse(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            throw new FormatException("query empty");

        var idx = query.IndexOf(':');
        if (idx < 0)
            throw new FormatException(
                $"query \"{query}\": missing kind prefix (call:|new:|using:|memberref:)");

        var kind = query[..idx];
        var rest = query[(idx + 1)..].Trim();

        switch (kind)
        {
            case "call":
            case "memberref":
                var dot = rest.LastIndexOf('.');
                if (dot < 0)
                    throw new FormatException($"query \"{query}\": expected Type.Member form");
                return new ParsedQuery
                {
                    Kind = kind == "call" ? QueryKind.Call : QueryKind.MemberRef,
                    Type = rest[..dot],
                    Member = rest[(dot + 1)..],
                };
            case "new":
                return new ParsedQuery { Kind = QueryKind.New, Type = rest };
            case "using":
                return new ParsedQuery { Kind = QueryKind.Using, Namespace = rest };
            default:
                throw new FormatException(
                    $"query \"{query}\": unknown kind \"{kind}\" (want call|new|using|memberref)");
        }
    }
}

internal sealed class RuleMatcher
{
    public required string RuleId { get; init; }
    public required ParsedQuery Query { get; init; }
}

internal sealed class CSharpAstMatcher
{
    private readonly string[] _lines;
    private readonly List<MatchOut> _matches = new();

    private CSharpAstMatcher(string source)
    {
        _lines = source.Split('\n');
        for (var i = 0; i < _lines.Length; i++)
            _lines[i] = _lines[i].TrimEnd('\r');
    }

    public static List<MatchOut> Run(string filePath, string source, List<RuleQuery> rules)
    {
        var compiled = new List<RuleMatcher>(rules.Count);
        foreach (var r in rules)
        {
            ParsedQuery pq;
            try { pq = QueryParser.Parse(r.Query); }
            catch { continue; }
            compiled.Add(new RuleMatcher { RuleId = r.Id, Query = pq });
        }
        if (compiled.Count == 0)
            return new List<MatchOut>();

        var tree = CSharpSyntaxTree.ParseText(source, path: filePath);
        var root = tree.GetRoot();

        var m = new CSharpAstMatcher(source);
        m.Walk(root, compiled);
        return m._matches;
    }

    private void Walk(SyntaxNode root, List<RuleMatcher> rules)
    {
        // Group rules by kind for cheap dispatch.
        var calls = rules.Where(r => r.Query.Kind == QueryKind.Call).ToList();
        var news = rules.Where(r => r.Query.Kind == QueryKind.New).ToList();
        var usings = rules.Where(r => r.Query.Kind == QueryKind.Using).ToList();
        var members = rules.Where(r => r.Query.Kind == QueryKind.MemberRef).ToList();

        foreach (var node in root.DescendantNodesAndSelf())
        {
            switch (node)
            {
                case InvocationExpressionSyntax inv when calls.Count > 0:
                    HandleInvocation(inv, calls);
                    break;
                case ObjectCreationExpressionSyntax oce when news.Count > 0:
                    HandleObjectCreation(oce, news);
                    break;
                case UsingDirectiveSyntax ud when usings.Count > 0:
                    HandleUsing(ud, usings);
                    break;
                case MemberAccessExpressionSyntax ma when members.Count > 0:
                    HandleMemberRef(ma, members);
                    break;
            }
        }
    }

    private void HandleInvocation(InvocationExpressionSyntax inv, List<RuleMatcher> calls)
    {
        // Match Type.Method(...) and instance.Method(...) where the receiver
        // identifier matches the rule's Type. Roslyn semantic model would let us
        // resolve instance types precisely but that needs MetadataReferences;
        // for v1, syntax-level match by identifier name keeps the subprocess
        // self-contained. This is still strictly better than regex because we
        // anchor to a SyntaxKind, not a text pattern.
        if (inv.Expression is not MemberAccessExpressionSyntax ma)
            return;
        var typeIdent = NameOf(ma.Expression);
        var methodName = ma.Name.Identifier.Text;
        if (typeIdent is null)
            return;

        foreach (var r in calls)
        {
            if (r.Query.Type != typeIdent || r.Query.Member != methodName)
                continue;
            Emit(r.RuleId, inv.GetLocation());
        }
    }

    private void HandleObjectCreation(ObjectCreationExpressionSyntax oce, List<RuleMatcher> news)
    {
        var typeIdent = NameOf(oce.Type);
        if (typeIdent is null)
            return;
        foreach (var r in news)
        {
            if (r.Query.Type != typeIdent)
                continue;
            Emit(r.RuleId, oce.GetLocation());
        }
    }

    private void HandleUsing(UsingDirectiveSyntax ud, List<RuleMatcher> usings)
    {
        if (ud.Name is null) return;
        var ns = ud.Name.ToString();
        foreach (var r in usings)
        {
            if (r.Query.Namespace != ns)
                continue;
            Emit(r.RuleId, ud.GetLocation());
        }
    }

    private void HandleMemberRef(MemberAccessExpressionSyntax ma, List<RuleMatcher> members)
    {
        // Skip member-access nodes that are the callee of an invocation — those
        // are handled by HandleInvocation. Without this guard, `RSA.Create(...)`
        // would match both call:RSA.Create AND memberref:RSA.Create.
        if (ma.Parent is InvocationExpressionSyntax)
            return;
        var typeIdent = NameOf(ma.Expression);
        var memberName = ma.Name.Identifier.Text;
        if (typeIdent is null)
            return;
        foreach (var r in members)
        {
            if (r.Query.Type != typeIdent || r.Query.Member != memberName)
                continue;
            Emit(r.RuleId, ma.GetLocation());
        }
    }

    private static string? NameOf(SyntaxNode node) => node switch
    {
        IdentifierNameSyntax ins => ins.Identifier.Text,
        // qualified names like System.Security.Cryptography.RSA reduce to the
        // rightmost identifier for matching (rules name the type, not the FQN).
        QualifiedNameSyntax qns => qns.Right.Identifier.Text,
        _ => null,
    };

    private const int ContextLines = 3;

    private void Emit(string ruleId, Location loc)
    {
        var ls = loc.GetLineSpan().StartLinePosition;
        var line = ls.Line + 1;   // Roslyn is 0-based; rules use 1-based.
        var col = ls.Character + 1;
        _matches.Add(new MatchOut
        {
            RuleId = ruleId,
            Line = line,
            Column = col,
            Snippet = LineAt(line),
            Context = ContextOf(line),
        });
    }

    private string LineAt(int lineNo)
    {
        if (lineNo < 1 || lineNo > _lines.Length) return "";
        return _lines[lineNo - 1];
    }

    private List<string> ContextOf(int lineNo)
    {
        var start = Math.Max(0, lineNo - 1 - ContextLines);
        var end = Math.Min(_lines.Length, lineNo - 1 + ContextLines + 1);
        var ctx = new List<string>(end - start);
        for (var i = start; i < end; i++)
            ctx.Add(_lines[i]);
        return ctx;
    }
}
