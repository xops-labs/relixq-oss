// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using System.Text.Json.Serialization;

namespace Relixq.Roslyn;

internal sealed class Request
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("filePath")] public string FilePath { get; set; } = "";
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("rules")] public List<RuleQuery> Rules { get; set; } = new();
}

internal sealed class RuleQuery
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("query")] public string Query { get; set; } = "";
}

internal sealed class Response
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("matches")] public List<MatchOut>? Matches { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

internal sealed class MatchOut
{
    [JsonPropertyName("ruleId")] public string RuleId { get; set; } = "";
    [JsonPropertyName("line")] public int Line { get; set; }
    [JsonPropertyName("column")] public int Column { get; set; }
    [JsonPropertyName("snippet")] public string Snippet { get; set; } = "";
    [JsonPropertyName("context")] public List<string> Context { get; set; } = new();
}
