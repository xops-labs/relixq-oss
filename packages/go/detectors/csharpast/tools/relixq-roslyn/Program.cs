// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
using System.Text;
using System.Text.Json;
using Relixq.Roslyn;

// JSONL loop over stdin/stdout. One Request per line in, one Response per line
// out. EOF on stdin → clean exit. Designed to be long-running across a single
// scan run so we amortize JIT startup over many files (AST runner).

Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = Encoding.UTF8;

var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
var stdin = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8);

var jsonOpts = new JsonSerializerOptions
{
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
};

while (true)
{
    var line = await stdin.ReadLineAsync().ConfigureAwait(false);
    if (line is null) break;
    if (line.Length == 0) continue;

    Response resp;
    try
    {
        var req = JsonSerializer.Deserialize<Request>(line, jsonOpts)
                   ?? throw new InvalidOperationException("null request");
        var matches = CSharpAstMatcher.Run(req.FilePath, req.Source, req.Rules);
        resp = new Response { Id = req.Id, Matches = matches };
    }
    catch (Exception ex)
    {
        // Pull the id back out so the client can correlate the error.
        string id = "";
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.TryGetProperty("id", out var idEl))
                id = idEl.GetString() ?? "";
        }
        catch
        {
        }
        resp = new Response { Id = id, Error = ex.Message };
    }

    var outLine = JsonSerializer.Serialize(resp, jsonOpts);
    await stdout.WriteLineAsync(outLine).ConfigureAwait(false);
}
