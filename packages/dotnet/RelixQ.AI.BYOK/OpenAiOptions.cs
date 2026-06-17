// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.AI.BYOK;

public sealed class OpenAiOptions
{
    public const string SectionName = "Llm:OpenAi";
    public const string ApiKeyEnvVar = "OPENAI_API_KEY";

    public string BaseUrl { get; set; } = "https://api.openai.com/v1";

    /// <summary>
    /// API key. Optional here — at construction time the provider falls back to
    /// the <c>OPENAI_API_KEY</c> environment variable via <see cref="EnvKeyResolver"/>.
    /// </summary>
    public string? ApiKey { get; set; }

    public string? OrganizationId { get; set; }
    public string? Project { get; set; }
    public double Temperature { get; set; } = 0.1;

    /// <summary>Tier -> model name. Defaults shipped match GPT-4o-mini / GPT-4o.</summary>
    public Dictionary<string, string> Models { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["small"] = "gpt-4o-mini",
        ["large"] = "gpt-4o",
    };
}
