// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.AI.BYOK;

public sealed class AnthropicOptions
{
    public const string SectionName = "Llm:Anthropic";
    public const string ApiKeyEnvVar = "ANTHROPIC_API_KEY";

    public string BaseUrl { get; set; } = "https://api.anthropic.com/v1";
    public string AnthropicVersion { get; set; } = "2023-06-01";

    /// <summary>
    /// API key. Optional here — at construction time the provider falls back
    /// to the <c>ANTHROPIC_API_KEY</c> environment variable via
    /// <see cref="EnvKeyResolver"/>.
    /// </summary>
    public string? ApiKey { get; set; }

    public double Temperature { get; set; } = 0.1;

    /// <summary>
    /// Tier -> model id. Defaults map small=haiku, large=sonnet. Override per
    /// deployment if you want opus on "large", or a pinned dated variant.
    /// </summary>
    public Dictionary<string, string> Models { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["small"] = "claude-haiku-4-5-20251001",
        ["large"] = "claude-sonnet-4-6",
    };
}
