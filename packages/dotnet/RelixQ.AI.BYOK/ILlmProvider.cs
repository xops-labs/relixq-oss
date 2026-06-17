// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.AI.BYOK;

/// <summary>
/// Single LLM provider adapter. Implementations carve into two camps:
///   BYOK:   <c>OpenAiProvider</c>, <c>AnthropicProvider</c>
///   Hosted: <c>AzureOpenAiProvider</c>, <c>BedrockProvider</c>, <c>VertexProvider</c>
/// Adding a new provider is plug-in: implement this interface and register it
/// with the router.
/// </summary>
public interface ILlmProvider
{
    LlmProviderKind Kind { get; }
    string Name { get; }
    bool SupportsTier(string modelTier);

    Task<LlmResult> CompleteJsonAsync(LlmRequest request, CancellationToken ct);
}

public sealed record LlmRequest
{
    public required string SystemMessage { get; init; }
    public required string UserMessage { get; init; }
    public required string ModelTier { get; init; }
    public required int MaxOutputTokens { get; init; }

    /// <summary>Hint to the provider that the response must be a JSON object.</summary>
    public bool EnforceJsonMode { get; init; } = true;
}

public sealed record LlmResult
{
    public required string Json { get; init; }
    public required string Model { get; init; }
    public required int InputTokens { get; init; }
    public required int OutputTokens { get; init; }
    public required decimal CostUsd { get; init; }
}

public sealed class LlmProviderUnavailableException : Exception
{
    public LlmProviderUnavailableException(string providerName, Exception? inner = null)
        : base($"LLM provider '{providerName}' is unavailable", inner)
    {
        ProviderName = providerName;
    }

    public string ProviderName { get; }
}
