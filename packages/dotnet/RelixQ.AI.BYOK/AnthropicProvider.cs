// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace RelixQ.AI.BYOK;

/// <summary>
/// Anthropic Messages API (api.anthropic.com/v1/messages) adapter. BYOK: the
/// API key is sourced from the <c>ANTHROPIC_API_KEY</c> environment variable
/// first, with the configured <see cref="AnthropicOptions.ApiKey"/> as
/// fallback. The Messages API does not have a strict JSON mode — the system
/// prompt is augmented to ask for a single JSON object, and the response is
/// returned verbatim for the caller to validate against its expected shape.
/// </summary>
public sealed class AnthropicProvider : ILlmProvider
{
    public LlmProviderKind Kind => LlmProviderKind.Anthropic;
    public string Name => "anthropic";

    private readonly HttpClient _http;
    private readonly AnthropicOptions _options;
    private readonly ILogger<AnthropicProvider> _log;
    private readonly string? _resolvedKey;

    public AnthropicProvider(HttpClient http, AnthropicOptions options, ILogger<AnthropicProvider> log)
    {
        _http = http;
        _options = options;
        _log = log;
        _resolvedKey = EnvKeyResolver.TryResolve(AnthropicOptions.ApiKeyEnvVar, options.ApiKey);

        if (!string.IsNullOrWhiteSpace(_resolvedKey))
        {
            _http.DefaultRequestHeaders.Add("x-api-key", _resolvedKey);
            _http.DefaultRequestHeaders.Add("anthropic-version", _options.AnthropicVersion);
        }
    }

    public bool SupportsTier(string modelTier)
    {
        if (string.IsNullOrWhiteSpace(_resolvedKey)) return false;
        return _options.Models.ContainsKey(modelTier);
    }

    public async Task<LlmResult> CompleteJsonAsync(LlmRequest request, CancellationToken ct)
    {
        if (!_options.Models.TryGetValue(request.ModelTier, out var model))
            throw new LlmProviderUnavailableException(Name);

        var url = $"{_options.BaseUrl.TrimEnd('/')}/messages";

        // Anthropic Messages API: system is a top-level field; messages is the
        // alternating user/assistant turn list. We always send a single user
        // turn and (when JSON mode is requested) suffix the system prompt with
        // a strict-JSON instruction since the API has no response_format flag.
        var system = request.EnforceJsonMode
            ? request.SystemMessage + "\n\nRespond with a single JSON object and nothing else."
            : request.SystemMessage;

        var body = new MessagesRequest
        {
            Model = model,
            MaxTokens = request.MaxOutputTokens,
            Temperature = _options.Temperature,
            System = system,
            Messages =
            [
                new() { Role = "user", Content = request.UserMessage },
            ],
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body, options: SerializerOptions),
        };

        using var res = await _http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var text = await res.Content.ReadAsStringAsync(ct);
            _log.LogWarning("anthropic {Status} {Body}", (int)res.StatusCode, text);
            throw new LlmProviderUnavailableException(Name);
        }

        var parsed = await res.Content.ReadFromJsonAsync<MessagesResponse>(SerializerOptions, ct)
            ?? throw new LlmProviderUnavailableException(Name);

        // The Messages API returns a content[] of typed blocks; we use the first
        // text block. Empty / tool-only responses surface as unavailable.
        var content = parsed.Content?.FirstOrDefault(c => c.Type == "text")?.Text
            ?? throw new LlmProviderUnavailableException(Name);

        return new LlmResult
        {
            Json = content,
            Model = model,
            InputTokens = parsed.Usage?.InputTokens ?? 0,
            OutputTokens = parsed.Usage?.OutputTokens ?? 0,
            CostUsd = CostCalculator.Estimate(model, parsed.Usage?.InputTokens ?? 0, parsed.Usage?.OutputTokens ?? 0),
        };
    }

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed class MessagesRequest
    {
        [JsonPropertyName("model")] public required string Model { get; init; }
        [JsonPropertyName("max_tokens")] public int MaxTokens { get; init; }
        [JsonPropertyName("temperature")] public double Temperature { get; init; }
        [JsonPropertyName("system")] public string? System { get; init; }
        [JsonPropertyName("messages")] public required IList<MessageTurn> Messages { get; init; }
    }

    private sealed class MessageTurn
    {
        [JsonPropertyName("role")] public required string Role { get; init; }
        [JsonPropertyName("content")] public required string Content { get; init; }
    }

    private sealed class MessagesResponse
    {
        [JsonPropertyName("content")] public IList<ContentBlock>? Content { get; init; }
        [JsonPropertyName("usage")] public Usage? Usage { get; init; }
    }

    private sealed class ContentBlock
    {
        [JsonPropertyName("type")] public string Type { get; init; } = string.Empty;
        [JsonPropertyName("text")] public string? Text { get; init; }
    }

    private sealed class Usage
    {
        [JsonPropertyName("input_tokens")] public int InputTokens { get; init; }
        [JsonPropertyName("output_tokens")] public int OutputTokens { get; init; }
    }
}
