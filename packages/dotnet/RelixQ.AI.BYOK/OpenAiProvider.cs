// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace RelixQ.AI.BYOK;

/// <summary>
/// Public OpenAI (api.openai.com) chat completions adapter using
/// <c>response_format: json_object</c>. BYOK: the API key is sourced from the
/// <c>OPENAI_API_KEY</c> environment variable first, with the configured
/// <see cref="OpenAiOptions.ApiKey"/> as fallback. Recommended supply path is
/// env var in containers, .NET user-secrets in dev, Azure Key Vault in prod.
/// NEVER commit a key to source — once present in git history it is compromised.
/// </summary>
public sealed class OpenAiProvider : ILlmProvider
{
    public LlmProviderKind Kind => LlmProviderKind.OpenAi;
    public string Name => "openai";

    private readonly HttpClient _http;
    private readonly OpenAiOptions _options;
    private readonly ILogger<OpenAiProvider> _log;
    private readonly string? _resolvedKey;

    public OpenAiProvider(HttpClient http, OpenAiOptions options, ILogger<OpenAiProvider> log)
    {
        _http = http;
        _options = options;
        _log = log;
        _resolvedKey = EnvKeyResolver.TryResolve(OpenAiOptions.ApiKeyEnvVar, options.ApiKey);

        if (!string.IsNullOrWhiteSpace(_resolvedKey))
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _resolvedKey);
        if (!string.IsNullOrWhiteSpace(_options.OrganizationId))
            _http.DefaultRequestHeaders.Add("OpenAI-Organization", _options.OrganizationId);
        if (!string.IsNullOrWhiteSpace(_options.Project))
            _http.DefaultRequestHeaders.Add("OpenAI-Project", _options.Project);
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

        var url = $"{_options.BaseUrl.TrimEnd('/')}/chat/completions";
        var body = new ChatRequest
        {
            Model = model,
            Messages =
            [
                new() { Role = "system", Content = request.SystemMessage },
                new() { Role = "user", Content = request.UserMessage },
            ],
            Temperature = _options.Temperature,
            MaxTokens = request.MaxOutputTokens,
            ResponseFormat = request.EnforceJsonMode ? new ResponseFormat { Type = "json_object" } : null,
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(body, options: SerializerOptions),
        };

        using var res = await _http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var text = await res.Content.ReadAsStringAsync(ct);
            _log.LogWarning("openai {Status} {Body}", (int)res.StatusCode, text);
            throw new LlmProviderUnavailableException(Name);
        }

        var parsed = await res.Content.ReadFromJsonAsync<ChatResponse>(SerializerOptions, ct)
            ?? throw new LlmProviderUnavailableException(Name);

        var content = parsed.Choices.FirstOrDefault()?.Message.Content
            ?? throw new LlmProviderUnavailableException(Name);

        return new LlmResult
        {
            Json = content,
            Model = model,
            InputTokens = parsed.Usage?.PromptTokens ?? 0,
            OutputTokens = parsed.Usage?.CompletionTokens ?? 0,
            CostUsd = CostCalculator.Estimate(model, parsed.Usage?.PromptTokens ?? 0, parsed.Usage?.CompletionTokens ?? 0),
        };
    }

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed class ChatRequest
    {
        [JsonPropertyName("model")] public required string Model { get; init; }
        [JsonPropertyName("messages")] public required IList<ChatMessage> Messages { get; init; }
        [JsonPropertyName("temperature")] public double Temperature { get; init; }
        [JsonPropertyName("max_tokens")] public int MaxTokens { get; init; }
        [JsonPropertyName("response_format")] public ResponseFormat? ResponseFormat { get; init; }
    }

    private sealed class ResponseFormat
    {
        [JsonPropertyName("type")] public required string Type { get; init; }
    }

    private sealed class ChatMessage
    {
        [JsonPropertyName("role")] public required string Role { get; init; }
        [JsonPropertyName("content")] public required string Content { get; init; }
    }

    private sealed class ChatResponse
    {
        [JsonPropertyName("choices")] public IList<Choice> Choices { get; init; } = [];
        [JsonPropertyName("usage")] public Usage? Usage { get; init; }
    }

    private sealed class Choice
    {
        [JsonPropertyName("message")] public ChatMessage Message { get; init; } = new() { Role = "assistant", Content = "" };
    }

    private sealed class Usage
    {
        [JsonPropertyName("prompt_tokens")] public int PromptTokens { get; init; }
        [JsonPropertyName("completion_tokens")] public int CompletionTokens { get; init; }
        [JsonPropertyName("total_tokens")] public int TotalTokens { get; init; }
    }
}
