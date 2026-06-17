// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.AI.BYOK;

/// <summary>
/// Canonical set of LLM provider kinds Relix-Q supports. The enum lives in
/// the OSS package because every adapter — BYOK or hosted —
/// declares one of these as its <see cref="ILlmProvider.Kind"/>.
/// </summary>
public enum LlmProviderKind
{
    AzureOpenAi = 0,
    AwsBedrock = 1,
    VertexAi = 2,
    OpenAi = 3,
    Anthropic = 4,
    Deterministic = 99,
}
