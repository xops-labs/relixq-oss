// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
namespace RelixQ.Contracts.Events;

/// <summary>
/// Base shape for Relix-Q cross-service scoring events. Each concrete event
/// sets its own constant <see cref="Event"/> discriminator in its
/// constructor so the bus subscriber can route by string.
/// </summary>
public abstract class ScoringEvent
{
    public string Event { get; init; } = string.Empty;
    public DateTimeOffset Ts { get; init; }
    public string? TraceId { get; init; }
    public Guid OrganizationId { get; init; }
}

public sealed class FindingCreatedEvent : ScoringEvent
{
    public Guid FindingId { get; init; }
    public Guid ProjectId { get; init; }
    public string RuleId { get; init; } = string.Empty;
    public int RiskScore { get; init; }
    public string RiskLevel { get; init; } = string.Empty;
    public FindingCreatedEvent() { Event = "finding.created"; }
}

public sealed class FindingUpdatedEvent : ScoringEvent
{
    public Guid FindingId { get; init; }
    public int PrevScore { get; init; }
    public int NewScore { get; init; }
    public FindingUpdatedEvent() { Event = "finding.updated"; }
}

public sealed class FindingResolvedEvent : ScoringEvent
{
    public Guid FindingId { get; init; }
    public DateTimeOffset ResolvedAt { get; init; }
    public FindingResolvedEvent() { Event = "finding.resolved"; }
}
