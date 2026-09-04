using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<CorrelationType>))]
public enum CorrelationType { OrderedSequence, UnorderedSet, ThresholdChain, DistinctEntity, ParentChild, CrossDomain, FindingToFinding, EventToFinding, NegativeSequence, StatefulAccumulation }
[JsonConverter(typeof(JsonStringEnumConverter<CorrelationStatus>))]
public enum CorrelationStatus { Draft, Testing, Active, Disabled, Deprecated }
[JsonConverter(typeof(JsonStringEnumConverter<CorrelationInputKind>))]
public enum CorrelationInputKind { Event, DetectionFinding }
[JsonConverter(typeof(JsonStringEnumConverter<CorrelationCompletionState>))]
public enum CorrelationCompletionState { Complete, Incomplete, TimedOut }

public sealed record CorrelationStep(
    string Id,
    int Order,
    CorrelationInputKind InputKind,
    DetectionDomain? Domain,
    DetectionCondition Condition,
    bool Required = true,
    bool Negative = false,
    int MinimumCount = 1,
    bool Distinct = false,
    string? DistinctField = null,
    int OrderGroup = 0,
    Guid? DetectionId = null);

public sealed record CorrelationQuality(
    string Rationale,
    string[] KnownBenignCases,
    string TuningGuidance,
    string[] FalsePositiveDrivers,
    string ConfidenceRationale,
    string[] SupportLimitations);

public sealed record CorrelationRule(
    string SchemaVersion,
    Guid CorrelationRuleId,
    int Version,
    string TenantId,
    Guid PackId,
    int PackVersion,
    string Name,
    string Description,
    int Severity,
    int Confidence,
    string Category,
    string[] Tags,
    string MitreTactic,
    string MitreTechnique,
    string? MitreSubTechnique,
    DetectionDomain[] RequiredTelemetry,
    Guid[] RequiredDetectionFindings,
    string EntityScope,
    CorrelationType Type,
    int WindowSeconds,
    string[] JoinKeys,
    CorrelationStep[] Steps,
    CorrelationSuppression Suppression,
    Guid[] ExclusionReferences,
    CorrelationQuality Quality,
    CorrelationStatus Status,
    bool Enabled,
    bool ValidationPassed,
    DateTimeOffset? ValidatedAt,
    DateTimeOffset CreatedAt,
    string CreatedBy,
    DateTimeOffset? ActivatedAt = null,
    DateTimeOffset? DeactivatedAt = null);

public sealed record CorrelationSuppression(string Scope = "correlation-key", int DurationMinutes = 0);
public sealed record CorrelationPack(
    Guid PackId,
    int Version,
    string TenantId,
    string Name,
    string Description,
    DetectionDomain[] SupportedTelemetry,
    Guid[] RuleIds,
    string[] MitreCoverage,
    string[] Dependencies,
    bool ValidationPassed,
    bool Enabled,
    string Changelog,
    DateTimeOffset CreatedAt,
    string CreatedBy);

public sealed record CorrelationAssignment(Guid Id, string TenantId, Guid PackId, int PackVersion, Guid? EndpointId, Guid? EndpointGroupId, bool Enabled, DateTimeOffset CreatedAt, string CreatedBy);
public sealed record CorrelationExclusion(Guid Id, int Version, string TenantId, Guid? PackId, Guid? RuleId, string Field, string Value, DateTimeOffset StartsAt, DateTimeOffset EndsAt, string Reason, string CreatedBy, long MatchCount = 0);

public sealed record CorrelationObservation(
    Guid ObservationId,
    string TenantId,
    CorrelationInputKind Kind,
    DetectionDomain? Domain,
    DateTimeOffset EventTime,
    DateTimeOffset IngestedAt,
    Guid? EndpointId,
    string? ProcessEntityId,
    string? ParentProcessEntityId,
    string? EntityId,
    Guid? DetectionFindingId,
    Guid? DetectionId,
    IReadOnlyDictionary<string, string?> Fields,
    string EvidenceReference,
    bool Late = false,
    bool Incomplete = false,
    string[]? MissingTelemetry = null,
    string[]? Quality = null,
    int Confidence = 0);

public sealed record CorrelationMatchedStep(string StepId, int Order, Guid[] ObservationIds, string[] EvidenceReferences, string[] MatchedValues, DateTimeOffset FirstSeen, DateTimeOffset LastSeen);
public sealed record CorrelationTimelineItem(Guid ObservationId, string StepId, DateTimeOffset EventTime, DateTimeOffset IngestedAt, DetectionDomain? Domain, string EvidenceReference, bool Late, bool Incomplete);
public sealed record CorrelatedFinding(
    Guid CorrelatedFindingId,
    string TenantId,
    Guid CorrelationRuleId,
    int CorrelationRuleVersion,
    Guid PackId,
    int PackVersion,
    string RuleName,
    Guid? EndpointId,
    string CorrelationKey,
    int Severity,
    int Confidence,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    CorrelationCompletionState CompletionState,
    CorrelationMatchedStep[] MatchedSteps,
    string[] UnmatchedOptionalSteps,
    string[] MissingRequiredTelemetry,
    Guid[] EvidenceEventIds,
    Guid[] ChildFindingIds,
    DetectionDomain[] SourceDomains,
    string[] EntityRelationships,
    string[] MatchedValues,
    CorrelationTimelineItem[] Timeline,
    string Explanation,
    string MitreTactic,
    string MitreTechnique,
    string? MitreSubTechnique,
    bool Suppressed,
    string? SuppressionReason,
    Guid? OriginalFindingId,
    bool Excluded,
    string? ExclusionReason,
    DetectionExecutionMode ExecutionMode,
    string EngineVersion,
    string[] TelemetryQuality,
    bool LateEvidence,
    bool IncompleteEvidence,
    double MaximumIngestionDelayMilliseconds,
    string CompletionReason,
    string? TimeoutReason,
    DateTimeOffset CreatedAt);

public sealed record CorrelationEvaluationResult(bool Duplicate, bool Matched, bool Excluded, bool Suppressed, string CorrelationKey, string[] MissingSteps, CorrelatedFinding? Finding, string Reason);
public sealed record CorrelationFixture(string Name, string Kind, CorrelationObservation[] Observations, int ExpectedFindings);
public sealed record CorrelationTestResult(string Name, string Kind, bool Passed, int ExpectedFindings, int ActualFindings, bool Deterministic, bool TenantIsolated, bool ResourceCostPassed, DateTimeOffset CompletedAt, string[] Failures);
public sealed record CorrelationRun(Guid Id, string TenantId, Guid RuleId, int RuleVersion, Guid PackId, int PackVersion, DetectionExecutionMode Mode, DateTimeOffset From, DateTimeOffset To, string Status, long ObservationsTotal, long ObservationsEvaluated, long Findings, bool ProductionFindings, DateTimeOffset CreatedAt, DateTimeOffset? CompletedAt = null);
public sealed record CorrelationHealth(long CorrelationsEvaluated, long ActiveStateObjects, long ExpiredStates, long CompletedCorrelations, long IncompleteCorrelations, long LateEvents, long DuplicateEvents, double StateStoreLatencyMilliseconds, double EvaluationLatencyMilliseconds, double ReplayLatencyMilliseconds, long RuleFailures, long MissingTelemetry, long Suppressed, long Excluded, long ReplayQueueDepth, DateTimeOffset UpdatedAt);
public sealed record CorrelatedFindingQuery(Guid? RuleId = null, Guid? PackId = null, Guid? EndpointId = null, int? MinimumSeverity = null, bool? Suppressed = null, DetectionExecutionMode? Mode = null, DateTimeOffset? From = null, DateTimeOffset? To = null, int PageSize = 100, string? Cursor = null);
public sealed record CorrelatedFindingPage(IReadOnlyList<CorrelatedFinding> Items, string? NextCursor);
public sealed record MitreCoverageRow(string Tactic, string Technique, string? SubTechnique, string[] RuleNames, DetectionDomain[] RequiredTelemetry, bool TelemetryAvailable, bool DetectionImplemented, bool DetectionTested, bool ProductionActive);

public static class CorrelationDsl
{
    public const string EngineVersion = "correlation-engine.v1";
    public const int MaximumRuleBytes = 96 * 1024;
    public const int MaximumSteps = 16;
    public const int MaximumWindowSeconds = 7 * 24 * 60 * 60;
    public const int MaximumJoinKeys = 4;
    public const int MaximumStepCount = 10_000;
    static readonly HashSet<string> JoinAllowlist = new(StringComparer.OrdinalIgnoreCase) { "endpointId", "processEntityId", "parentProcessEntityId", "entityId", "user", "userSid", "logonId", "fileEntityId", "filePathArgument", "registryEntityId", "remoteEndpoint", "dnsName", "moduleEntityId", "serviceEntityId", "taskEntityId", "persistenceEntityId", "identityEntityId" };

    public static IReadOnlyDictionary<string, string[]> Validate(CorrelationRule rule)
    {
        var errors = new Dictionary<string, string[]>();
        void Add(string key, string value) => errors[key] = [value];
        if (System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(rule).Length > MaximumRuleBytes) Add("rule", "Rule exceeds 96 KiB.");
        if (rule.CorrelationRuleId == Guid.Empty || !Guid.TryParse(rule.TenantId, out _) || rule.PackId == Guid.Empty || rule.Version < 1 || rule.PackVersion < 1) Add("identity", "Rule, pack, tenant and versions are required.");
        if (string.IsNullOrWhiteSpace(rule.Name) || rule.Name.Length > 160 || rule.Description.Length > 4_096) Add("name", "Name or description bounds are invalid.");
        if (rule.Severity is < 0 or > 100 || rule.Confidence is < 0 or > 100) Add("score", "Severity and confidence must be 0-100.");
        if (rule.WindowSeconds is < 1 or > MaximumWindowSeconds) Add("window", "Window must be 1 second to 7 days.");
        if (rule.Steps.Length is < 2 or > MaximumSteps) Add("steps", "Correlation requires 2-16 steps.");
        if (rule.JoinKeys.Length is < 1 or > MaximumJoinKeys || rule.JoinKeys.Any(x => !JoinAllowlist.Contains(x))) Add("joinKeys", "Join keys must be 1-4 allowlisted stable identifiers.");
        if (rule.Steps.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != rule.Steps.Length || rule.Steps.Any(x => string.IsNullOrWhiteSpace(x.Id) || x.MinimumCount is < 1 or > MaximumStepCount)) Add("stepIdentity", "Step IDs and counts must be unique and bounded.");
        if (rule.Steps.Any(x => x.InputKind == CorrelationInputKind.Event && x.Domain is null || x.InputKind == CorrelationInputKind.DetectionFinding && x.DetectionId is null)) Add("stepSource", "Every step requires an explicit event domain or detection identity.");
        foreach (var step in rule.Steps.Where(x => x.InputKind == CorrelationInputKind.Event && x.Domain is not null))
        {
            var fake = FakeRule(rule, step);
            foreach (var error in DetectionDsl.Validate(fake)) Add($"step.{step.Id}.{error.Key}", string.Join(';', error.Value));
        }
        if (rule.RequiredTelemetry.Distinct().Count() != rule.RequiredTelemetry.Length || rule.Steps.Where(x => x.Domain is not null).Any(x => !rule.RequiredTelemetry.Contains(x.Domain!.Value))) Add("requiredTelemetry", "Required telemetry must cover every event step.");
        if (!System.Text.RegularExpressions.Regex.IsMatch(rule.MitreTechnique, "^T[0-9]{4}(\\.[0-9]{3})?$", System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50))) Add("mitre", "MITRE technique identifier is invalid.");
        if (rule.Suppression.DurationMinutes is < 0 or > 10_080) Add("suppression", "Suppression is bounded to seven days.");
        return errors;
    }

    public static string Key(CorrelationRule rule, CorrelationObservation observation)
    {
        var values = rule.JoinKeys.Select(x => Field(observation, x) ?? "<missing>");
        return string.Join('|', values);
    }

    public static bool Matches(CorrelationRule rule, CorrelationStep step, CorrelationObservation observation, out string[] values)
    {
        values = [];
        if (step.InputKind != observation.Kind || step.Domain is not null && step.Domain != observation.Domain || step.DetectionId is not null && step.DetectionId != observation.DetectionId) return false;
        var evidence = new DetectionEvidenceEvent(observation.ObservationId, observation.TenantId, observation.Domain ?? DetectionDomain.Process, observation.EventTime, observation.EndpointId, observation.ProcessEntityId, observation.EntityId, observation.Fields, observation.EvidenceReference, observation.Late, observation.Incomplete, observation.MissingTelemetry, observation.Quality);
        var evaluation = DetectionDsl.Evaluate(FakeRule(rule, step), evidence);
        values = evaluation.Conditions.Where(x => x.Matched).Select(x => $"{x.Field}={x.ActualValue}").ToArray();
        return evaluation.Matched;
    }

    public static CorrelatedFinding? Complete(CorrelationRule rule, IReadOnlyList<CorrelationObservation> observations, DetectionExecutionMode mode, CorrelatedFinding? prior = null)
    {
        if (observations.Count == 0) return null;
        var key = Key(rule, observations[^1]);
        var first = observations.Min(x => x.EventTime); var last = observations.Max(x => x.EventTime);
        var bounded = observations.Where(x => x.EventTime >= last.AddSeconds(-rule.WindowSeconds) && x.EventTime <= last).OrderBy(x => x.EventTime).ThenBy(x => x.ObservationId).ToArray();
        var matched = new List<(CorrelationStep Step, CorrelationObservation[] Values, string[] MatchedValues)>();
        foreach (var step in rule.Steps)
        {
            var candidates = bounded.Where(x => Key(rule, x) == key && Matches(rule, step, x, out _)).ToArray();
            var count = step.Distinct ? candidates.Select(x => Field(x, step.DistinctField!)).Where(x => x is not null).Distinct(StringComparer.Ordinal).Count() : candidates.Length;
            if (step.Negative) { if (candidates.Length > 0) return null; continue; }
            if (step.Required && count < step.MinimumCount) return null;
            if (count >= step.MinimumCount)
            {
                var used = step.Distinct ? candidates.GroupBy(x => Field(x, step.DistinctField!) ?? "").Select(x => x.First()).Take(step.MinimumCount).ToArray() : candidates.Take(step.MinimumCount).ToArray();
                matched.Add((step, used, used.SelectMany(x => { Matches(rule, step, x, out var v); return v; }).Distinct().ToArray()));
            }
        }
        if (rule.Type == CorrelationType.NegativeSequence && last - first < TimeSpan.FromSeconds(rule.WindowSeconds)) return null;
        if (rule.Type is CorrelationType.OrderedSequence or CorrelationType.ThresholdChain or CorrelationType.ParentChild or CorrelationType.CrossDomain or CorrelationType.EventToFinding)
        {
            var ordered = matched.Where(x => x.Step.Required).OrderBy(x => x.Step.Order).Select(x => x.Values.Min(v => v.EventTime)).ToArray();
            for (var i = 1; i < ordered.Length; i++) if (ordered[i] < ordered[i - 1]) return null;
        }
        if (rule.Type == CorrelationType.ParentChild && matched.OrderBy(x => x.Step.Order).SelectMany(x => x.Values).ToArray() is { Length: >= 2 } tree && !string.Equals(tree[1].ParentProcessEntityId, tree[0].ProcessEntityId, StringComparison.Ordinal)) return null;
        var usedObservations = matched.SelectMany(x => x.Values).DistinctBy(x => x.ObservationId).OrderBy(x => x.EventTime).ThenBy(x => x.ObservationId).ToArray();
        if (usedObservations.Length == 0) return null;
        var evidenceIds = usedObservations.Where(x => x.Kind == CorrelationInputKind.Event).Select(x => x.ObservationId).ToArray();
        var childIds = usedObservations.Where(x => x.DetectionFindingId is not null).Select(x => x.DetectionFindingId!.Value).Distinct().ToArray();
        var findingId = DeterministicId($"{rule.TenantId}:{rule.CorrelationRuleId}:{rule.Version}:{rule.PackId}:{rule.PackVersion}:{mode}:{key}:{string.Join(',', usedObservations.Select(x => x.ObservationId))}");
        var confidence = Math.Clamp(rule.Confidence + usedObservations.Sum(x => x.Confidence) / Math.Max(1, usedObservations.Length) - usedObservations.Count(x => x.Late || x.Incomplete) * 5, 0, 100);
        var suppressed = prior is not null && rule.Suppression.DurationMinutes > 0 && prior.CreatedAt >= last.AddMinutes(-rule.Suppression.DurationMinutes);
        var stepResults = matched.Select(x => new CorrelationMatchedStep(x.Step.Id, x.Step.Order, x.Values.Select(v => v.ObservationId).ToArray(), x.Values.Select(v => v.EvidenceReference).ToArray(), x.MatchedValues, x.Values.Min(v => v.EventTime), x.Values.Max(v => v.EventTime))).ToArray();
        var missing = rule.RequiredTelemetry.Where(d => usedObservations.All(x => x.Domain != d)).Select(x => x.ToString()).Concat(usedObservations.SelectMany(x => x.MissingTelemetry ?? [])).Distinct().ToArray();
        var timeline = usedObservations.Select(x => new CorrelationTimelineItem(x.ObservationId, matched.First(m => m.Values.Any(v => v.ObservationId == x.ObservationId)).Step.Id, x.EventTime, x.IngestedAt, x.Domain, x.EvidenceReference, x.Late, x.Incomplete)).ToArray();
        return new(findingId, rule.TenantId, rule.CorrelationRuleId, rule.Version, rule.PackId, rule.PackVersion, rule.Name, usedObservations.Select(x => x.EndpointId).FirstOrDefault(x => x is not null), key, rule.Severity, confidence, usedObservations[0].EventTime, usedObservations[^1].EventTime, CorrelationCompletionState.Complete, stepResults, rule.Steps.Where(x => !x.Required && matched.All(m => m.Step.Id != x.Id)).Select(x => x.Id).ToArray(), missing, evidenceIds, childIds, usedObservations.Where(x => x.Domain is not null).Select(x => x.Domain!.Value).Distinct().ToArray(), Relationships(usedObservations), matched.SelectMany(x => x.MatchedValues).Distinct().ToArray(), timeline, Explain(rule, stepResults, key, missing), rule.MitreTactic, rule.MitreTechnique, rule.MitreSubTechnique, suppressed, suppressed ? "bounded-correlation-key-suppression" : null, prior?.CorrelatedFindingId, false, null, mode, EngineVersion, usedObservations.SelectMany(x => x.Quality ?? []).Distinct().ToArray(), usedObservations.Any(x => x.Late), usedObservations.Any(x => x.Incomplete), usedObservations.Max(x => Math.Max(0, (x.IngestedAt - x.EventTime).TotalMilliseconds)), rule.Type == CorrelationType.NegativeSequence ? "negative-window-expired" : "all-required-steps-satisfied", rule.Type == CorrelationType.NegativeSequence ? "prohibited-step-not-observed-within-window" : null, DateTimeOffset.UtcNow);
    }

    static string? Field(CorrelationObservation x, string field) => field switch { "endpointId" => x.EndpointId?.ToString("D"), "processEntityId" => x.ProcessEntityId, "parentProcessEntityId" => x.ParentProcessEntityId, "entityId" => x.EntityId, _ => x.Fields.GetValueOrDefault(field) };
    public static string? Value(CorrelationObservation observation, string field) => Field(observation, field);
    static string[] Relationships(CorrelationObservation[] values) => values.SelectMany(x => new[] { x.EndpointId is null ? null : $"endpoint:{x.EndpointId:D}", x.ProcessEntityId is null ? null : $"process:{x.ProcessEntityId}", x.ParentProcessEntityId is null ? null : $"parent:{x.ParentProcessEntityId}", x.EntityId is null ? null : $"entity:{x.EntityId}" }).Where(x => x is not null).Cast<string>().Distinct().ToArray();
    static string Explain(CorrelationRule r, CorrelationMatchedStep[] steps, string key, string[] missing) => $"Rule {r.Name} v{r.Version} completed {steps.Length} matched steps in order [{string.Join(" -> ", steps.OrderBy(x => x.Order).Select(x => x.StepId))}] within {r.WindowSeconds}s using {string.Join(',', r.JoinKeys)}={key}. Missing telemetry: {(missing.Length == 0 ? "none" : string.Join(',', missing))}.";
    static DetectionDefinition FakeRule(CorrelationRule rule, CorrelationStep step) => new("detection-rule.v1", rule.CorrelationRuleId, rule.Version, rule.TenantId, rule.Name, rule.Description, DetectionRuleStatus.Testing, false, rule.CreatedBy, rule.CreatedAt, rule.CreatedAt, rule.Severity, rule.Confidence, rule.Category, rule.Tags, [rule.MitreTactic], [rule.MitreTechnique], [step.Domain?.ToString() ?? "Finding"], DetectionRuleType.Event, step.Domain ?? DetectionDomain.Process, [], [], 1, [], 1, false, null, step.Condition, DetectionExecutionMode.Simulation, new(), [], "correlation-fixture.v1", true, rule.ValidatedAt);
    public static Guid DeterministicId(string value) { var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value)); return new Guid(bytes.AsSpan(0, 16)); }
}

public interface ICorrelationRepository
{
    Task<IReadOnlyList<CorrelationPack>> ListPacksAsync(string tenant, CancellationToken ct);
    Task<CorrelationPack?> GetPackAsync(string tenant, Guid id, int? version, CancellationToken ct);
    Task<IReadOnlyList<CorrelationPack>> PackHistoryAsync(string tenant, Guid id, CancellationToken ct);
    Task<CorrelationPack> PutPackAsync(string tenant, string actor, CorrelationPack pack, CancellationToken ct);
    Task<CorrelationPack> SetPackEnabledAsync(string tenant, string actor, Guid id, int version, bool enabled, CancellationToken ct);
    Task<CorrelationAssignment> AssignPackAsync(string tenant, string actor, CorrelationAssignment assignment, CancellationToken ct);
    Task<IReadOnlyList<CorrelationRule>> ListRulesAsync(string tenant, Guid? packId, CancellationToken ct);
    Task<CorrelationRule?> GetRuleAsync(string tenant, Guid id, int? version, CancellationToken ct);
    Task<IReadOnlyList<CorrelationRule>> RuleHistoryAsync(string tenant, Guid id, CancellationToken ct);
    Task<CorrelationRule> PutRuleAsync(string tenant, string actor, CorrelationRule rule, bool newVersion, CancellationToken ct);
    Task<CorrelationRule> ValidateRuleAsync(string tenant, Guid id, int version, IReadOnlyDictionary<string, string[]> errors, CancellationToken ct);
    Task RecordTestsAsync(string tenant, Guid id, int version, IReadOnlyList<CorrelationTestResult> tests, CancellationToken ct);
    Task<IReadOnlyList<CorrelationTestResult>> ListTestsAsync(string tenant, Guid id, int version, CancellationToken ct);
    Task<CorrelationRule> SetRuleEnabledAsync(string tenant, string actor, Guid id, int version, bool enabled, CancellationToken ct);
    Task<CorrelationEvaluationResult> EvaluateAsync(string tenant, CorrelationObservation observation, DetectionExecutionMode mode, Guid? ruleId, int? version, Guid? runId, bool production, CancellationToken ct);
    Task<IReadOnlyList<CorrelationObservation>> LoadObservationsAsync(string tenant, DateTimeOffset from, DateTimeOffset until, int maximum, CancellationToken ct);
    Task<CorrelatedFindingPage> SearchFindingsAsync(string tenant, CorrelatedFindingQuery query, CancellationToken ct);
    Task<CorrelatedFinding?> GetFindingAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<CorrelationExclusion>> ListExclusionsAsync(string tenant, CancellationToken ct);
    Task<CorrelationExclusion> PutExclusionAsync(string tenant, string actor, CorrelationExclusion exclusion, CancellationToken ct);
    Task<CorrelationRun> PutRunAsync(string tenant, CorrelationRun run, CorrelationRule rule, CancellationToken ct);
    Task<CorrelationRun?> GetRunAsync(string tenant, Guid id, CancellationToken ct);
    Task<CorrelationRun> CompleteRunAsync(string tenant, Guid id, long evaluated, long findings, string status, CancellationToken ct);
    Task<CorrelationRun> CancelRunAsync(string tenant, Guid id, CancellationToken ct);
    Task<CorrelationHealth> HealthAsync(string tenant, CancellationToken ct);
    Task<IReadOnlyList<MitreCoverageRow>> CoverageAsync(string tenant, CancellationToken ct);
}

public interface ICorrelationProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(CorrelatedFinding finding, CancellationToken ct);
    Task<long> CountAsync(string tenant, CancellationToken ct);
    Task<bool> HealthAsync(CancellationToken ct);
}
