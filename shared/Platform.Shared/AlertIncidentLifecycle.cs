using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<AlertSourceType>))] public enum AlertSourceType { DetectionFinding, CorrelatedFinding, AnalystPromotion }
[JsonConverter(typeof(JsonStringEnumConverter<AlertStatus>))] public enum AlertStatus { New, Acknowledged, Investigating, Escalated, Resolved, Closed }
[JsonConverter(typeof(JsonStringEnumConverter<AlertDisposition>))] public enum AlertDisposition { None, ConfirmedMalicious, Suspicious, Benign, FalsePositive, ExpectedActivity, Duplicate, Inconclusive }
[JsonConverter(typeof(JsonStringEnumConverter<IncidentStatus>))] public enum IncidentStatus { New, Triage, Investigating, Contained, Resolved, Closed }
[JsonConverter(typeof(JsonStringEnumConverter<AnalystNoteKind>))] public enum AnalystNoteKind { Comment, Investigation, Handoff, DispositionRationale }

public sealed record AlertEvidence(
    Guid[] EndpointIds, string[] ProcessEntities, string[] Users, string[] Files,
    string[] NetworkDnsEntities, string[] PersistenceEntities, Guid[] RawEventIds,
    string[] EvidenceReferences, Guid[] DetectionFindingIds, Guid[] CorrelatedFindingIds,
    Guid[] AttackStoryIds, string[] TelemetryQuality, string[] MissingEvidence);

public sealed record LifecycleAuditEvent(
    Guid AuditId, string TenantId, string ObjectType, Guid ObjectId, int ObjectVersion,
    string Action, string Actor, DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, string?> Before, IReadOnlyDictionary<string, string?> After,
    string Reason, string Provenance = "analyst-workflow");

public sealed record AnalystNote(
    Guid NoteId, string TenantId, string ObjectType, Guid ObjectId, AnalystNoteKind Kind,
    string Author, string Content, int Version, DateTimeOffset CreatedAt, Guid AuditId);

public sealed record AlertCandidate(
    string TenantId, AlertSourceType SourceType, Guid SourceId, Guid? DetectionFindingId,
    Guid? CorrelatedFindingId, Guid RuleId, int RuleVersion, int PackVersion,
    string Title, string Description, int Severity, int Confidence, string Category,
    string[] MitreTactics, string[] MitreTechniques, string[] TelemetryDomains,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, Guid? EndpointId,
    string? ProcessEntityId, string? EntityId, string? CorrelationKey,
    AlertEvidence Evidence, DetectionExecutionMode ExecutionMode, bool ProductionFinding);

public sealed record AlertRecord(
    string SchemaVersion, Guid AlertId, string TenantId, AlertSourceType AlertType,
    Guid? SourceFindingId, Guid? SourceCorrelatedFindingId, Guid RuleId, int RuleVersion,
    int PackVersion, string Title, string Description, int Severity, int Confidence,
    int Priority, string PriorityExplanation, string Category, string[] MitreTactics,
    string[] MitreTechniques, string[] TelemetryDomains, DateTimeOffset CreatedAt,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, DateTimeOffset? AcknowledgedAt,
    DateTimeOffset? AssignedAt, DateTimeOffset? InvestigationStartedAt,
    DateTimeOffset? ResolvedAt, DateTimeOffset? ClosedAt, DateTimeOffset? ReopenedAt,
    AlertStatus CurrentStatus, AlertDisposition Disposition, string? Assignee, string? Team,
    string Creator, string LastEditor, AlertEvidence Evidence, int RepeatCount,
    Guid[] SourceFindingHistory, string DeduplicationKey, int DeduplicationWindowMinutes,
    int ReopenCount, int Version, AnalystNote[] Comments, LifecycleAuditEvent[] AuditHistory)
{
    public double AgeSeconds => Math.Max(0, (DateTimeOffset.UtcNow - CreatedAt).TotalSeconds);
    public double? TimeToAcknowledgeSeconds => AcknowledgedAt is null ? null : Math.Max(0, (AcknowledgedAt.Value - CreatedAt).TotalSeconds);
    public double? TimeToAssignSeconds => AssignedAt is null ? null : Math.Max(0, (AssignedAt.Value - CreatedAt).TotalSeconds);
    public double? TimeToInvestigationSeconds => InvestigationStartedAt is null ? null : Math.Max(0, (InvestigationStartedAt.Value - CreatedAt).TotalSeconds);
    public double? TimeToResolutionSeconds => ResolvedAt is null ? null : Math.Max(0, (ResolvedAt.Value - CreatedAt).TotalSeconds);
    public double? TimeToCloseSeconds => ClosedAt is null ? null : Math.Max(0, (ClosedAt.Value - CreatedAt).TotalSeconds);
}

public sealed record IncidentRecord(
    string SchemaVersion, Guid IncidentId, string TenantId, string Title, string Summary,
    int Severity, int Priority, int Confidence, IncidentStatus Status,
    AlertDisposition Disposition, string Owner, string? Team, string? Assignee,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset? ClosedAt,
    DateTimeOffset? ReopenedAt, int ReopenCount, int Version, Guid[] AlertIds,
    Guid[] EndpointIds, string[] Users, string[] ProcessEntities, string[] Files,
    string[] NetworkDnsEntities, string[] PersistenceEntities, string[] MitreTechniques,
    Guid[] AttackStoryIds, string[] EvidenceReferences, string GroupingReason,
    AnalystNote[] Comments, LifecycleAuditEvent[] AuditHistory);

public sealed record AlertQuery(
    int? Severity = null, int? Priority = null, AlertStatus? Status = null,
    AlertDisposition? Disposition = null, string? Assignee = null, string? Team = null,
    Guid? EndpointId = null, string? User = null, Guid? RuleId = null,
    string? MitreTechnique = null, string? EvidenceQuality = null,
    DateTimeOffset? From = null, DateTimeOffset? To = null, string Sort = "updated-desc",
    int PageSize = 100, string? Cursor = null, bool Unassigned = false,
    int? MinimumPriority = null);
public sealed record AlertPage(IReadOnlyList<AlertRecord> Items, string? NextCursor, long Total);
public sealed record IncidentQuery(IncidentStatus? Status = null, string? Assignee = null, string? Team = null, int? Priority = null, int PageSize = 100, string? Cursor = null);
public sealed record IncidentPage(IReadOnlyList<IncidentRecord> Items, string? NextCursor, long Total);
public sealed record AlertMutation(AlertStatus? Status = null, AlertDisposition? Disposition = null, string? Assignee = null, string? Team = null, int? Severity = null, int? Priority = null, string Reason = "analyst action");
public sealed record IncidentMutation(IncidentStatus? Status = null, AlertDisposition? Disposition = null, string? Assignee = null, string? Team = null, int? Severity = null, int? Priority = null, string? Title = null, string? Summary = null, string Reason = "analyst action");
public sealed record IncidentCreate(string Title, string Summary, Guid[] AlertIds, string? Team = null, string? Assignee = null, string GroupingReason = "manual selected alerts");
public sealed record SavedTriageFilter(Guid FilterId, string TenantId, string Owner, string Name, AlertQuery Query, int Version, DateTimeOffset CreatedAt);
public sealed record TriageHealth(long AlertsCreated, long AlertsDeduplicated, long AlertsClosed, long AlertsReopened, long IncidentsCreated, long IncidentsClosed, long AssignmentFailures, long InvalidStateTransitions, long GroupingExecutions, long GroupingFailures, double QueueLatencyMilliseconds, double ApiLatencyMilliseconds, double ExportLatencyMilliseconds, DateTimeOffset UpdatedAt);

public interface IAlertIncidentRepository
{
    Task<AlertRecord?> CreateAlertAsync(string tenant, string actor, AlertCandidate candidate, CancellationToken ct);
    Task<AlertRecord?> GetAlertAsync(string tenant, Guid id, CancellationToken ct);
    Task<AlertPage> SearchAlertsAsync(string tenant, AlertQuery query, CancellationToken ct);
    Task<AlertRecord> MutateAlertAsync(string tenant, Guid id, string actor, AlertMutation mutation, CancellationToken ct);
    Task<AnalystNote> AddAlertNoteAsync(string tenant, Guid id, string actor, AnalystNoteKind kind, string content, CancellationToken ct);
    Task<IReadOnlyList<LifecycleAuditEvent>> AlertAuditAsync(string tenant, Guid id, CancellationToken ct);
    Task<AlertRecord[]> BulkMutateAlertsAsync(string tenant, string actor, Guid[] ids, AlertMutation mutation, CancellationToken ct);
    Task<IncidentRecord> CreateIncidentAsync(string tenant, string actor, IncidentCreate input, CancellationToken ct);
    Task<IncidentRecord?> GetIncidentAsync(string tenant, Guid id, CancellationToken ct);
    Task<IncidentPage> SearchIncidentsAsync(string tenant, IncidentQuery query, CancellationToken ct);
    Task<IncidentRecord> MutateIncidentAsync(string tenant, Guid id, string actor, IncidentMutation mutation, CancellationToken ct);
    Task<IncidentRecord> LinkAlertsAsync(string tenant, Guid id, string actor, Guid[] alertIds, bool remove, string reason, CancellationToken ct);
    Task<IncidentRecord> MergeIncidentsAsync(string tenant, Guid target, Guid source, string actor, string reason, CancellationToken ct);
    Task<IncidentRecord> SplitIncidentAsync(string tenant, Guid source, string actor, Guid[] alertIds, string title, string reason, CancellationToken ct);
    Task<AnalystNote> AddIncidentNoteAsync(string tenant, Guid id, string actor, AnalystNoteKind kind, string content, CancellationToken ct);
    Task<IReadOnlyList<LifecycleAuditEvent>> IncidentAuditAsync(string tenant, Guid id, CancellationToken ct);
    Task RecordExportAuditAsync(string tenant, string objectType, Guid objectId, Guid exportId, string actor, CancellationToken ct);
    Task<SavedTriageFilter> SaveFilterAsync(string tenant, string actor, SavedTriageFilter filter, CancellationToken ct);
    Task<IReadOnlyList<SavedTriageFilter>> FiltersAsync(string tenant, string actor, CancellationToken ct);
    Task<TriageHealth> HealthAsync(string tenant, CancellationToken ct);
}

public static class AlertIncidentSafety
{
    public const int MaximumBulk = 100;
    public const int MaximumCommentLength = 4096;
    public const int MaximumIncidentAlerts = 500;
    public const int DeduplicationWindowMinutes = 15;
    public static int Priority(int severity, int confidence, int endpoints, bool complete) => Math.Clamp((severity >= 80 ? 3 : severity >= 50 ? 2 : 1) + (confidence >= 80 ? 1 : 0) + (endpoints > 1 ? 1 : 0) - (complete ? 0 : 1), 1, 5);
    public static string PriorityExplanation(int severity, int confidence, int endpoints, bool complete) => $"priority.v1 severity={severity};confidence={confidence};endpoints={endpoints};evidenceComplete={complete}";
    public static string DeduplicationKey(AlertCandidate x) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|', x.TenantId, x.SourceType, x.RuleId, x.RuleVersion, x.EndpointId, x.ProcessEntityId, x.EntityId, x.CorrelationKey)))).ToLowerInvariant();
    public static string PlainText(string content)
    {
        if (string.IsNullOrWhiteSpace(content) || content.Length > MaximumCommentLength) throw new EnrollmentConflictException("COMMENT_BOUNDS", $"Comment must contain 1-{MaximumCommentLength} characters.");
        if (content.IndexOfAny(['<', '>']) >= 0 || content.Contains("javascript:", StringComparison.OrdinalIgnoreCase) || content.Contains("](", StringComparison.Ordinal) || content.Contains("![", StringComparison.Ordinal)) throw new EnrollmentConflictException("COMMENT_MARKUP_REJECTED", "Comments are plain text; HTML, scripts, links and images are rejected.");
        return content.Trim();
    }
    public static bool CanTransition(AlertStatus from, AlertStatus to) => from == to || (from, to) switch
    {
        (AlertStatus.New, AlertStatus.Acknowledged) => true,
        (AlertStatus.Acknowledged, AlertStatus.Investigating) => true,
        (AlertStatus.Investigating, AlertStatus.Escalated) => true,
        (AlertStatus.Investigating, AlertStatus.Resolved) => true,
        (AlertStatus.Escalated, AlertStatus.Investigating) => true,
        (AlertStatus.Escalated, AlertStatus.Resolved) => true,
        (AlertStatus.Resolved, AlertStatus.Closed) => true,
        (AlertStatus.Closed, AlertStatus.Investigating) => true,
        _ => false
    };
    public static bool CanTransition(IncidentStatus from, IncidentStatus to) => from == to || (from, to) switch
    {
        (IncidentStatus.New, IncidentStatus.Triage) => true,
        (IncidentStatus.Triage, IncidentStatus.Investigating) => true,
        (IncidentStatus.Investigating, IncidentStatus.Contained) => true,
        (IncidentStatus.Investigating, IncidentStatus.Resolved) => true,
        (IncidentStatus.Contained, IncidentStatus.Resolved) => true,
        (IncidentStatus.Resolved, IncidentStatus.Closed) => true,
        (IncidentStatus.Closed, IncidentStatus.Investigating) => true,
        _ => false
    };
    public static AlertCandidate FromDetection(DetectionFinding f, DetectionDefinition rule) => new(f.TenantId, AlertSourceType.DetectionFinding, f.FindingId, f.FindingId, null, f.DetectionId, f.DetectionVersion, 0, f.RuleName, rule.Description, f.Severity, f.Confidence, rule.Category, rule.MitreTactics, rule.MitreTechniques, rule.DataSources, f.FirstSeen, f.LastSeen, f.EndpointId, f.ProcessEntityId, f.EntityId, f.GroupKey, new(f.EndpointId is { } e ? [e] : [], f.ProcessEntityId is null ? [] : [f.ProcessEntityId], [], rule.Domain == DetectionDomain.File && f.EntityId is not null ? [f.EntityId] : [], [], [], f.MatchingEventIds, f.EvidenceReferences, [f.FindingId], [], [], f.TelemetryQuality, f.MissingTelemetry), f.ExecutionMode, f.ExecutionMode == DetectionExecutionMode.Live && !f.Excluded);
    public static AlertCandidate FromCorrelation(CorrelatedFinding f) => new(f.TenantId, AlertSourceType.CorrelatedFinding, f.CorrelatedFindingId, null, f.CorrelatedFindingId, f.CorrelationRuleId, f.CorrelationRuleVersion, f.PackVersion, f.RuleName, f.Explanation, f.Severity, f.Confidence, "correlation", [f.MitreTactic], [f.MitreTechnique], f.SourceDomains.Select(x => x.ToString()).ToArray(), f.FirstSeen, f.LastSeen, f.EndpointId, f.EntityRelationships.FirstOrDefault(x => x.StartsWith("process:", StringComparison.Ordinal))?[8..], null, f.CorrelationKey, new(f.EndpointId is { } e ? [e] : [], f.EntityRelationships.Where(x => x.StartsWith("process:", StringComparison.Ordinal)).Select(x => x[8..]).ToArray(), f.EntityRelationships.Where(x => x.StartsWith("user:", StringComparison.Ordinal)).Select(x => x[5..]).ToArray(), f.EntityRelationships.Where(x => x.StartsWith("file:", StringComparison.Ordinal)).Select(x => x[5..]).ToArray(), f.EntityRelationships.Where(x => x.StartsWith("network:", StringComparison.Ordinal) || x.StartsWith("dns:", StringComparison.Ordinal)).ToArray(), f.EntityRelationships.Where(x => x.StartsWith("persistence:", StringComparison.Ordinal)).ToArray(), f.EvidenceEventIds, f.MatchedSteps.SelectMany(x => x.EvidenceReferences).Distinct().ToArray(), f.ChildFindingIds, [f.CorrelatedFindingId], [], f.TelemetryQuality, f.MissingRequiredTelemetry), f.ExecutionMode, f.ExecutionMode == DetectionExecutionMode.Live && !f.Excluded);
}

public class FileAlertIncidentRepository : IAlertIncidentRepository, IDisposable
{
    readonly ConcurrentDictionary<(string Tenant, Guid Id), AlertRecord> _alerts = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), IncidentRecord> _incidents = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), SavedTriageFilter> _filters = new();
    readonly ConcurrentDictionary<string, long[]> _health = new();
    readonly SemaphoreSlim _gate = new(1, 1);
    protected virtual Task<IReadOnlyList<AlertRecord>> LoadAlertsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<AlertRecord>>(_alerts.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<IncidentRecord>> LoadIncidentsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<IncidentRecord>>(_incidents.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<SavedTriageFilter>> LoadFiltersAsync(string tenant, string actor, CancellationToken ct) => Task.FromResult<IReadOnlyList<SavedTriageFilter>>(_filters.Where(x => x.Key.Tenant == tenant && x.Value.Owner == actor).Select(x => x.Value).ToArray());
    protected virtual Task PersistAlertAsync(AlertRecord alert, LifecycleAuditEvent audit, CancellationToken ct) { _alerts[(alert.TenantId, alert.AlertId)] = alert; return Task.CompletedTask; }
    protected virtual Task PersistIncidentAsync(IncidentRecord incident, LifecycleAuditEvent audit, CancellationToken ct) { _incidents[(incident.TenantId, incident.IncidentId)] = incident; return Task.CompletedTask; }
    protected virtual Task PersistFilterAsync(SavedTriageFilter filter, CancellationToken ct) { _filters[(filter.TenantId, filter.FilterId)] = filter; return Task.CompletedTask; }
    static LifecycleAuditEvent Audit(string tenant, string type, Guid id, int version, string action, string actor, string reason, Dictionary<string, string?>? before = null, Dictionary<string, string?>? after = null) => new(Guid.NewGuid(), tenant, type, id, version, action, actor, DateTimeOffset.UtcNow, before ?? [], after ?? [], reason);
    static AlertEvidence Merge(AlertEvidence a, AlertEvidence b) => new(a.EndpointIds.Concat(b.EndpointIds).Distinct().ToArray(), a.ProcessEntities.Concat(b.ProcessEntities).Distinct().ToArray(), a.Users.Concat(b.Users).Distinct().ToArray(), a.Files.Concat(b.Files).Distinct().ToArray(), a.NetworkDnsEntities.Concat(b.NetworkDnsEntities).Distinct().ToArray(), a.PersistenceEntities.Concat(b.PersistenceEntities).Distinct().ToArray(), a.RawEventIds.Concat(b.RawEventIds).Distinct().ToArray(), a.EvidenceReferences.Concat(b.EvidenceReferences).Distinct().ToArray(), a.DetectionFindingIds.Concat(b.DetectionFindingIds).Distinct().ToArray(), a.CorrelatedFindingIds.Concat(b.CorrelatedFindingIds).Distinct().ToArray(), a.AttackStoryIds.Concat(b.AttackStoryIds).Distinct().ToArray(), a.TelemetryQuality.Concat(b.TelemetryQuality).Distinct().ToArray(), a.MissingEvidence.Concat(b.MissingEvidence).Distinct().ToArray());

    public async Task<AlertRecord?> CreateAlertAsync(string tenant, string actor, AlertCandidate candidate, CancellationToken ct)
    {
        if (candidate.TenantId != tenant) throw new EnrollmentConflictException("TENANT_MISMATCH", "Alert candidate tenant mismatch.");
        if (!candidate.ProductionFinding || candidate.ExecutionMode != DetectionExecutionMode.Live) return null;
        await _gate.WaitAsync(ct); try
        {
            var all = await LoadAlertsAsync(tenant, ct); var key = AlertIncidentSafety.DeduplicationKey(candidate); var existing = all.Where(x => x.DeduplicationKey == key && candidate.FirstSeen <= x.LastSeen.AddMinutes(x.DeduplicationWindowMinutes) && candidate.LastSeen >= x.FirstSeen.AddMinutes(-x.DeduplicationWindowMinutes)).OrderByDescending(x => x.LastSeen).FirstOrDefault();
            if (existing is not null)
            {
                if (existing.SourceFindingHistory.Contains(candidate.SourceId)) return existing;
                var audit = Audit(tenant, "alert", existing.AlertId, existing.Version + 1, "alert.deduplicated", actor, "bounded deterministic rule/entity/time grouping", after: new() { ["sourceFindingId"] = candidate.SourceId.ToString("D"), ["deduplicationKey"] = key });
                var merged = existing with { LastSeen = existing.LastSeen > candidate.LastSeen ? existing.LastSeen : candidate.LastSeen, Evidence = Merge(existing.Evidence, candidate.Evidence), RepeatCount = existing.RepeatCount + 1, SourceFindingHistory = existing.SourceFindingHistory.Append(candidate.SourceId).Distinct().ToArray(), LastEditor = actor, Version = existing.Version + 1, AuditHistory = existing.AuditHistory.Append(audit).ToArray() };
                await PersistAlertAsync(merged, audit, ct); _health.GetOrAdd(tenant, _ => new long[12])[1]++; return merged;
            }
            var bucket = candidate.FirstSeen.ToUnixTimeSeconds() / (AlertIncidentSafety.DeduplicationWindowMinutes * 60); var id = InvestigationSafety.StableId(tenant, "alert", key, bucket.ToString(System.Globalization.CultureInfo.InvariantCulture)); var now = DateTimeOffset.UtcNow; var complete = candidate.Evidence.MissingEvidence.Length == 0; var priority = AlertIncidentSafety.Priority(candidate.Severity, candidate.Confidence, candidate.Evidence.EndpointIds.Length, complete); var auditCreated = Audit(tenant, "alert", id, 1, "alert.created", actor, "production finding converted to alert", after: new() { ["sourceId"] = candidate.SourceId.ToString("D"), ["status"] = AlertStatus.New.ToString() });
            var value = new AlertRecord("alert.v1", id, tenant, candidate.SourceType, candidate.DetectionFindingId, candidate.CorrelatedFindingId, candidate.RuleId, candidate.RuleVersion, candidate.PackVersion, candidate.Title, candidate.Description, candidate.Severity, candidate.Confidence, priority, AlertIncidentSafety.PriorityExplanation(candidate.Severity, candidate.Confidence, candidate.Evidence.EndpointIds.Length, complete), candidate.Category, candidate.MitreTactics, candidate.MitreTechniques, candidate.TelemetryDomains, now, candidate.FirstSeen, candidate.LastSeen, null, null, null, null, null, null, AlertStatus.New, AlertDisposition.None, null, null, actor, actor, candidate.Evidence, 1, [candidate.SourceId], key, AlertIncidentSafety.DeduplicationWindowMinutes, 0, 1, [], [auditCreated]);
            await PersistAlertAsync(value, auditCreated, ct); _health.GetOrAdd(tenant, _ => new long[12])[0]++; return value;
        }
        finally { _gate.Release(); }
    }

    public async Task<AlertRecord?> GetAlertAsync(string tenant, Guid id, CancellationToken ct) => (await LoadAlertsAsync(tenant, ct)).FirstOrDefault(x => x.AlertId == id);
    public async Task<AlertPage> SearchAlertsAsync(string tenant, AlertQuery q, CancellationToken ct)
    {
        if (q.PageSize is < 1 or > 200) throw new EnrollmentConflictException("PAGE_BOUNDS", "Page size must be 1-200."); if (q.MinimumPriority is < 1 or > 5) throw new EnrollmentConflictException("PRIORITY_BOUNDS", "Minimum priority must be 1-5."); var values = (await LoadAlertsAsync(tenant, ct)).Where(x => q.Severity is null || x.Severity == q.Severity).Where(x => q.Priority is null || x.Priority == q.Priority).Where(x => q.MinimumPriority is null || x.Priority >= q.MinimumPriority).Where(x => q.Status is null || x.CurrentStatus == q.Status).Where(x => q.Disposition is null || x.Disposition == q.Disposition).Where(x => q.Assignee is null || x.Assignee == q.Assignee).Where(x => q.Team is null || x.Team == q.Team).Where(x => !q.Unassigned || x.Assignee is null && x.Team is null).Where(x => q.EndpointId is null || x.Evidence.EndpointIds.Contains(q.EndpointId.Value)).Where(x => q.User is null || x.Evidence.Users.Contains(q.User)).Where(x => q.RuleId is null || x.RuleId == q.RuleId).Where(x => q.MitreTechnique is null || x.MitreTechniques.Contains(q.MitreTechnique)).Where(x => q.EvidenceQuality is null || x.Evidence.TelemetryQuality.Contains(q.EvidenceQuality)).Where(x => q.From is null || x.LastSeen >= q.From).Where(x => q.To is null || x.FirstSeen <= q.To).ToArray();
        var ordered = q.Sort switch { "priority-desc" => values.OrderByDescending(x => x.Priority).ThenByDescending(x => x.LastSeen), "age-desc" => values.OrderBy(x => x.CreatedAt).ThenBy(x => x.AlertId), "updated-asc" => values.OrderBy(x => x.LastSeen).ThenBy(x => x.AlertId), _ => values.OrderByDescending(x => x.LastSeen).ThenBy(x => x.AlertId) }; var offset = q.Cursor is null ? 0 : int.TryParse(TenantCursor.Unprotect(tenant, q.Cursor), out var parsed) ? parsed : throw new EnrollmentConflictException("CURSOR_INVALID", "Cursor offset is invalid."); var page = ordered.Skip(offset).Take(q.PageSize).ToArray(); return new(page, offset + page.Length < values.Length ? TenantCursor.Protect(tenant, (offset + page.Length).ToString(System.Globalization.CultureInfo.InvariantCulture)) : null, values.Length);
    }

    public async Task<AlertRecord> MutateAlertAsync(string tenant, Guid id, string actor, AlertMutation m, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try
        {
            var old = await GetAlertAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var nextStatus = m.Status ?? old.CurrentStatus; if (!AlertIncidentSafety.CanTransition(old.CurrentStatus, nextStatus)) { _health.GetOrAdd(tenant, _ => new long[12])[7]++; throw new EnrollmentConflictException("ALERT_TRANSITION_INVALID", $"{old.CurrentStatus} cannot transition to {nextStatus}."); }
            if (nextStatus == AlertStatus.Closed && (m.Disposition ?? old.Disposition) == AlertDisposition.None) throw new EnrollmentConflictException("DISPOSITION_REQUIRED", "Closing an alert requires an explicit disposition."); if (m.Severity is < 0 or > 100 || m.Priority is < 1 or > 5) throw new EnrollmentConflictException("CLASSIFICATION_BOUNDS", "Severity must be 0-100 and priority 1-5."); var now = DateTimeOffset.UtcNow; var before = new Dictionary<string, string?> { ["status"] = old.CurrentStatus.ToString(), ["disposition"] = old.Disposition.ToString(), ["assignee"] = old.Assignee, ["team"] = old.Team }; var after = new Dictionary<string, string?> { ["status"] = nextStatus.ToString(), ["disposition"] = (m.Disposition ?? old.Disposition).ToString(), ["assignee"] = m.Assignee ?? old.Assignee, ["team"] = m.Team ?? old.Team }; var assignmentChanged = (m.Assignee is not null && m.Assignee != old.Assignee) || (m.Team is not null && m.Team != old.Team); var dispositionChanged = m.Disposition is not null && m.Disposition != old.Disposition; var action = nextStatus != old.CurrentStatus ? "alert.status.changed" : assignmentChanged ? "alert.assignment.changed" : dispositionChanged ? "alert.disposition.changed" : "alert.classification.changed"; var audit = Audit(tenant, "alert", id, old.Version + 1, action, actor, m.Reason, before, after);
            var value = old with { CurrentStatus = nextStatus, Disposition = m.Disposition ?? old.Disposition, Assignee = m.Assignee ?? old.Assignee, Team = m.Team ?? old.Team, Severity = m.Severity ?? old.Severity, Priority = m.Priority ?? old.Priority, AcknowledgedAt = nextStatus == AlertStatus.Acknowledged && old.AcknowledgedAt is null ? now : old.AcknowledgedAt, AssignedAt = (m.Assignee is not null || m.Team is not null) && old.AssignedAt is null ? now : old.AssignedAt, InvestigationStartedAt = nextStatus == AlertStatus.Investigating && old.InvestigationStartedAt is null ? now : old.InvestigationStartedAt, ResolvedAt = nextStatus == AlertStatus.Resolved ? now : old.ResolvedAt, ClosedAt = nextStatus == AlertStatus.Closed ? now : nextStatus == AlertStatus.Investigating ? null : old.ClosedAt, ReopenedAt = old.CurrentStatus == AlertStatus.Closed && nextStatus == AlertStatus.Investigating ? now : old.ReopenedAt, ReopenCount = old.CurrentStatus == AlertStatus.Closed && nextStatus == AlertStatus.Investigating ? old.ReopenCount + 1 : old.ReopenCount, LastEditor = actor, Version = old.Version + 1, AuditHistory = old.AuditHistory.Append(audit).ToArray() };
            await PersistAlertAsync(value, audit, ct); var h = _health.GetOrAdd(tenant, _ => new long[12]); if (nextStatus == AlertStatus.Closed && old.CurrentStatus != AlertStatus.Closed) h[2]++; if (old.CurrentStatus == AlertStatus.Closed && nextStatus == AlertStatus.Investigating) h[3]++; return value;
        }
        finally { _gate.Release(); }
    }

    public async Task<AnalystNote> AddAlertNoteAsync(string tenant, Guid id, string actor, AnalystNoteKind kind, string content, CancellationToken ct)
    {
        var text = AlertIncidentSafety.PlainText(content); await _gate.WaitAsync(ct); try { var old = await GetAlertAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var audit = Audit(tenant, "alert", id, old.Version + 1, "alert.note.added", actor, kind.ToString()); var note = new AnalystNote(Guid.NewGuid(), tenant, "alert", id, kind, actor, text, 1, DateTimeOffset.UtcNow, audit.AuditId); var value = old with { Comments = old.Comments.Append(note).ToArray(), LastEditor = actor, Version = old.Version + 1, AuditHistory = old.AuditHistory.Append(audit).ToArray() }; await PersistAlertAsync(value, audit, ct); return note; } finally { _gate.Release(); }
    }
    public async Task<IReadOnlyList<LifecycleAuditEvent>> AlertAuditAsync(string tenant, Guid id, CancellationToken ct) => (await GetAlertAsync(tenant, id, ct))?.AuditHistory ?? [];
    public async Task<AlertRecord[]> BulkMutateAlertsAsync(string tenant, string actor, Guid[] ids, AlertMutation mutation, CancellationToken ct) { if (ids.Length is < 1 or > AlertIncidentSafety.MaximumBulk || ids.Distinct().Count() != ids.Length) throw new EnrollmentConflictException("BULK_BOUNDS", $"Bulk actions require 1-{AlertIncidentSafety.MaximumBulk} distinct alerts."); var output = new List<AlertRecord>(); foreach (var id in ids) output.Add(await MutateAlertAsync(tenant, id, actor, mutation, ct)); return output.ToArray(); }

    public async Task<IncidentRecord> CreateIncidentAsync(string tenant, string actor, IncidentCreate input, CancellationToken ct)
    {
        if (input.AlertIds.Length is < 1 or > AlertIncidentSafety.MaximumIncidentAlerts || input.AlertIds.Distinct().Count() != input.AlertIds.Length) throw new EnrollmentConflictException("INCIDENT_ALERT_BOUNDS", $"Incident requires 1-{AlertIncidentSafety.MaximumIncidentAlerts} distinct alerts."); var alerts = (await LoadAlertsAsync(tenant, ct)).Where(x => input.AlertIds.Contains(x.AlertId)).ToArray(); if (alerts.Length != input.AlertIds.Length) { _health.GetOrAdd(tenant, _ => new long[12])[9]++; throw new EnrollmentConflictException("INCIDENT_ALERT_INVALID", "Every incident alert must exist in the same tenant."); }
        var id = Guid.NewGuid(); var now = DateTimeOffset.UtcNow; var audit = Audit(tenant, "incident", id, 1, "incident.created", actor, input.GroupingReason, after: new() { ["alertCount"] = alerts.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) }); var value = Aggregate(new IncidentRecord("incident.v1", id, tenant, AlertIncidentSafety.PlainText(input.Title), AlertIncidentSafety.PlainText(input.Summary), alerts.Max(x => x.Severity), alerts.Max(x => x.Priority), (int)alerts.Average(x => x.Confidence), IncidentStatus.New, AlertDisposition.None, actor, input.Team, input.Assignee, now, now, null, null, 0, 1, input.AlertIds, [], [], [], [], [], [], [], [], [], input.GroupingReason, [], [audit]), alerts);
        await PersistIncidentAsync(value, audit, ct); var h = _health.GetOrAdd(tenant, _ => new long[12]); h[4]++; h[8]++; return value;
    }
    static IncidentRecord Aggregate(IncidentRecord value, IReadOnlyList<AlertRecord> alerts) => value with { Severity = alerts.Count == 0 ? value.Severity : alerts.Max(x => x.Severity), Priority = alerts.Count == 0 ? value.Priority : alerts.Max(x => x.Priority), Confidence = alerts.Count == 0 ? value.Confidence : (int)alerts.Average(x => x.Confidence), EndpointIds = alerts.SelectMany(x => x.Evidence.EndpointIds).Distinct().ToArray(), Users = alerts.SelectMany(x => x.Evidence.Users).Distinct().ToArray(), ProcessEntities = alerts.SelectMany(x => x.Evidence.ProcessEntities).Distinct().ToArray(), Files = alerts.SelectMany(x => x.Evidence.Files).Distinct().ToArray(), NetworkDnsEntities = alerts.SelectMany(x => x.Evidence.NetworkDnsEntities).Distinct().ToArray(), PersistenceEntities = alerts.SelectMany(x => x.Evidence.PersistenceEntities).Distinct().ToArray(), MitreTechniques = alerts.SelectMany(x => x.MitreTechniques).Distinct().ToArray(), AttackStoryIds = alerts.SelectMany(x => x.Evidence.AttackStoryIds).Distinct().ToArray(), EvidenceReferences = alerts.SelectMany(x => x.Evidence.EvidenceReferences).Distinct().ToArray() };
    public async Task<IncidentRecord?> GetIncidentAsync(string tenant, Guid id, CancellationToken ct) => (await LoadIncidentsAsync(tenant, ct)).FirstOrDefault(x => x.IncidentId == id);
    public async Task<IncidentPage> SearchIncidentsAsync(string tenant, IncidentQuery q, CancellationToken ct) { if (q.PageSize is < 1 or > 200) throw new EnrollmentConflictException("PAGE_BOUNDS", "Page size must be 1-200."); var values = (await LoadIncidentsAsync(tenant, ct)).Where(x => q.Status is null || x.Status == q.Status).Where(x => q.Assignee is null || x.Assignee == q.Assignee).Where(x => q.Team is null || x.Team == q.Team).Where(x => q.Priority is null || x.Priority == q.Priority).OrderByDescending(x => x.UpdatedAt).ThenBy(x => x.IncidentId).ToArray(); var offset = q.Cursor is null ? 0 : int.Parse(TenantCursor.Unprotect(tenant, q.Cursor), System.Globalization.CultureInfo.InvariantCulture); var page = values.Skip(offset).Take(q.PageSize).ToArray(); return new(page, offset + page.Length < values.Length ? TenantCursor.Protect(tenant, (offset + page.Length).ToString(System.Globalization.CultureInfo.InvariantCulture)) : null, values.Length); }
    public async Task<IncidentRecord> MutateIncidentAsync(string tenant, Guid id, string actor, IncidentMutation m, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var old = await GetIncidentAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var status = m.Status ?? old.Status; if (!AlertIncidentSafety.CanTransition(old.Status, status)) { _health.GetOrAdd(tenant, _ => new long[12])[7]++; throw new EnrollmentConflictException("INCIDENT_TRANSITION_INVALID", $"{old.Status} cannot transition to {status}."); } if (status == IncidentStatus.Closed && (m.Disposition ?? old.Disposition) == AlertDisposition.None) throw new EnrollmentConflictException("DISPOSITION_REQUIRED", "Closing an incident requires an explicit disposition."); var assignmentChanged = (m.Assignee is not null && m.Assignee != old.Assignee) || (m.Team is not null && m.Team != old.Team); var dispositionChanged = m.Disposition is not null && m.Disposition != old.Disposition; var action = status != old.Status ? "incident.status.changed" : assignmentChanged ? "incident.assignment.changed" : dispositionChanged ? "incident.disposition.changed" : "incident.modified"; var audit = Audit(tenant, "incident", id, old.Version + 1, action, actor, m.Reason, new() { ["status"] = old.Status.ToString(), ["disposition"] = old.Disposition.ToString() }, new() { ["status"] = status.ToString(), ["disposition"] = (m.Disposition ?? old.Disposition).ToString() }); var now = DateTimeOffset.UtcNow; var value = old with { Status = status, Disposition = m.Disposition ?? old.Disposition, Assignee = m.Assignee ?? old.Assignee, Team = m.Team ?? old.Team, Severity = m.Severity ?? old.Severity, Priority = m.Priority ?? old.Priority, Title = m.Title is null ? old.Title : AlertIncidentSafety.PlainText(m.Title), Summary = m.Summary is null ? old.Summary : AlertIncidentSafety.PlainText(m.Summary), UpdatedAt = now, ClosedAt = status == IncidentStatus.Closed ? now : status == IncidentStatus.Investigating ? null : old.ClosedAt, ReopenedAt = old.Status == IncidentStatus.Closed && status == IncidentStatus.Investigating ? now : old.ReopenedAt, ReopenCount = old.Status == IncidentStatus.Closed && status == IncidentStatus.Investigating ? old.ReopenCount + 1 : old.ReopenCount, Version = old.Version + 1, AuditHistory = old.AuditHistory.Append(audit).ToArray() }; await PersistIncidentAsync(value, audit, ct); if (status == IncidentStatus.Closed && old.Status != IncidentStatus.Closed) _health.GetOrAdd(tenant, _ => new long[12])[5]++; return value; } finally { _gate.Release(); }
    }
    public async Task<IncidentRecord> LinkAlertsAsync(string tenant, Guid id, string actor, Guid[] alertIds, bool remove, string reason, CancellationToken ct)
    {
        if (alertIds.Length is < 1 or > AlertIncidentSafety.MaximumBulk) throw new EnrollmentConflictException("LINK_BOUNDS", "Link operation is bounded to 1-100 alerts."); await _gate.WaitAsync(ct); try { var old = await GetIncidentAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var all = await LoadAlertsAsync(tenant, ct); if (all.Count(x => alertIds.Contains(x.AlertId)) != alertIds.Distinct().Count()) throw new EnrollmentConflictException("INCIDENT_ALERT_INVALID", "Linked alerts must exist in the same tenant."); var ids = remove ? old.AlertIds.Except(alertIds).ToArray() : old.AlertIds.Concat(alertIds).Distinct().ToArray(); if (ids.Length is < 1 or > AlertIncidentSafety.MaximumIncidentAlerts) throw new EnrollmentConflictException("INCIDENT_ALERT_BOUNDS", "Incident alert count is outside bounds."); var audit = Audit(tenant, "incident", id, old.Version + 1, remove ? "incident.alerts.unlinked" : "incident.alerts.linked", actor, reason, after: new() { ["alertCount"] = ids.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) }); var value = Aggregate(old with { AlertIds = ids, UpdatedAt = DateTimeOffset.UtcNow, Version = old.Version + 1, AuditHistory = old.AuditHistory.Append(audit).ToArray() }, all.Where(x => ids.Contains(x.AlertId)).ToArray()); await PersistIncidentAsync(value, audit, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<IncidentRecord> MergeIncidentsAsync(string tenant, Guid target, Guid source, string actor, string reason, CancellationToken ct)
    {
        if (target == source) throw new EnrollmentConflictException("INCIDENT_MERGE_INVALID", "An incident cannot merge into itself."); var sourceValue = await GetIncidentAsync(tenant, source, ct) ?? throw new KeyNotFoundException(); var merged = await LinkAlertsAsync(tenant, target, actor, sourceValue.AlertIds, false, $"merge:{source:D}:{reason}", ct); var state = sourceValue;
        if (state.Status == IncidentStatus.New) state = await MutateIncidentAsync(tenant, source, actor, new(Status: IncidentStatus.Triage, Reason: $"merge-source:{target:D}:{reason}"), ct);
        if (state.Status == IncidentStatus.Triage) state = await MutateIncidentAsync(tenant, source, actor, new(Status: IncidentStatus.Investigating, Reason: $"merge-source:{target:D}:{reason}"), ct);
        if (state.Status is IncidentStatus.Investigating or IncidentStatus.Contained) state = await MutateIncidentAsync(tenant, source, actor, new(Status: IncidentStatus.Resolved, Disposition: AlertDisposition.Duplicate, Reason: $"merge-source:{target:D}:{reason}"), ct);
        if (state.Status == IncidentStatus.Resolved) await MutateIncidentAsync(tenant, source, actor, new(Status: IncidentStatus.Closed, Disposition: AlertDisposition.Duplicate, Reason: $"merged-into:{target:D}:{reason}"), ct); return merged;
    }
    public async Task<IncidentRecord> SplitIncidentAsync(string tenant, Guid source, string actor, Guid[] alertIds, string title, string reason, CancellationToken ct) { var original = await GetIncidentAsync(tenant, source, ct) ?? throw new KeyNotFoundException(); if (alertIds.Length == 0 || alertIds.Any(x => !original.AlertIds.Contains(x)) || alertIds.Length >= original.AlertIds.Length) throw new EnrollmentConflictException("INCIDENT_SPLIT_INVALID", "Split must move a non-empty proper subset of source alerts."); var created = await CreateIncidentAsync(tenant, actor, new(title, $"Split from {source:D}", alertIds, original.Team, original.Assignee, $"split:{source:D}:{reason}"), ct); await LinkAlertsAsync(tenant, source, actor, alertIds, true, $"split-to:{created.IncidentId:D}:{reason}", ct); return created; }
    public async Task<AnalystNote> AddIncidentNoteAsync(string tenant, Guid id, string actor, AnalystNoteKind kind, string content, CancellationToken ct) { var text = AlertIncidentSafety.PlainText(content); await _gate.WaitAsync(ct); try { var old = await GetIncidentAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var audit = Audit(tenant, "incident", id, old.Version + 1, "incident.note.added", actor, kind.ToString()); var note = new AnalystNote(Guid.NewGuid(), tenant, "incident", id, kind, actor, text, 1, DateTimeOffset.UtcNow, audit.AuditId); var value = old with { Comments = old.Comments.Append(note).ToArray(), UpdatedAt = DateTimeOffset.UtcNow, Version = old.Version + 1, AuditHistory = old.AuditHistory.Append(audit).ToArray() }; await PersistIncidentAsync(value, audit, ct); return note; } finally { _gate.Release(); } }
    public async Task<IReadOnlyList<LifecycleAuditEvent>> IncidentAuditAsync(string tenant, Guid id, CancellationToken ct) => (await GetIncidentAsync(tenant, id, ct))?.AuditHistory ?? [];
    public async Task RecordExportAuditAsync(string tenant, string objectType, Guid objectId, Guid exportId, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try
        {
            if (objectType == "alert") { var old = await GetAlertAsync(tenant, objectId, ct) ?? throw new KeyNotFoundException(); var audit = Audit(tenant, "alert", objectId, old.Version + 1, "alert.export.created", actor, $"export:{exportId:D}"); await PersistAlertAsync(old with { Version = old.Version + 1, LastEditor = actor, AuditHistory = old.AuditHistory.Append(audit).ToArray() }, audit, ct); }
            else if (objectType == "incident") { var old = await GetIncidentAsync(tenant, objectId, ct) ?? throw new KeyNotFoundException(); var audit = Audit(tenant, "incident", objectId, old.Version + 1, "incident.export.created", actor, $"export:{exportId:D}"); await PersistIncidentAsync(old with { Version = old.Version + 1, UpdatedAt = DateTimeOffset.UtcNow, AuditHistory = old.AuditHistory.Append(audit).ToArray() }, audit, ct); }
            else throw new EnrollmentConflictException("EXPORT_OBJECT_INVALID", "Export object must be alert or incident.");
        }
        finally { _gate.Release(); }
    }
    public async Task<SavedTriageFilter> SaveFilterAsync(string tenant, string actor, SavedTriageFilter filter, CancellationToken ct) { if (filter.TenantId != tenant || filter.Owner != actor && filter.FilterId != Guid.Empty) throw new EnrollmentConflictException("FILTER_OWNERSHIP", "Saved filter owner mismatch."); var value = filter with { FilterId = filter.FilterId == Guid.Empty ? Guid.NewGuid() : filter.FilterId, TenantId = tenant, Owner = actor, Version = Math.Max(1, filter.Version), CreatedAt = DateTimeOffset.UtcNow, Name = AlertIncidentSafety.PlainText(filter.Name) }; await PersistFilterAsync(value, ct); return value; }
    public virtual async Task<IReadOnlyList<SavedTriageFilter>> FiltersAsync(string tenant, string actor, CancellationToken ct) => (await LoadFiltersAsync(tenant, actor, ct)).OrderBy(x => x.Name).ToArray();
    public virtual Task<TriageHealth> HealthAsync(string tenant, CancellationToken ct) { var h = _health.GetOrAdd(tenant, _ => new long[12]); return Task.FromResult(new TriageHealth(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], 0, DateTimeOffset.UtcNow)); }
    public void Dispose() { _gate.Dispose(); GC.SuppressFinalize(this); }
}
