using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OpenSecurityPlatform.Foundation;

public static class RetentionCategories
{
    public static readonly string[] All = ["raw-telemetry", "search-projection", "findings", "correlated-findings", "alerts-incidents", "response-audit", "live-response-transcripts", "forensic-evidence", "quarantine-artifacts", "threat-intelligence", "update-artifacts", "audit-records", "temporary-data"];
}

public sealed record RetentionPolicy(Guid PolicyId, string TenantId, int Version, string Category,
    int AuthorityDays, int ProjectionDays, int BatchSize, bool ArchiveBeforeDelete, bool Enabled,
    DateTimeOffset CreatedAt, string CreatedBy, string PreviousHash, string PolicyHash);
public sealed record RetentionPolicyRequest(string Category, int AuthorityDays, int ProjectionDays,
    int BatchSize, bool ArchiveBeforeDelete, bool Enabled);
public sealed record RetentionHold(Guid HoldId, string TenantId, string HoldType, string Category,
    string? TargetId, string Reason, bool Active, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, string CreatedBy);
public sealed record RetentionHoldRequest(string HoldType, string Category, string? TargetId, string Reason, DateTimeOffset? ExpiresAt);
public sealed record RetentionPreview(Guid PreviewId, string TenantId, Guid PolicyId, int PolicyVersion,
    string Scope, DateTimeOffset Cutoff, long EligibleRows, long EstimatedBytes, long HeldRows,
    string PreviewHash, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);
public sealed record RetentionRun(Guid RunId, string TenantId, Guid PreviewId, Guid PolicyId, int PolicyVersion,
    string State, bool DryRun, long DeletedRows, long ArchivedRows, long HeldRows,
    DateTimeOffset StartedAt, DateTimeOffset? CompletedAt, string Actor, string Detail);
public sealed record RetentionFixture(Guid RecordId, string TenantId, string Category, DateTimeOffset OccurredAt,
    int PayloadBytes, bool ActiveReference, string ContentHash);
public sealed record ArchiveJob(Guid ArchiveId, string TenantId, Guid PolicyId, int PolicyVersion, string Scope,
    DateTimeOffset From, DateTimeOffset To, long RecordCount, string[] SchemaVersions, string ManifestHash,
    string State, DateTimeOffset CreatedAt);
public sealed record CleanupHistory(Guid CleanupId, string TenantId, string Category, long ItemCount,
    long BytesReclaimed, long HeldItems, string State, DateTimeOffset OccurredAt, string Actor, string Detail);

public sealed record TenantCapacityQuota(string TenantId, int Version, int IngestPerMinute, int SearchPerMinute,
    int ReplayPerMinute, int ExportPerMinute, int ForensicPerMinute, int PlaybookPerMinute, int UpdatePerMinute,
    int MaxConcurrentForensic, int MaxConcurrentPlaybooks, DateTimeOffset CreatedAt, string CreatedBy, string PolicyHash);
public sealed record TenantCapacityQuotaRequest(int IngestPerMinute, int SearchPerMinute, int ReplayPerMinute,
    int ExportPerMinute, int ForensicPerMinute, int PlaybookPerMinute, int UpdatePerMinute,
    int MaxConcurrentForensic, int MaxConcurrentPlaybooks);
public sealed record TenantQuotaDecision(bool Allowed, string Category, int Limit, int Used, DateTimeOffset WindowEndsAt);

public sealed record StorageDomainUsage(string Domain, long Records, long PostgreSqlBytes, long OpenSearchBytes, long MinioBytes);
public sealed record CapacitySample(Guid SampleId, DateTimeOffset CapturedAt, string PlatformVersion, string Profile,
    decimal DurationSeconds, int SimulatedEndpoints, int NativeAgents, long GeneratedEvents, long AcceptedEvents,
    long RejectedEvents, long DuplicateEvents, long UnexplainedLoss, decimal EventsPerSecond,
    long PostgreSqlBytes, long OpenSearchBytes, long MinioBytes, long NatsBytes,
    IReadOnlyDictionary<string, string> Environment, IReadOnlyDictionary<string, decimal> Measurements);
public sealed record CapacityOperationalMetrics(long RetentionDeleted, long RetentionHeld, long CleanupFailures,
    long TenantThrottled, long TemporaryBytes, long ActiveHolds);
public sealed record CapacityPlannerInput(long EndpointCount, long EventsPerEndpointDay, int RetentionDays,
    decimal PostgreSqlBytesPerEvent, decimal OpenSearchBytesPerEvent, long ForensicBytesPerEndpointDay,
    decimal RedundancyFactor, decimal RequiredMarginPercent);
public sealed record CapacityPlannerEstimate(long DailyEvents, decimal DailyIngestBytes, decimal PostgreSqlBytes,
    decimal OpenSearchBytes, decimal MinioBytes, decimal TotalWithMarginBytes, string Basis);

public interface ICapacityRetentionRepository
{
    Task<RetentionPolicy> PutPolicyAsync(string tenant, string actor, Guid? policyId, RetentionPolicyRequest request, CancellationToken ct);
    Task<IReadOnlyList<RetentionPolicy>> PoliciesAsync(string tenant, CancellationToken ct);
    Task<RetentionHold> PutHoldAsync(string tenant, string actor, RetentionHoldRequest request, CancellationToken ct);
    Task<RetentionHold> ReleaseHoldAsync(string tenant, Guid holdId, CancellationToken ct);
    Task<IReadOnlyList<RetentionHold>> HoldsAsync(string tenant, CancellationToken ct);
    Task<RetentionPreview> PreviewAsync(string tenant, Guid policyId, string scope, CancellationToken ct);
    Task<RetentionRun> ExecuteAsync(string tenant, string actor, Guid previewId, string previewHash, bool dryRun, CancellationToken ct);
    Task<IReadOnlyList<RetentionRun>> RunsAsync(string tenant, CancellationToken ct);
    Task<IReadOnlyList<ArchiveJob>> ArchivesAsync(string tenant, CancellationToken ct);
    Task<IReadOnlyList<CleanupHistory>> CleanupAsync(string tenant, CancellationToken ct);
    Task<IReadOnlyList<StorageDomainUsage>> StorageAsync(string tenant, CancellationToken ct);
    Task<CapacitySample> RecordCapacityAsync(CapacitySample value, CancellationToken ct);
    Task<IReadOnlyList<CapacitySample>> CapacityAsync(int limit, CancellationToken ct);
    Task<CapacityOperationalMetrics> OperationalMetricsAsync(CancellationToken ct);
    Task<TenantCapacityQuota> PutQuotaAsync(string tenant, string actor, TenantCapacityQuotaRequest request, CancellationToken ct);
    Task<TenantCapacityQuota> QuotaAsync(string tenant, CancellationToken ct);
    Task<TenantQuotaDecision> ConsumeAsync(string tenant, string category, int units, CancellationToken ct);
    Task SeedFixturesAsync(string tenant, IReadOnlyList<RetentionFixture> fixtures, CancellationToken ct);
    Task<IReadOnlyList<RetentionFixture>> FixturesAsync(string tenant, CancellationToken ct);
}

public static class CapacityRetentionSafety
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    public static void Validate(RetentionPolicyRequest x)
    {
        if (!RetentionCategories.All.Contains(x.Category, StringComparer.Ordinal) || x.AuthorityDays is < 1 or > 36500 ||
            x.ProjectionDays is < 1 or > 36500 || x.ProjectionDays > x.AuthorityDays || x.BatchSize is < 1 or > 5000)
            throw new EnrollmentConflictException("RETENTION_POLICY_INVALID", "Retention category, duration, projection boundary, or batch size is invalid.");
    }
    public static void Validate(RetentionHoldRequest x, DateTimeOffset now)
    {
        if (x.HoldType is not ("incident" or "forensic" or "quarantine" or "legal" or "administrative" or "replay" or "export" or "investigation") ||
            !RetentionCategories.All.Contains(x.Category, StringComparer.Ordinal) || string.IsNullOrWhiteSpace(x.Reason) || x.Reason.Length > 1024 ||
            x.TargetId?.Length > 256 || x.ExpiresAt is { } expiry && (expiry <= now || expiry > now.AddDays(36500)))
            throw new EnrollmentConflictException("RETENTION_HOLD_INVALID", "Retention hold type, category, target, reason, or expiry is invalid.");
    }
    public static void Validate(TenantCapacityQuotaRequest x)
    {
        var rates = new[] { x.IngestPerMinute, x.SearchPerMinute, x.ReplayPerMinute, x.ExportPerMinute, x.ForensicPerMinute, x.PlaybookPerMinute, x.UpdatePerMinute };
        if (rates.Any(v => v is < 1 or > 1_000_000) || x.MaxConcurrentForensic is < 1 or > 100 || x.MaxConcurrentPlaybooks is < 1 or > 100)
            throw new EnrollmentConflictException("CAPACITY_QUOTA_INVALID", "Tenant rate or concurrency quota is outside bounded limits.");
    }
    public static CapacityPlannerEstimate Estimate(CapacityPlannerInput x)
    {
        if (x.EndpointCount is < 1 or > 10_000_000 || x.EventsPerEndpointDay is < 1 or > 10_000_000 || x.RetentionDays is < 1 or > 3650 ||
            x.PostgreSqlBytesPerEvent is <= 0 or > 10_000_000 || x.OpenSearchBytesPerEvent is < 0 or > 10_000_000 ||
            x.ForensicBytesPerEndpointDay is < 0 or > 1_000_000_000_000 || x.RedundancyFactor is < 1 or > 10 || x.RequiredMarginPercent is < 0 or > 500)
            throw new EnrollmentConflictException("CAPACITY_PLANNER_BOUNDS", "Capacity planner input exceeds defensible numeric bounds.");
        try
        {
            var events = checked(x.EndpointCount * x.EventsPerEndpointDay); var days = (decimal)x.RetentionDays;
            var pg = checked(events * x.PostgreSqlBytesPerEvent * days * x.RedundancyFactor);
            var os = checked(events * x.OpenSearchBytesPerEvent * days * x.RedundancyFactor);
            var minio = checked((decimal)x.EndpointCount * x.ForensicBytesPerEndpointDay * days * x.RedundancyFactor);
            var daily = checked(events * (x.PostgreSqlBytesPerEvent + x.OpenSearchBytesPerEvent));
            var total = checked((pg + os + minio) * (1 + x.RequiredMarginPercent / 100));
            return new(events, daily, pg, os, minio, total, "Estimate from measured Sprint 29 profile/version inputs; not a physical endpoint-scale claim.");
        }
        catch (OverflowException) { throw new EnrollmentConflictException("CAPACITY_PLANNER_OVERFLOW", "Capacity estimate exceeds supported numeric range."); }
    }
    public static TenantCapacityQuota DefaultQuota(string tenant) { var now = DateTimeOffset.UtcNow; var q = new TenantCapacityQuota(tenant, 1, 120000, 6000, 60, 300, 6000, 300, 300, 4, 8, now, "system", ""); return q with { PolicyHash = Hash(q with { PolicyHash = "", CreatedAt = default, CreatedBy = "" }) }; }
    public static RetentionFixture Fixture(string tenant, string category, Guid id, DateTimeOffset at, int bytes, bool referenced)
    { var x = new RetentionFixture(id, tenant, category, at, bytes, referenced, ""); return x with { ContentHash = Hash(x with { ContentHash = "" }) }; }
    public static Guid StableFixtureId(string tenant, int ordinal) => new(SHA256.HashData(Encoding.UTF8.GetBytes($"sprint29\n{tenant}\n{ordinal}"))[..16]);
}
