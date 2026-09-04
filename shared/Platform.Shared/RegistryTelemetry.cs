using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<RegistryEventKind>))]
public enum RegistryEventKind
{
    KeyCreated,
    KeyDeleted,
    KeyRenamed,
    ValueSet,
    ValueDeleted,
    KeySecurityChanged,
}

[JsonConverter(typeof(JsonStringEnumConverter<RegistryEntityState>))]
public enum RegistryEntityState
{
    Present,
    Deleted,
    Renamed,
    Recreated,
    Unknown,
    IncompleteHistory,
}

[JsonConverter(typeof(JsonStringEnumConverter<RegistryCaptureMode>))]
public enum RegistryCaptureMode
{
    None,
    MetadataOnly,
    ContentHash,
    BoundedPreview,
    ApprovedFullContent,
}

public sealed record RegistryProcessRelationship(
    string? ProcessEntityId,
    int? ProcessId,
    DateTimeOffset? ProcessStartTime,
    string? Image,
    string? Path,
    string? CommandLine,
    string? UserSid,
    int? SessionId,
    int? ThreadId,
    string Source,
    string Confidence
);

public sealed record RegistryValueMetadata(
    string? ValueType,
    int? DataLength,
    bool DataPresent,
    RegistryCaptureMode CaptureMode,
    int CapturedLength,
    bool Truncated,
    bool Redacted,
    string? Sha256,
    string? PreviousSha256,
    string? Encoding,
    string? Preview,
    string Classification,
    DateTimeOffset? CapturedAt,
    string? PolicyVersion,
    string? FailureReason,
    string? HashAlgorithm = null
)
{
    public static RegistryValueMetadata MetadataOnly(string? failure = null) =>
        new(
            null,
            null,
            false,
            RegistryCaptureMode.MetadataOnly,
            0,
            false,
            false,
            null,
            null,
            null,
            null,
            "unknown",
            null,
            null,
            failure
        );
}

public sealed record RegistryObservation(
    Guid EventId,
    string SchemaVersion,
    RegistryEventKind Kind,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    string CollectorId,
    string CollectorSource,
    string CollectorVersion,
    string SourcePlatform,
    string? SourceEventId,
    long Sequence,
    DateTimeOffset ObservedAt,
    string NormalizationVersion,
    string? RawSha256,
    string? CorrelationId,
    string? TraceId,
    string[] DataQualityFlags,
    string SourceConfidence,
    string RegistryKeyEntityId,
    string? RegistryValueEntityId,
    string Hive,
    ulong? NativeKeyHandle,
    string KeyPath,
    string? ParentKeyPath,
    string? PreviousKeyPath,
    string? DestinationKeyPath,
    string? ValueName,
    string RegistryView,
    string VirtualizationState,
    string TransactionState,
    string NativeOperation,
    int? NativeStatus,
    string? OperationResult,
    uint? AccessMask,
    uint? DesiredAccess,
    string? Disposition,
    bool? Deleted,
    RegistryValueMetadata Value,
    RegistryProcessRelationship? Process,
    string? UserSid,
    bool Late = false,
    DateTimeOffset? ReceivedAt = null,
    DateTimeOffset? IngestedAt = null
)
{
    public static string StableKeyEntityId(
        Guid endpointId,
        string hive,
        string path,
        DateTimeOffset instanceStart
    ) => Stable(endpointId, $"key:{hive}:{path}:{instanceStart.UtcTicks}");

    public static string StableValueEntityId(
        Guid endpointId,
        string keyEntityId,
        string valueName,
        DateTimeOffset instanceStart
    ) => Stable(endpointId, $"value:{keyEntityId}:{valueName}:{instanceStart.UtcTicks}");

    private static string Stable(Guid endpointId, string material) =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes($"{endpointId:D}:{material}"))
        ).ToLowerInvariant();
}

public sealed record RegistryEventBatch(
    Guid BatchId,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    long FirstSequence,
    long LastSequence,
    IReadOnlyList<RegistryObservation> Events,
    string ContentSha256,
    string SchemaVersion = "registry-batch.v1",
    string Compression = "gzip",
    int UncompressedBytes = 0,
    int CompressedBytes = 0,
    string CapabilityVersion = "registry.v1"
);

public sealed record RegistryBatchAcknowledgement(
    Guid BatchId,
    IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds,
    IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough,
    bool GapDetected
);

public sealed record RegistryIngestResult(
    RegistryBatchAcknowledgement Acknowledgement,
    int Accepted,
    int Duplicates,
    int Rejected,
    int SequenceGaps
);

public sealed record RegistryKeyView(
    string TenantId,
    Guid EndpointId,
    string RegistryKeyEntityId,
    string Hive,
    string CurrentKeyPath,
    IReadOnlyList<string> PreviousPaths,
    string? ParentKeyPath,
    DateTimeOffset FirstObserved,
    DateTimeOffset LastObserved,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? DeletedAt,
    RegistryEntityState State,
    Guid LatestEventId,
    string SourceConfidence,
    string[] DataQualityFlags,
    RegistryProcessRelationship? LatestProcess,
    string? UserSid
);

public sealed record RegistryValueView(
    string TenantId,
    Guid EndpointId,
    string RegistryValueEntityId,
    string RegistryKeyEntityId,
    string Hive,
    string KeyPath,
    string ValueName,
    RegistryValueMetadata Value,
    DateTimeOffset FirstObserved,
    DateTimeOffset LastObserved,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? DeletedAt,
    RegistryEntityState State,
    Guid LatestEventId,
    string SourceConfidence,
    string[] DataQualityFlags,
    RegistryProcessRelationship? LatestProcess,
    string? UserSid
);

public sealed record RegistrySearchRequest(
    Guid? EndpointId = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    string? Hive = null,
    string? KeyPath = null,
    string? ValueName = null,
    RegistryEventKind? Operation = null,
    string? Process = null,
    string? User = null,
    string? ValueType = null,
    string? Collector = null,
    string? DataQuality = null,
    string? ContentHash = null,
    int PageSize = 100,
    string? Cursor = null
);

public sealed record RegistryEventPage(
    IReadOnlyList<RegistryObservation> Items,
    string? NextCursor
);

public sealed record RegistryKeyPage(IReadOnlyList<RegistryKeyView> Items, string? NextCursor);
public sealed record RegistryValuePage(IReadOnlyList<RegistryValueView> Items, string? NextCursor);

public sealed record RegistryProjectionRebuildProgress(
    Guid RebuildId,
    string TargetVersion,
    string Scope,
    string State,
    DateTimeOffset StartedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? CompletedAt,
    int PostgreSqlSourceCount,
    int IndexedCount,
    int FailureCount,
    string CurrentAlias,
    string? ErrorSummary,
    bool RollbackAvailable
);

public sealed record RegistryTelemetryHealth(
    Guid EndpointId,
    bool Enabled,
    string CollectorSource,
    string CollectorVersion,
    DateTimeOffset? LastSourceEvent,
    DateTimeOffset? LastAcceptedEvent,
    long QueueDepth,
    long OldestQueuedSeconds,
    long DroppedEvents,
    long ExcludedEvents,
    long SourceLosses,
    long SequenceGaps,
    long HandleResolutionFailures,
    long PathResolutionFailures,
    long CaptureAttempts,
    long CaptureSkips,
    long CaptureFailures,
    long RedactedValues,
    string LastUploadResult,
    string PolicyVersion,
    int? AppliedVersion,
    bool Drift,
    DateTimeOffset? LastUpload,
    long LastSequence
);

public sealed record RegistryExclusionRule(
    Guid Id,
    string Category,
    string Pattern,
    bool Enabled = true,
    string Reason = "",
    string Creator = "",
    DateTimeOffset? CreatedAt = null,
    long MatchCount = 0,
    DateTimeOffset? LastMatch = null
);

public sealed record RegistryTelemetryPolicy(
    string Version = "registry-policy.v1",
    bool Enabled = true,
    bool KeyCreateEnabled = true,
    bool KeyDeleteEnabled = true,
    bool KeyRenameEnabled = true,
    bool ValueSetEnabled = true,
    bool ValueDeleteEnabled = true,
    bool SecurityChangeEnabled = false,
    RegistryCaptureMode CaptureMode = RegistryCaptureMode.MetadataOnly,
    int MaximumCapturedBytes = 256,
    bool ContentHashingEnabled = false,
    string[]? IncludedHives = null,
    string[]? IncludedPaths = null,
    string[]? ExcludedPaths = null,
    string[]? IncludedValueNames = null,
    string[]? ExcludedValueNames = null,
    string[]? IncludedValueTypes = null,
    string[]? ExcludedValueTypes = null,
    string[]? ExcludedProcesses = null,
    string[]? ExcludedUsers = null,
    string[]? AllowedCapturePaths = null,
    string[]? RedactionPatterns = null,
    long MaximumQueueBytes = 128 * 1024 * 1024,
    int MaximumQueueAgeHours = 24,
    int MaximumBatchEvents = 200,
    int MaximumBatchBytes = 1024 * 1024,
    int FlushSeconds = 5,
    string CollectorSource = "windows.etw-registry",
    bool DiagnosticMode = false,
    IReadOnlyList<RegistryExclusionRule>? ExclusionRules = null
);

public sealed record RegistryPolicyVersion(
    Guid Id,
    string TenantId,
    string Name,
    int Version,
    RegistryTelemetryPolicy Policy,
    string Sha256,
    string Status,
    DateTimeOffset CreatedAt,
    string CreatedBy
);

public sealed record EffectiveRegistryPolicy(
    RegistryPolicyVersion Policy,
    string AssignmentSource,
    Guid EndpointId,
    DateTimeOffset? AcknowledgedAt,
    int? AppliedVersion,
    int? RejectedVersion,
    string? ValidationError,
    bool Drift
);

public sealed record RegistryPolicyAcknowledgement(
    Guid PolicyId,
    int Version,
    bool Applied,
    string? ValidationError,
    DateTimeOffset AcknowledgedAt
);

public static class RegistryPolicyValidation
{
    private static readonly string[] Hives =
        ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"];
    private static readonly string[] Categories =
        ["key-exact", "key-prefix", "value", "hive", "process", "user", "value-type"];
    private static readonly string[] ProtectedCapturePaths =
        [
            "HKLM\\SAM",
            "HKLM\\SECURITY",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "HKCU\\Software\\Microsoft\\Credentials",
            "HKCU\\Software\\Microsoft\\Vault",
            "HKCU\\Software\\Microsoft\\Protected Storage System Provider",
        ];

    public static IReadOnlyDictionary<string, string[]> Validate(RegistryTelemetryPolicy p)
    {
        var e = new Dictionary<string, string[]>();
        if (p.CollectorSource != "windows.etw-registry")
            e["collectorSource"] = ["Only the approved Windows ETW registry source is supported."];
        if (p.MaximumCapturedBytes is < 0 or > 4096)
            e["maximumCapturedBytes"] = ["Capture must be bounded between 0 and 4096 bytes."];
        if (p.MaximumQueueBytes is < 1024 * 1024 or > 4L * 1024 * 1024 * 1024)
            e["maximumQueueBytes"] = ["Queue must be between 1 MiB and 4 GiB."];
        if (p.MaximumQueueAgeHours is < 1 or > 720)
            e["maximumQueueAgeHours"] = ["Queue age must be between 1 and 720 hours."];
        if (p.MaximumBatchEvents is < 1 or > 1000 || p.MaximumBatchBytes is < 1024 or > 4 * 1024 * 1024)
            e["batch"] = ["Batch bounds are invalid."];
        if (p.FlushSeconds is < 1 or > 300)
            e["flushSeconds"] = ["Flush interval must be between 1 and 300 seconds."];
        if (p.IncludedHives?.Any(x => !Hives.Contains(x, StringComparer.OrdinalIgnoreCase)) == true)
            e["includedHives"] = ["A registry hive is unsupported."];
        if ((p.CaptureMode is RegistryCaptureMode.ContentHash or RegistryCaptureMode.BoundedPreview or RegistryCaptureMode.ApprovedFullContent) && p.AllowedCapturePaths is not { Length: > 0 })
            e["allowedCapturePaths"] = ["Hashing, preview, and full capture require an explicit allowed path."];
        if (p.AllowedCapturePaths?.Any(IsProtectedPath) == true)
            e["allowedCapturePaths"] = ["Protected registry locations can never authorize value content."];
        if (p.ExclusionRules is { Count: > 64 })
            e["exclusionRules"] = ["At most 64 exclusions are allowed."];
        foreach (var rule in p.ExclusionRules ?? [])
        {
            if (!Categories.Contains(rule.Category, StringComparer.Ordinal))
                e[$"exclusion.{rule.Id}"] = ["Unsupported exclusion category."];
            if (string.IsNullOrWhiteSpace(rule.Pattern) || rule.Pattern is "*" or "**" or "\\" || rule.Pattern.Length > 512 || rule.Pattern.Any(char.IsControl) || rule.Pattern.Count(x => x is '*' or '?') > 8)
                e[$"exclusion.{rule.Id}"] = ["Empty, match-all, unsafe, or excessive-wildcard exclusion."];
            if (rule.Category == "hive" && Hives.Contains(rule.Pattern, StringComparer.OrdinalIgnoreCase))
                e[$"exclusion.{rule.Id}"] = ["An entire hive requires an elevated out-of-band confirmation and is rejected by this API."];
        }
        return e;
    }

    public static bool IsProtectedPath(string path) =>
        ProtectedCapturePaths.Any(x => path.StartsWith(x, StringComparison.OrdinalIgnoreCase));

    public static bool IsSecretLikeName(string? valueName) =>
        valueName is not null
        && new[] { "password", "passwd", "secret", "token", "privatekey", "credential", "apikey" }
            .Any(x => valueName.Contains(x, StringComparison.OrdinalIgnoreCase));
}

public interface IRegistryTelemetryRepository
{
    Task<RegistryIngestResult> IngestAsync(string tenantId, RegistryEventBatch batch, RegistryTelemetryHealth health, CancellationToken ct);
    Task<RegistryEventPage> SearchAsync(string tenantId, RegistrySearchRequest request, CancellationToken ct);
    Task<RegistryObservation?> GetEventAsync(string tenantId, Guid eventId, CancellationToken ct);
    Task<RegistryKeyView?> GetKeyAsync(string tenantId, Guid endpointId, string entityId, CancellationToken ct);
    Task<RegistryValueView?> GetValueAsync(string tenantId, Guid endpointId, string entityId, CancellationToken ct);
    Task<RegistryEventPage> KeyHistoryAsync(string tenantId, Guid endpointId, string entityId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<RegistryEventPage> ValueHistoryAsync(string tenantId, Guid endpointId, string entityId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<RegistryEventPage> EndpointTimelineAsync(string tenantId, Guid endpointId, RegistrySearchRequest request, CancellationToken ct);
    Task<RegistryEventPage> ProcessRegistryAsync(string tenantId, Guid endpointId, string processEntityId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<RegistryTelemetryHealth?> HealthAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task<IReadOnlyList<RegistryObservation>> ListAllAsync(CancellationToken ct);
}

public interface IRegistryProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(string tenantId, RegistryObservation observation, CancellationToken ct);
    Task<RegistryEventPage> SearchAsync(string tenantId, RegistrySearchRequest request, CancellationToken ct);
    Task<ProcessProjectionRebuildResult> RebuildAsync(IReadOnlyList<RegistryObservation> events, CancellationToken ct);
    RegistryProjectionRebuildProgress GetRebuildProgress();
    Task<bool> HealthAsync(CancellationToken ct);
}

public interface IRegistryPolicyRepository
{
    Task<IReadOnlyList<RegistryPolicyVersion>> ListAsync(string tenantId, CancellationToken ct);
    Task<RegistryPolicyVersion> CreateAsync(string tenantId, string actor, string name, RegistryTelemetryPolicy policy, CancellationToken ct);
    Task AssignAsync(string tenantId, Guid policyId, Guid? endpointId, string actor, CancellationToken ct);
    Task<EffectiveRegistryPolicy> EffectiveAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task AcknowledgeAsync(string tenantId, Guid endpointId, RegistryPolicyAcknowledgement acknowledgement, CancellationToken ct);
    Task<RegistryPolicyVersion> RollbackAsync(string tenantId, Guid policyId, int version, string actor, CancellationToken ct);
}

public static class RegistryEvidence
{
    public static string CanonicalSha256<T>(T value) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value))).ToLowerInvariant();
}
