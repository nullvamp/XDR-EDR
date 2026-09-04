using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

public enum FileEventKind
{
    Created,
    Modified,
    Deleted,
    Renamed,
    Moved,
    MetadataChanged,
    Opened,
    Closed,
}

public enum FileEntityState
{
    Present,
    Deleted,
    Renamed,
    Moved,
    Replaced,
    Unknown,
    IncompleteHistory,
}

[JsonConverter(typeof(JsonStringEnumConverter<FileHashState>))]
public enum FileHashState
{
    NotRequested,
    Pending,
    Succeeded,
    TooLarge,
    RateLimited,
    ChangedDuringHash,
    ReplacedDuringHash,
    IdentityMismatch,
    DeletedDuringHash,
    PermissionLost,
    ReadFailure,
    Failed,
    Unavailable,
}

public static class FileHashSafety
{
    public static bool ShouldRequest(FileEventKind kind) =>
        kind is FileEventKind.Created or FileEventKind.Modified or FileEventKind.Renamed or FileEventKind.Moved;
}

public sealed record FileNativeIdentity(
    string? VolumeId,
    string? FileId,
    long? DeviceId,
    long? Inode,
    string? ParentDirectoryId,
    bool? SymbolicLink,
    bool? HardLink,
    long? MountId = null
);

public sealed record FileMetadata(
    long? Size,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? ModifiedAt,
    DateTimeOffset? AccessedAt,
    string? Attributes,
    string? Permissions,
    string? Owner,
    string? Group,
    string? MimeType,
    bool? Hidden,
    bool? System,
    bool? ReadOnly,
    bool? Temporary
);

public sealed record FileHashMetadata(
    FileHashState State = FileHashState.NotRequested,
    string? Sha256 = null,
    string? FailureReason = null,
    DateTimeOffset? HashedAt = null,
    long? SizeAtHash = null,
    DateTimeOffset? ModifiedAtHash = null,
    ProcessSignatureState SignatureState = ProcessSignatureState.NotChecked,
    string? Signer = null,
    string? CertificateThumbprint = null,
    string? VerificationFailure = null,
    DateTimeOffset? RequestedAt = null,
    string? PolicyVersion = null,
    FileNativeIdentity? NativeIdentityBefore = null,
    FileNativeIdentity? NativeIdentityAfter = null,
    DateTimeOffset? ChangeTimeAtHash = null,
    double? QueueWaitMilliseconds = null,
    double? DurationMilliseconds = null,
    string? CacheResult = null,
    long? SizeAfterHash = null,
    DateTimeOffset? ModifiedAfterHash = null,
    DateTimeOffset? ChangeTimeAfterHash = null
);

public sealed record FileHashMetrics(
    long Requests,
    long Pending,
    long OldestPendingSeconds,
    long ActiveWorkers,
    long Successes,
    long Failures,
    long Skips,
    long Oversized,
    long RateLimited,
    long CacheHits,
    long CacheMisses,
    long CacheInvalidations,
    long CacheEvictions,
    long IdentityMismatches,
    long ChangedDuringHash,
    long ReplacedDuringHash,
    long DeletedDuringHash,
    long PermissionFailures,
    long ReadFailures,
    long BytesHashed,
    double DurationMeanMilliseconds,
    double DurationP50Milliseconds,
    double DurationP95Milliseconds,
    double DurationMaximumMilliseconds,
    double QueueWaitMeanMilliseconds,
    double QueueWaitP95Milliseconds
);

public sealed record FileProcessRelationship(
    string? ProcessEntityId,
    int? ProcessId,
    string? Image,
    string? Path,
    string? CommandLine,
    DateTimeOffset? ProcessStartTime,
    string? User,
    string Source,
    string Confidence
);

public sealed record FileObservation(
    Guid EventId,
    string SchemaVersion,
    FileEventKind Kind,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    string CollectorId,
    string CollectorType,
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
    string FileEntityId,
    FileNativeIdentity NativeIdentity,
    string OriginalPath,
    string CurrentPath,
    string? PreviousPath,
    string? DestinationPath,
    string FileName,
    string DirectoryPath,
    string Extension,
    string PathType,
    string PathNormalization,
    bool CaseSensitive,
    string? AlternateDataStream,
    bool? NetworkPath,
    string? ContainerId,
    FileMetadata Metadata,
    FileHashMetadata Hash,
    FileProcessRelationship? Process,
    string? UserId,
    string? UserName,
    string? OperationOutcome,
    string? NativeOperation,
    bool Late = false
)
{
    public static string StableEntityId(
        Guid endpointId,
        FileNativeIdentity identity,
        string path,
        DateTimeOffset firstObserved
    )
    {
        var native =
            identity.FileId
            ?? (
                identity.DeviceId is not null && identity.Inode is not null
                    ? $"{identity.DeviceId}:{identity.Inode}"
                    : null
            );
        var material = native is null
            ? $"path-instance:{path}:{firstObserved.UtcTicks}"
            : $"native:{native}";
        return Convert
            .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{endpointId:D}:{material}")))
            .ToLowerInvariant();
    }
}

public sealed record FileEventBatch(
    Guid BatchId,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    long FirstSequence,
    long LastSequence,
    IReadOnlyList<FileObservation> Events,
    string ContentSha256
);

public sealed record FileBatchAcknowledgement(
    Guid BatchId,
    IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds,
    IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough,
    bool GapDetected
);

public sealed record FileIngestResult(
    FileBatchAcknowledgement Acknowledgement,
    int Accepted,
    int Duplicates,
    int Rejected,
    int SequenceGaps
);

public sealed record FileEntityView(
    string TenantId,
    Guid EndpointId,
    string FileEntityId,
    FileNativeIdentity NativeIdentity,
    string CurrentPath,
    IReadOnlyList<string> PreviousPaths,
    DateTimeOffset FirstObserved,
    DateTimeOffset LastObserved,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? DeletedAt,
    FileEntityState State,
    FileMetadata Metadata,
    FileHashMetadata Hash,
    FileProcessRelationship? LatestProcess,
    string? UserName,
    string SourceConfidence,
    Guid LatestEventId,
    string[] DataQualityFlags,
    string CollectorType,
    string CollectorVersion
);

public sealed record FileSearchRequest(
    Guid? EndpointId = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    FileEventKind? Operation = null,
    string? FileName = null,
    string? Path = null,
    string? Directory = null,
    string? Extension = null,
    string? Process = null,
    string? User = null,
    string? Sha256 = null,
    ProcessSignatureState? Signature = null,
    long? MinimumSize = null,
    long? MaximumSize = null,
    string? Collector = null,
    string? Container = null,
    string? DataQuality = null,
    int PageSize = 100,
    string? Cursor = null,
    string? PreviousPath = null,
    string? NativeFileId = null,
    string? VolumeId = null,
    long? DeviceId = null,
    long? Inode = null
);

public sealed record FilePage(IReadOnlyList<FileEntityView> Items, string? NextCursor);

public sealed record FileEventPage(IReadOnlyList<FileObservation> Items, string? NextCursor);

public sealed record FileProjectionRebuildProgress(
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

public sealed record FileTelemetryHealth(
    Guid EndpointId,
    bool Enabled,
    string CollectorType,
    string CollectorVersion,
    DateTimeOffset? LastEventAt,
    long QueueDepth,
    long OldestQueuedSeconds,
    long DroppedEvents,
    long ExcludedEvents,
    long SourceGaps,
    long WatchErrors,
    long JournalResets,
    long EtwLostEvents,
    long FalcoLostEvents,
    long HashFailures,
    long SignatureFailures,
    string LastUploadResult,
    string PolicyVersion,
    long LastSequence,
    FileHashMetrics? HashMetrics = null
);

public sealed record FileExclusionRule(
    Guid Id,
    string Category,
    string Pattern,
    bool Enabled = true
);

public sealed record FileTelemetryPolicy(
    string Version = "file-policy.v1",
    bool Enabled = true,
    bool CreateEnabled = true,
    bool ModifyEnabled = true,
    bool DeleteEnabled = true,
    bool RenameEnabled = true,
    bool MoveEnabled = true,
    bool OpenEnabled = false,
    bool MetadataChangeEnabled = true,
    bool HashingEnabled = false,
    bool SignatureEnabled = false,
    long MaximumHashBytes = 16 * 1024 * 1024,
    int HashesPerMinute = 30,
    int SignaturesPerMinute = 15,
    int MetadataCacheSeconds = 60,
    string[]? IncludedPaths = null,
    string[]? ExcludedPaths = null,
    string[]? IncludedExtensions = null,
    string[]? ExcludedExtensions = null,
    string[]? ExcludedProcesses = null,
    string[]? ExcludedUsers = null,
    string[]? ExcludedContainers = null,
    bool NetworkShares = false,
    bool RemovableMedia = false,
    bool TemporaryDirectories = false,
    bool PseudoFileSystems = false,
    long MaximumQueueBytes = 128 * 1024 * 1024,
    int MaximumQueueAgeHours = 24,
    int MaximumBatchEvents = 200,
    int MaximumBatchBytes = 1024 * 1024,
    int FlushSeconds = 5,
    string CollectorSource = "auto",
    bool DiagnosticMode = false,
    IReadOnlyList<FileExclusionRule>? ExclusionRules = null
);

public sealed record FilePolicyVersion(
    Guid Id,
    string TenantId,
    string Name,
    int Version,
    FileTelemetryPolicy Policy,
    string Sha256,
    string Status,
    DateTimeOffset CreatedAt,
    string CreatedBy
);

public sealed record EffectiveFilePolicy(
    FilePolicyVersion Policy,
    string AssignmentSource,
    Guid EndpointId,
    DateTimeOffset? AcknowledgedAt,
    int? AppliedVersion,
    int? RejectedVersion,
    string? ValidationError,
    bool Drift
);

public sealed record FilePolicyAcknowledgement(
    Guid PolicyId,
    int Version,
    bool Applied,
    string? ValidationError,
    DateTimeOffset AcknowledgedAt
);

public static class FilePolicyValidation
{
    public static IReadOnlyDictionary<string, string[]> Validate(FileTelemetryPolicy p)
    {
        var e = new Dictionary<string, string[]>();
        if (p.MaximumHashBytes is < 0 or > 1024L * 1024 * 1024)
            e["maximumHashBytes"] = ["Must be between 0 and 1 GiB."];
        if (p.HashesPerMinute is < 1 or > 10000)
            e["hashesPerMinute"] = ["Must be between 1 and 10000."];
        if (p.MaximumQueueBytes is < 1024 * 1024 or > 4L * 1024 * 1024 * 1024)
            e["maximumQueueBytes"] = ["Must be between 1 MiB and 4 GiB."];
        if (p.MaximumBatchEvents is < 1 or > 1000)
            e["maximumBatchEvents"] = ["Must be between 1 and 1000."];
        if (
            p.ExclusionRules?.Any(x =>
                string.IsNullOrWhiteSpace(x.Pattern) || x.Pattern is "*" or "**" or "/" or "\\"
            ) == true
        )
            e["exclusionRules"] = ["Empty and match-all exclusions are forbidden."];
        if (
            p.ExclusionRules?.Any(x =>
                x.Category
                    is not ("path" or "extension" or "process" or "user" or "container")
                || x.Pattern.Length > 512
                || x.Pattern.Any(char.IsControl)
                || x.Pattern.Count(c => c is '*' or '?') > 16
                || x.Pattern is "/*" or "\\*"
                || (x.Category == "path"
                    && x.Pattern.Length == 3
                    && char.IsLetter(x.Pattern[0])
                    && x.Pattern[1] == ':'
                    && x.Pattern[2] is '\\' or '/')
            ) == true
        )
            e["exclusionRules"] =
            [
                "Exclusions require a supported category, a bounded pattern, no control characters, and may not exclude a filesystem root.",
            ];
        if (
            p.CollectorSource
            is not ("auto" or "windows.etw-file" or "linux.falco-json" or "macos.endpoint-security")
        )
            e["collectorSource"] = ["Collector source is unsupported."];
        return e;
    }
}

public interface IFileTelemetryRepository
{
    Task<FileIngestResult> IngestAsync(
        string tenantId,
        FileEventBatch batch,
        FileTelemetryHealth health,
        CancellationToken ct
    );
    Task<FilePage> SearchAsync(string tenantId, FileSearchRequest request, CancellationToken ct);
    Task<FileObservation?> GetEventAsync(string tenantId, Guid eventId, CancellationToken ct);
    Task<FileEntityView?> GetAsync(
        string tenantId,
        Guid endpointId,
        string fileEntityId,
        CancellationToken ct
    );
    Task<FileEventPage> HistoryAsync(
        string tenantId,
        Guid endpointId,
        string fileEntityId,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    );
    Task<FileEventPage> EndpointTimelineAsync(
        string tenantId,
        Guid endpointId,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    );
    Task<FileEventPage> ProcessFilesAsync(
        string tenantId,
        Guid endpointId,
        string processEntityId,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    );
    Task<FileTelemetryHealth?> HealthAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task<IReadOnlyList<FileEntityView>> ListAllAsync(CancellationToken ct);
}

public interface IFileProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(FileEntityView file, string eventId, CancellationToken ct);
    Task<FilePage> SearchAsync(string tenantId, FileSearchRequest request, CancellationToken ct);
    Task<ProcessProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<FileEntityView> files,
        CancellationToken ct
    );
    FileProjectionRebuildProgress GetRebuildProgress();
    Task<bool> HealthAsync(CancellationToken ct);
}

public interface IFilePolicyRepository
{
    Task<IReadOnlyList<FilePolicyVersion>> ListAsync(string tenantId, CancellationToken ct);
    Task<FilePolicyVersion> CreateAsync(
        string tenantId,
        string actor,
        string name,
        FileTelemetryPolicy policy,
        CancellationToken ct
    );
    Task AssignAsync(
        string tenantId,
        Guid policyId,
        Guid? endpointId,
        string actor,
        CancellationToken ct
    );
    Task<EffectiveFilePolicy> EffectiveAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    );
    Task AcknowledgeAsync(
        string tenantId,
        Guid endpointId,
        FilePolicyAcknowledgement acknowledgement,
        CancellationToken ct
    );
    Task<FilePolicyVersion> RollbackAsync(
        string tenantId,
        Guid policyId,
        int version,
        string actor,
        CancellationToken ct
    );
}
