using System.Security.Cryptography;
using System.Text;

namespace OpenSecurityPlatform.Foundation;

public enum ProcessEventKind
{
    Started,
    Exited,
}

public enum LineageState
{
    Resolved,
    ParentNotObserved,
    ParentExitedBeforeObservation,
    CollectionStartedAfterParent,
    InformationUnavailable,
    PossibleEventLoss,
}

public enum ProcessSignatureState
{
    Unknown,
    NotSigned,
    Valid,
    Invalid,
    NotChecked,
    Error,
}

public sealed record ProcessTelemetryPolicy(
    bool StartEnabled = true,
    bool ExitEnabled = true,
    bool CommandLineEnabled = true,
    bool WorkingDirectoryEnabled = false,
    bool UserEnabled = true,
    bool HashingEnabled = false,
    bool SignatureEnabled = false,
    bool ContainerMetadataEnabled = true,
    long MaximumQueueBytes = 64 * 1024 * 1024,
    int MaximumEventAgeHours = 72,
    int MaximumBatchEvents = 200,
    int MaximumBatchBytes = 512 * 1024,
    int FlushSeconds = 5,
    string[]? ExcludedProcessNames = null,
    string Version = "process-policy.v1",
    bool TelemetryEnabled = true,
    int MetadataCacheSeconds = 300,
    long MaximumHashFileBytes = 128 * 1024 * 1024,
    int HashesPerMinute = 30,
    int SignaturesPerMinute = 30,
    int MaximumCompressedBatchBytes = 1024 * 1024,
    string CollectorSource = "auto",
    ProcessExclusionRule[]? ExclusionRules = null,
    string SensitiveCommandLineHandling = "redact",
    string[]? AllowedProcessPaths = null,
    string[]? ExcludedProcessPaths = null,
    string[]? ExcludedUsers = null,
    string[]? ExcludedContainers = null,
    bool TemporaryDiagnosticMode = false
);

public sealed record ProcessExclusionRule(
    Guid Id,
    string Category,
    string Pattern,
    bool Enabled = true
);

public sealed record ProcessPolicyVersion(
    Guid Id,
    string TenantId,
    string Name,
    int Version,
    ProcessTelemetryPolicy Policy,
    string ContentHash,
    string Status,
    DateTimeOffset CreatedAt,
    string CreatedBy
);

public sealed record EffectiveProcessPolicy(
    ProcessPolicyVersion Policy,
    string AssignmentType,
    Guid? EndpointId,
    DateTimeOffset? AcknowledgedAt,
    int? AppliedVersion,
    int? RejectedVersion,
    string? ValidationError,
    bool Drift
);

public sealed record ProcessPolicyAcknowledgement(
    Guid PolicyId,
    int Version,
    bool Applied,
    string? ValidationError,
    DateTimeOffset AcknowledgedAt
);

public sealed record ProcessExclusionMetric(
    Guid RuleId,
    string Category,
    long EventsExcluded,
    DateTimeOffset? LastMatchAt
);

public interface IProcessPolicyRepository
{
    Task<IReadOnlyList<ProcessPolicyVersion>> ListAsync(
        string tenantId,
        CancellationToken cancellationToken
    );
    Task<ProcessPolicyVersion> CreateAsync(
        string tenantId,
        string actor,
        string name,
        ProcessTelemetryPolicy policy,
        CancellationToken cancellationToken
    );
    Task AssignAsync(
        string tenantId,
        Guid policyId,
        Guid? endpointId,
        string actor,
        CancellationToken cancellationToken
    );
    Task<EffectiveProcessPolicy> EffectiveAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken cancellationToken
    );
    Task AcknowledgeAsync(
        string tenantId,
        Guid endpointId,
        ProcessPolicyAcknowledgement acknowledgement,
        CancellationToken cancellationToken
    );
    Task<ProcessPolicyVersion> RollbackAsync(
        string tenantId,
        Guid policyId,
        int version,
        string actor,
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<ProcessExclusionMetric>> ExclusionMetricsAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken cancellationToken
    );
}

public static class ProcessPolicyValidation
{
    private static readonly string[] Categories = ["name", "path", "user", "container"];
    private static readonly string[] CollectorSources =
    [
        "auto",
        "etw",
        "windows.etw",
        "falco",
        "linux.falco-json",
        "procfs",
        "linux.procfs",
        "endpoint-security",
        "macos.endpoint-security",
    ];

    public static IReadOnlyDictionary<string, string[]> Validate(ProcessTelemetryPolicy policy)
    {
        var errors = new Dictionary<string, string[]>();
        if (!CollectorSources.Contains(policy.CollectorSource, StringComparer.OrdinalIgnoreCase))
            errors["collectorSource"] = ["Collector source is unsupported."];
        if (policy.MaximumQueueBytes is < 1024 * 1024 or > 4L * 1024 * 1024 * 1024)
            errors["maximumQueueBytes"] = ["Queue size must be between 1 MiB and 4 GiB."];
        if (policy.MaximumEventAgeHours is < 1 or > 720)
            errors["maximumEventAgeHours"] = ["Queue age must be between 1 and 720 hours."];
        if (
            policy.MaximumBatchEvents is < 1 or > 500
            || policy.MaximumBatchBytes is < 1024 or > 4 * 1024 * 1024
            || policy.MaximumCompressedBatchBytes is < 1024 or > 1024 * 1024
        )
            errors["batch"] = ["Batch limits are outside safe bounds."];
        if (
            policy.FlushSeconds is < 1 or > 300
            || policy.HashesPerMinute is < 0 or > 600
            || policy.SignaturesPerMinute is < 0 or > 600
        )
            errors["rate"] = ["Flush or enrichment rate is outside safe bounds."];
        if (policy.ExclusionRules is { Length: > 64 })
            errors["exclusions"] = ["At most 64 exclusion rules are allowed."];
        foreach (var rule in policy.ExclusionRules ?? [])
        {
            if (!Categories.Contains(rule.Category, StringComparer.Ordinal))
                errors[$"exclusion.{rule.Id}"] = ["Exclusion category is invalid."];
            if (
                string.IsNullOrWhiteSpace(rule.Pattern)
                || rule.Pattern.Trim() is "*" or "**"
                || rule.Pattern.Length > 256
                || rule.Pattern.Count(x => x == '*') > 8
            )
                errors[$"exclusion.{rule.Id}"] =
                [
                    "Empty, match-all, oversized, or excessively complex exclusions are forbidden.",
                ];
            if (rule.Pattern.Any(char.IsControl))
                errors[$"exclusion.{rule.Id}"] =
                [
                    "Control characters are forbidden in exclusions.",
                ];
        }
        return errors;
    }
}

public sealed record ProcessExecutableMetadata(
    string? FileName,
    string? Path,
    long? Size,
    DateTimeOffset? LastModifiedAt,
    string? Sha256,
    ProcessSignatureState SignatureState,
    string? SignerSubject,
    string? CertificateThumbprint,
    string? ProductName,
    string? OriginalFileName,
    string? FileVersion,
    string? Description,
    string? Format,
    DateTimeOffset? CompileTime,
    string HashOutcome,
    string SignatureOutcome,
    double MetadataDurationMs,
    string? ErrorCategory
);

public sealed record ProcessObservation(
    Guid EventId,
    ProcessEventKind Kind,
    string SchemaVersion,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    string CollectorId,
    string CollectorType,
    string CollectorVersion,
    string SourcePlatform,
    string? SourceEventId,
    DateTimeOffset ObservedAt,
    long Sequence,
    string CorrelationId,
    string? TraceId,
    string? RawSha256,
    string NormalizationVersion,
    string[] DataQualityFlags,
    int ProcessId,
    DateTimeOffset ProcessStartTime,
    string ProcessEntityId,
    int? ParentProcessId,
    string? ParentProcessEntityId,
    LineageState LineageState,
    string? ParentImage,
    string? ParentPath,
    string? ParentCommandLine,
    DateTimeOffset? ParentStartTime,
    string? ExecutableName,
    string? ExecutablePath,
    string? CommandLine,
    string? WorkingDirectory,
    string? UserName,
    string? UserDomain,
    string? UserId,
    string? SessionId,
    string? LogonId,
    string? IntegrityLevel,
    bool? Elevated,
    string? Architecture,
    string? ContainerId,
    string? NamespaceId,
    ProcessExecutableMetadata? ExecutableMetadata,
    DateTimeOffset? ExitTime,
    int? ExitCode,
    long? DurationMilliseconds,
    string? TerminationReason,
    string? ExitState,
    long ClockOffsetMilliseconds = 0
);

public sealed record ProcessEventBatch(
    Guid BatchId,
    string ProtocolVersion,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    long FirstSequence,
    long LastSequence,
    string Compression,
    string ContentSha256,
    DateTimeOffset CreatedAt,
    IReadOnlyList<ProcessObservation> Events
);

public sealed record ProcessBatchAcknowledgement(
    Guid BatchId,
    IReadOnlyList<Guid> Accepted,
    IReadOnlyList<Guid> Duplicates,
    IReadOnlyDictionary<Guid, string> Rejected,
    long? HighestContiguousSequence,
    bool Retryable
);

public sealed record ProcessEntityView(
    string TenantId,
    Guid EndpointId,
    string ProcessEntityId,
    int ProcessId,
    DateTimeOffset StartTime,
    DateTimeOffset? ExitTime,
    string? ParentProcessEntityId,
    int? ParentProcessId,
    LineageState LineageState,
    string? ExecutableName,
    string? ExecutablePath,
    string? CommandLine,
    string? WorkingDirectory,
    string? UserName,
    string? UserId,
    string? SessionId,
    string? IntegrityLevel,
    bool? Elevated,
    string? Architecture,
    string? ContainerId,
    ProcessExecutableMetadata? ExecutableMetadata,
    Guid StartEventId,
    Guid? ExitEventId,
    DateTimeOffset FirstObservedAt,
    DateTimeOffset LastUpdatedAt,
    string CollectorType,
    string CollectorVersion,
    string SchemaVersion,
    string NormalizationVersion,
    string[] DataQualityFlags,
    bool Late,
    long? DurationMilliseconds,
    int? ExitCode
);

public sealed record ProcessSearchRequest(
    Guid? EndpointId,
    DateTimeOffset From,
    DateTimeOffset To,
    string? ProcessName = null,
    string? Path = null,
    string? CommandLine = null,
    int? ProcessId = null,
    int? ParentProcessId = null,
    string? User = null,
    string? Sha256 = null,
    ProcessSignatureState? Signature = null,
    string? State = null,
    int PageSize = 100,
    string? Cursor = null
);

public sealed record ProcessPage(IReadOnlyList<ProcessEntityView> Items, string? NextCursor);

public sealed record ProcessTreeNode(
    ProcessEntityView Process,
    IReadOnlyList<ProcessTreeNode> Children,
    bool MissingParent,
    bool IncompleteLineage
);

public sealed record ProcessLineageView(
    string SelectedProcessEntityId,
    ProcessTreeNode Tree,
    int AncestorCount,
    int DescendantCount,
    bool AncestorBoundaryIncomplete
);

public sealed record ProcessTelemetryHealth(
    Guid EndpointId,
    bool Enabled,
    string CollectorType,
    string CollectorVersion,
    DateTimeOffset? LastEventAt,
    long QueueDepth,
    long OldestQueuedAgeSeconds,
    long DroppedEvents,
    string? DropReason,
    string LastUploadResult,
    string PolicyVersion,
    long SequenceGaps,
    long ExcludedEvents = 0,
    Guid? LastExclusionRuleId = null,
    string? LastExclusionCategory = null,
    DateTimeOffset? LastExclusionAt = null
);

public sealed record ProcessIngestResult(
    ProcessBatchAcknowledgement Acknowledgement,
    int Accepted,
    int Duplicates,
    int Rejected,
    int SequenceGaps
);

public sealed record ProcessProjectionRebuildResult(
    string IndexName,
    int Documents,
    TimeSpan Duration,
    bool AliasSwitched
);

public interface IProcessTelemetryRepository
{
    Task<ProcessIngestResult> IngestAsync(
        string tenantId,
        ProcessEventBatch batch,
        ProcessTelemetryHealth health,
        CancellationToken cancellationToken
    );
    Task<ProcessPage> SearchAsync(
        string tenantId,
        ProcessSearchRequest request,
        CancellationToken cancellationToken
    );
    Task<ProcessEntityView?> GetAsync(
        string tenantId,
        Guid endpointId,
        string processEntityId,
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<ProcessEntityView>> TimelineAsync(
        string tenantId,
        Guid endpointId,
        DateTimeOffset from,
        DateTimeOffset toTime,
        int limit,
        CancellationToken cancellationToken
    );
    Task<ProcessTreeNode?> TreeAsync(
        string tenantId,
        Guid endpointId,
        string rootProcessEntityId,
        int depth,
        CancellationToken cancellationToken
    );
    Task<ProcessLineageView?> LineageAsync(
        string tenantId,
        Guid endpointId,
        string selectedProcessEntityId,
        int ancestorDepth,
        int descendantDepth,
        CancellationToken cancellationToken
    );
    Task<ProcessTelemetryHealth?> HealthAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<ProcessEntityView>> ListAllAsync(CancellationToken cancellationToken);
}

public interface IProcessProjection
{
    Task UpsertAsync(
        ProcessEntityView process,
        string eventId,
        CancellationToken cancellationToken
    );
    Task<ProcessPage> SearchAsync(
        string tenantId,
        ProcessSearchRequest request,
        CancellationToken cancellationToken
    );
    Task<ProcessProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<ProcessEntityView> processes,
        CancellationToken cancellationToken
    );
    Task<bool> HealthAsync(CancellationToken cancellationToken);
}

public static class ProcessIdentity
{
    public static string Create(
        Guid endpointId,
        int processId,
        DateTimeOffset startTime,
        string? platformStartKey = null
    )
    {
        var material =
            $"{endpointId:D}\n{processId}\n{startTime.UtcTicks}\n{platformStartKey ?? ""}";
        return Convert
            .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)))
            .ToLowerInvariant();
    }
}

public static class ProcessTelemetryValidation
{
    public static IReadOnlyDictionary<string, string[]> Validate(
        ProcessEventBatch batch,
        DateTimeOffset now
    )
    {
        var errors = new Dictionary<string, string[]>();
        if (batch.Events.Count is < 1 or > 500)
            errors["events"] = ["Batch event count must be between 1 and 500."];
        if (batch.FirstSequence < 1 || batch.LastSequence < batch.FirstSequence)
            errors["sequence"] = ["Batch sequence range is invalid."];
        if (
            batch.Events.Count > 0
            && (
                batch.Events.Min(x => x.Sequence) != batch.FirstSequence
                || batch.Events.Max(x => x.Sequence) != batch.LastSequence
            )
        )
            errors["sequenceRange"] = ["Event sequence range does not match the batch."];
        if (batch.Events.Select(x => x.EventId).Distinct().Count() != batch.Events.Count)
            errors["eventIds"] = ["A batch cannot contain duplicate event IDs."];
        foreach (var item in batch.Events)
        {
            if (
                item.EndpointId != batch.EndpointId
                || item.AgentId != batch.AgentId
                || item.InstallationId != batch.InstallationId
            )
                errors["binding"] = ["Event identity does not match the authenticated batch."];
            if (item.ProcessId <= 0 || item.ProcessEntityId.Length != 64)
                errors["processIdentity"] = ["Process identity is invalid."];
            if (item.ObservedAt < now.AddDays(-7) || item.ObservedAt > now.AddMinutes(5))
                errors["timestamp"] = ["Observed timestamp is outside the accepted window."];
            if (
                item.SchemaVersion != "process.event.v1"
                || item.NormalizationVersion != "process.normalize.v1"
            )
                errors["schema"] = ["Unsupported process schema or normalization version."];
            if (
                item.CommandLine?.Length > 32768
                || item.ExecutablePath?.Length > 4096
                || item.UserName?.Length > 512
            )
                errors["fieldLength"] = ["A process field exceeds its maximum length."];
            if (
                item.RawSha256 is not null
                && (item.RawSha256.Length != 64 || !item.RawSha256.All(Uri.IsHexDigit))
            )
                errors["rawHash"] = ["Raw hash must be SHA-256 hexadecimal."];
            if (item.Kind == ProcessEventKind.Exited && item.ExitTime is null)
                errors["exit"] = ["Exit events require an exit timestamp."];
        }
        return errors;
    }
}
