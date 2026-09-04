using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<ModuleEventKind>))]
public enum ModuleEventKind { ImageLoaded, ImageUnloaded, DriverLoaded, DriverUnloaded }
[JsonConverter(typeof(JsonStringEnumConverter<ModuleLifecycleState>))]
public enum ModuleLifecycleState { Loaded, Unloaded, Replaced, Recreated, Unknown, IncompleteLifecycle }
[JsonConverter(typeof(JsonStringEnumConverter<ModuleMode>))]
public enum ModuleMode { Unknown, User, Kernel }
[JsonConverter(typeof(JsonStringEnumConverter<ModuleHashState>))]
public enum ModuleHashState { NotRequested, Pending, Succeeded, ChangedDuringHash, ReplacedDuringHash, TooLarge, PermissionDenied, Failed, Unavailable }

public sealed record ModuleProcessRelationship(string? ProcessEntityId, int? ProcessId,
    DateTimeOffset? ProcessStartTime, string? Image, string? Path, string? User, int? SessionId,
    string AttributionSource, string AttributionConfidence);
public sealed record ModuleHashMetadata(ModuleHashState State = ModuleHashState.NotRequested,
    string Algorithm = "SHA-256", string? Value = null, string? FileIdentity = null,
    long? FileSize = null, DateTimeOffset? CapturedAt = null, string? FailureReason = null,
    string? PolicyVersion = null);
public sealed record ModuleSignerMetadata(string SignedState = "unknown",
    string VerificationStatus = "not-checked", string? Subject = null, string? Issuer = null,
    string? Thumbprint = null, string? TimestampState = null, DateTimeOffset? VerifiedAt = null,
    string? FailureState = null, string VerificationSource = "not-requested");

public sealed record ModuleObservation(Guid EventId, string SchemaVersion, ModuleEventKind Kind,
    Guid EndpointId, Guid AgentId, string InstallationId, string CollectorId,
    string CollectorSource, string CollectorVersion, string SourcePlatform, string NativeProvider,
    string? NativeProviderId, string? NativeEventId, int? NativeOpcode, long Sequence,
    DateTimeOffset ObservedAt, string NormalizationVersion, string? RawSha256,
    string[] DataQualityFlags, string SourceConfidence, string ModuleEntityId,
    string? NativeImageIdentity, string OriginalPath, string NormalizedPath, string Basename,
    string? BackingFileEntityId, FileNativeIdentity? BackingFileIdentity, long? ImageSize,
    ulong? PreferredImageBase, ulong? ActualLoadBase, ulong? LoadAddress, long? MappingSize,
    string? Architecture, string? MachineType, string ImageType, ModuleMode Mode, bool Driver,
    bool ExecutableImage, bool SharedLibrary, string? LoadResult, ModuleLifecycleState Lifecycle,
    ModuleHashMetadata Hash, ModuleSignerMetadata Signer, ModuleProcessRelationship? Process,
    string? User, DateTimeOffset? ReceivedAt = null, DateTimeOffset? IngestedAt = null,
    bool Late = false, bool OutOfOrder = false)
{
    public static bool TryNormalizePath(string value, bool windows, out string normalized, out string? error)
    {
        normalized = ""; error = null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 32767 || value.Any(char.IsControl)) { error = "Module path is empty, oversized, or contains controls."; return false; }
        var p = value.Trim().Replace('/', windows ? '\\' : '/');
        if (windows)
        {
            if (p.StartsWith("\\??\\", StringComparison.Ordinal)) p = p[4..];
            if (p.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) p = "%systemroot%\\" + p[12..];
            normalized = p.ToLowerInvariant();
        }
        else normalized = p;
        return true;
    }

    public static string StableEntityId(Guid endpoint, string installation, string? processEntity,
        DateTimeOffset? processStart, string? nativeIdentity, ulong? loadBase, string normalizedPath,
        DateTimeOffset observedAt, long sequence) => Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{endpoint:D}:{installation}:{processEntity}:{processStart?.UtcTicks}:{nativeIdentity}:{loadBase}:{normalizedPath}:{observedAt.UtcTicks}:{sequence}"))).ToLowerInvariant();
}

public sealed record ModuleEventBatch(Guid BatchId, Guid EndpointId, Guid AgentId,
    string InstallationId, long FirstSequence, long LastSequence, IReadOnlyList<ModuleObservation> Events,
    string ContentSha256, string SchemaVersion = "module-batch.v1", string Compression = "gzip");
public sealed record ModuleBatchAcknowledgement(Guid BatchId, IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds, IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough, bool GapDetected);
public sealed record ModuleIngestResult(ModuleBatchAcknowledgement Acknowledgement, int Accepted,
    int Duplicates, int Rejected, int SequenceGaps);
public sealed record ModuleSearchRequest(Guid? EndpointId = null, string? Process = null,
    string? Path = null, string? Basename = null, string? Sha256 = null, string? Signer = null,
    string? ImageType = null, ModuleMode? Mode = null, bool? Driver = null,
    ulong? LoadAddress = null, string? Architecture = null, string? User = null, DateTimeOffset? From = null,
    DateTimeOffset? To = null, string? Quality = null, int PageSize = 100, string? Cursor = null);
public sealed record ModuleEventPage(IReadOnlyList<ModuleObservation> Items, string? NextCursor);

public sealed record ModuleTelemetryHealth(Guid EndpointId, bool Enabled, string CollectorSource,
    string CollectorVersion, string NativeProvider, DateTimeOffset? LastSourceEvent,
    DateTimeOffset? LastAcceptedEvent, long NativeEvents, long UserLoads, long ExecutableLoads,
    long SharedLibraryLoads, long DriverLoads, long Unloads, long NormalizedEvents,
    long AttributionFailures, long FileIdentityFailures, long HashRequested, long HashCompleted,
    long HashFailed, long SignerRequested, long SignerCompleted, long SignerFailed,
    long SourceDrops, long SequenceGaps, long QueueDepth, long OldestQueuedSeconds,
    long QueueDrops, long ExcludedEvents, long Uploads, long Duplicates, long Rejections,
    string LastUploadResult, string PolicyVersion, int? AppliedVersion, bool Drift,
    DateTimeOffset? LastUpload, long LastSequence, bool Elevated, string[] KnownLimitations);

public sealed record ModuleExclusionRule(Guid Id, string Category, string Pattern, bool Enabled = true,
    string Reason = "", string Creator = "", DateTimeOffset? CreatedAt = null, long MatchCount = 0);
public sealed record ModuleTelemetryPolicy(string Version = "module-policy.v1", bool Enabled = true,
    bool UserModeModules = true, bool ExecutableImages = true, bool SharedLibraries = true,
    bool DriverLoads = true, bool UnloadEvents = false, bool Hashing = false,
    bool SignerMetadata = false, string[]? IncludedPaths = null, string[]? ExcludedPaths = null,
    string[]? IncludedProcesses = null, string[]? ExcludedProcesses = null,
    string[]? IncludedImageTypes = null, string[]? ExcludedImageTypes = null,
    long MaximumQueueBytes = 128 * 1024 * 1024, int MaximumQueueAgeHours = 24,
    int MaximumBatchEvents = 200, int MaximumBatchBytes = 1024 * 1024,
    int FlushSeconds = 5, int MaximumHashesPerMinute = 30,
    int MaximumSignersPerMinute = 30, long MaximumHashFileBytes = 256 * 1024 * 1024,
    bool DiagnosticMode = false, bool ElevatedWholeTelemetryDisableConfirmed = false,
    string CollectorSource = "auto", IReadOnlyList<ModuleExclusionRule>? ExclusionRules = null);
public sealed record ModulePolicyVersion(Guid Id, string TenantId, string Name, int Version,
    ModuleTelemetryPolicy Policy, string Sha256, string Status, DateTimeOffset CreatedAt, string CreatedBy);
public sealed record EffectiveModulePolicy(ModulePolicyVersion Policy, string AssignmentSource,
    Guid EndpointId, DateTimeOffset? AcknowledgedAt, int? AppliedVersion, int? RejectedVersion,
    string? ValidationError, bool Drift);
public sealed record ModulePolicyAcknowledgement(Guid PolicyId, int Version, bool Applied,
    string? ValidationError, DateTimeOffset AcknowledgedAt);

public static class ModulePolicyValidation
{
    static readonly string[] Types = ["dll", "executable", "driver", "shared-library", "image"];
    static readonly string[] Categories = ["path", "process", "image-type"];
    public static IReadOnlyDictionary<string, string[]> Validate(ModuleTelemetryPolicy p)
    {
        var e = new Dictionary<string, string[]>();
        if (!p.Enabled && !p.ElevatedWholeTelemetryDisableConfirmed) e["enabled"] = ["Whole module telemetry disable requires elevated confirmation."];
        if (p.CollectorSource is not ("auto" or "windows.kernel-image-etw" or "linux.unsupported")) e["collectorSource"] = ["Unsupported collector."];
        if (p.MaximumQueueBytes is < 1048576 or > 4294967296L || p.MaximumQueueAgeHours is < 1 or > 720) e["queue"] = ["Queue bounds are invalid."];
        if (p.MaximumBatchEvents is < 1 or > 1000 || p.MaximumBatchBytes is < 1024 or > 4194304 || p.FlushSeconds is < 1 or > 300) e["batch"] = ["Batch bounds are invalid."];
        if (p.MaximumHashesPerMinute is < 0 or > 600 || p.MaximumSignersPerMinute is < 0 or > 600 || p.MaximumHashFileBytes is < 1024 or > 1073741824) e["enrichment"] = ["Enrichment bounds are invalid."];
        foreach (var t in (p.IncludedImageTypes ?? []).Concat(p.ExcludedImageTypes ?? [])) if (!Types.Contains(t, StringComparer.OrdinalIgnoreCase)) e[$"imageType.{t}"] = ["Unsupported image type."];
        foreach (var x in (p.IncludedPaths ?? []).Concat(p.ExcludedPaths ?? [])) if (Unsafe(x)) e[$"path.{x}"] = ["Unsafe path pattern."];
        foreach (var r in p.ExclusionRules ?? []) if (!Categories.Contains(r.Category) || Unsafe(r.Pattern)) e[$"exclusion.{r.Id}"] = ["Unsafe exclusion."];
        return e;
    }
    static bool Unsafe(string? x) => string.IsNullOrWhiteSpace(x) || x.Trim() is "*" or "**" or "\\" or "/" || x.Length > 32767 || x.Any(char.IsControl) || x.Count(c => c is '*' or '?') > 8;
}

public static class ModuleEvidence { public static string Sha256<T>(T x) => Convert.ToHexString(SHA256.HashData(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(x))).ToLowerInvariant(); }
public interface IModuleTelemetryRepository
{
    Task<ModuleIngestResult> IngestAsync(string tenant, ModuleEventBatch batch, ModuleTelemetryHealth health, CancellationToken ct);
    Task<ModuleEventPage> SearchAsync(string tenant, ModuleSearchRequest request, CancellationToken ct);
    Task<ModuleObservation?> GetAsync(string tenant, Guid eventId, CancellationToken ct);
    Task<ModuleEventPage> ProcessHistoryAsync(string tenant, Guid endpoint, string processEntity, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<ModuleTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task<IReadOnlyList<ModuleObservation>> ListAllAsync(CancellationToken ct);
}
public interface IModuleProjection
{
    Task EnsureAsync(CancellationToken ct); Task UpsertAsync(string tenant, ModuleObservation value, CancellationToken ct);
    Task<ModuleEventPage> SearchAsync(string tenant, ModuleSearchRequest request, CancellationToken ct); Task<bool> HealthAsync(CancellationToken ct);
}
public interface IModulePolicyRepository
{
    Task<IReadOnlyList<ModulePolicyVersion>> ListAsync(string tenant, CancellationToken ct);
    Task<ModulePolicyVersion> CreateAsync(string tenant, string actor, string name, ModuleTelemetryPolicy policy, CancellationToken ct);
    Task AssignAsync(string tenant, Guid policyId, Guid? endpoint, string actor, CancellationToken ct);
    Task<EffectiveModulePolicy> EffectiveAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task AcknowledgeAsync(string tenant, Guid endpoint, ModulePolicyAcknowledgement ack, CancellationToken ct);
}
