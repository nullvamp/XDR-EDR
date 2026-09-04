using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<PersistenceObjectKind>))]
public enum PersistenceObjectKind { Service, ScheduledTask, PersistenceConfiguration }
[JsonConverter(typeof(JsonStringEnumConverter<PersistenceEventKind>))]
public enum PersistenceEventKind
{
    ServiceCreated, ServiceDeleted, ServiceConfigurationChanged, ServiceStarted, ServiceStopped, ServiceStateChanged,
    ScheduledTaskRegistered, ScheduledTaskUpdated, ScheduledTaskDeleted, ScheduledTaskEnabled, ScheduledTaskDisabled,
    ScheduledTaskExecutionStarted, ScheduledTaskExecutionCompleted,
    WmiFilterCreated, WmiFilterModified, WmiFilterDeleted,
    WmiConsumerCreated, WmiConsumerModified, WmiConsumerDeleted,
    WmiBindingCreated, WmiBindingDeleted,
    ComRegistrationCreated, ComRegistrationModified, ComRegistrationDeleted,
    AutorunCreated, AutorunModified, AutorunDeleted,
    StartupItemCreated, StartupItemModified, StartupItemDeleted,
    PersistenceConfigurationObserved
}

public sealed record NativeEventIdentity(string Channel, string Provider, string? ProviderGuid,
    int EventId, byte? Version, byte? Level, short? Opcode, int? Task, long? RecordId,
    string NativeOperation, string? NativeStatus);
public sealed record PersistenceProcessRelationship(string? ProcessEntityId, int? ProcessId,
    DateTimeOffset? ProcessStartTime, string? User, int? SessionId, string AttributionSource,
    string AttributionConfidence, string CorrelationMechanism, bool Ambiguous = false);
public sealed record ServiceEvidence(string EntityId, string Name, string? DisplayName,
    string? ServiceType, string? State, string? StartupType, string? ErrorControl,
    string? BinaryPath, string? NormalizedBinaryPath, string? Account, string? Description,
    string[] Dependencies, bool? DriverService, bool? InteractiveService, string? NativeIdentity,
    DateTimeOffset? CreatedAt, DateTimeOffset? DeletedAt, int ConfigurationVersion,
    PersistenceProcessRelationship? Process, string? ConfiguredFileEntityId = null);
public sealed record ScheduledTaskAction(string Type, string? Executable, string? Arguments,
    string? WorkingDirectory, string? ComHandlerClassId, bool Redacted);
public sealed record ScheduledTaskTrigger(string Type, DateTimeOffset? StartBoundary,
    DateTimeOffset? EndBoundary, string? RepetitionInterval, string? ExecutionTimeLimit);
public sealed record ScheduledTaskEvidence(string EntityId, string Name, string Path, string Folder,
    string? Uri, int Version, bool? Enabled, bool? Hidden, string? Principal, string? LogonType,
    string? RunLevel, string? Author, ScheduledTaskAction[] Actions, ScheduledTaskTrigger[] Triggers,
    string? InstanceId, string? ExecutionResult, DateTimeOffset? RegisteredAt,
    DateTimeOffset? DeletedAt, PersistenceProcessRelationship? Process,
    string? PolicyControlledXmlSha256 = null, string? ConfiguredFileEntityId = null);
public sealed record PersistenceConfigurationEvidence(string EntityId, string Category, string Subtype,
    string NativeObjectIdentity, string? NamespaceOrLocation, string Name, string? RegistryPath,
    string? RegistryView, string? Scope, string? FilePath, string? ActionPath, string? Arguments,
    string? Principal, string? TriggerMetadata, string? ConsumerMetadata, string? BindingIdentity,
    string? FilterIdentity, string? ConsumerIdentity, string[] RawEvidenceEventIds,
    string? RegistryEntityId, string? FileEntityId, string? ConfiguredFileEntityId,
    string MappingRule, string MappingVersion, string RelationshipConfidence,
    bool RelationshipAmbiguous, DateTimeOffset FirstObserved, DateTimeOffset LastObserved,
    DateTimeOffset? CreatedAt, DateTimeOffset? DeletedAt, long Generation, string CurrentState,
    bool Redacted = false);

public sealed record PersistenceObservation(Guid EventId, string SchemaVersion,
    PersistenceObjectKind ObjectKind, PersistenceEventKind Kind, Guid EndpointId, Guid AgentId,
    string InstallationId, string CollectorId, string CollectorSource, string CollectorVersion,
    string SourcePlatform, NativeEventIdentity Native, long Sequence, DateTimeOffset ObservedAt,
    DateTimeOffset? ReceivedAt, DateTimeOffset? IngestedAt, string NormalizationVersion,
    string EvidenceSha256, string[] DataQualityFlags, string QualityState, ServiceEvidence? Service,
    ScheduledTaskEvidence? ScheduledTask, string? AssociatedUser, bool Late = false,
    bool OutOfOrder = false, PersistenceConfigurationEvidence? Configuration = null);

public sealed record PersistenceEventBatch(Guid BatchId, Guid EndpointId, Guid AgentId,
    string InstallationId, long FirstSequence, long LastSequence,
    IReadOnlyList<PersistenceObservation> Events, string ContentSha256,
    string SchemaVersion = "persistence-batch.v1", string Compression = "gzip");
public sealed record PersistenceBatchAcknowledgement(Guid BatchId, IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds, IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough, bool GapDetected);
public sealed record PersistenceIngestResult(PersistenceBatchAcknowledgement Acknowledgement,
    int Accepted, int Duplicates, int Rejected, int SequenceGaps);
public sealed record PersistenceSearchRequest(PersistenceObjectKind? ObjectKind = null,
    Guid? EndpointId = null, string? Name = null, string? Path = null, string? Account = null,
    string? State = null, string? Type = null, string? Process = null, string? User = null,
    string? Quality = null, DateTimeOffset? From = null, DateTimeOffset? To = null,
    int PageSize = 100, string? Cursor = null, string? Category = null, string? Subtype = null,
    string? Scope = null, string? Namespace = null, string? ConsumerType = null);
public sealed record PersistenceEventPage(IReadOnlyList<PersistenceObservation> Items, string? NextCursor);

public sealed record PersistenceTelemetryHealth(Guid EndpointId, bool Enabled,
    string ServiceCollectorState, string TaskCollectorState, DateTimeOffset? LastSourceEvent,
    DateTimeOffset? LastAcceptedEvent, long SourceEvents, long ServiceCreate, long ServiceDelete,
    long ServiceConfiguration, long ServiceState, long TaskRegistration, long TaskUpdate,
    long TaskDelete, long TaskExecutionStart, long TaskExecutionCompletion,
    long NormalizationFailures, long RelationshipFailures, long SourceGaps, long SequenceGaps,
    long QueueDepth, long OldestQueuedSeconds, long QueueDrops, long ExcludedEvents,
    long Duplicates, long Rejections, string PolicyVersion, int? AppliedVersion, bool Drift,
    DateTimeOffset? LastUpload, long LastSequence, bool Elevated, string[] KnownLimitations,
    long WmiObjects = 0, long WmiBindings = 0, long ComRegistrations = 0,
    long AutorunStartupEvents = 0, long RawRegistryInputs = 0, long RawFileInputs = 0,
    long OrphanRelationships = 0, string ConfigurationCollectorState = "unknown");

public sealed record PersistenceExclusionRule(Guid Id, string Category, string Pattern,
    bool Enabled = true, string Reason = "", string Creator = "",
    DateTimeOffset? CreatedAt = null, long MatchCount = 0);
public sealed record PersistenceTelemetryPolicy(string Version = "persistence-policy.v1",
    bool ServicesEnabled = true, bool ServiceCreation = true, bool ServiceDeletion = true,
    bool ServiceConfiguration = true, bool ServiceStateChanges = true,
    bool ServiceProcessRelationships = true, bool DriverServices = true,
    bool TasksEnabled = true, bool TaskRegistration = true, bool TaskUpdates = true,
    bool TaskDeletion = true, bool TaskEnableDisable = true, bool TaskExecutionEvents = true,
    bool TaskProcessRelationships = true, bool ActionMetadata = true,
    bool TriggerMetadata = true, bool CaptureArguments = false, bool CaptureTaskXml = false,
    bool RedactSecretLikeArguments = true, int MaximumCommandLength = 4096,
    int MaximumTaskXmlBytes = 262144, string[]? IncludedServiceNames = null,
    string[]? ExcludedServiceNames = null, string[]? IncludedTaskPaths = null,
    string[]? ExcludedTaskPaths = null, string[]? ExcludedProcesses = null,
    string[]? ExcludedUsers = null, long MaximumQueueBytes = 128 * 1024 * 1024,
    int MaximumQueueAgeHours = 24, int MaximumBatchEvents = 200,
    int MaximumBatchBytes = 1024 * 1024, int FlushSeconds = 5,
    bool DiagnosticMode = false, bool ElevatedWholeTelemetryDisableConfirmed = false,
    IReadOnlyList<PersistenceExclusionRule>? ExclusionRules = null,
    bool WmiSubscriptionsEnabled = true, bool ComRegistrationEnabled = true,
    bool AutorunStartupEnabled = true, bool StartupFolderEnabled = true,
    bool IfeoMetadataEnabled = true, bool WinlogonMetadataEnabled = true,
    bool AppInitAppCertMetadataEnabled = true, bool LsaPackageMetadataEnabled = true,
    string[]? IncludedPersistenceCategories = null, string[]? ExcludedPersistenceCategories = null,
    string[]? IncludedPersistencePaths = null, string[]? ExcludedPersistencePaths = null);
public sealed record PersistencePolicyVersion(Guid Id, string TenantId, string Name, int Version,
    PersistenceTelemetryPolicy Policy, string Sha256, string Status, DateTimeOffset CreatedAt,
    string CreatedBy);
public sealed record EffectivePersistencePolicy(PersistencePolicyVersion Policy,
    string AssignmentSource, Guid EndpointId, DateTimeOffset? AcknowledgedAt,
    int? AppliedVersion, int? RejectedVersion, string? ValidationError, bool Drift);
public sealed record PersistencePolicyAcknowledgement(Guid PolicyId, int Version, bool Applied,
    string? ValidationError, DateTimeOffset AcknowledgedAt);

public static partial class PersistenceSafety
{
    static readonly string[] Categories = ["service-name", "service-type", "service-executable",
        "task-path", "task-path-prefix", "task-name", "task-action", "process", "user",
        "persistence-category", "persistence-path", "wmi-namespace", "wmi-object"];
    [GeneratedRegex("(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization)\\s*[:=]\\s*(?:\\\"[^\\\"]*\\\"|[^\\s]+)", RegexOptions.CultureInvariant)]
    private static partial Regex SecretPattern();

    public static bool IsDriverServiceType(string? value) => value is not null &&
        (value.Contains("driver", StringComparison.OrdinalIgnoreCase) ||
         value.Equals("1", StringComparison.Ordinal) || value.Equals("2", StringComparison.Ordinal));

    public static IReadOnlyDictionary<string, string[]> Validate(PersistenceTelemetryPolicy policy)
    {
        var errors = new Dictionary<string, string[]>();
        if (!policy.ServicesEnabled && !policy.TasksEnabled && !policy.WmiSubscriptionsEnabled &&
            !policy.ComRegistrationEnabled && !policy.AutorunStartupEnabled && !policy.StartupFolderEnabled &&
            !policy.ElevatedWholeTelemetryDisableConfirmed)
            errors["enabled"] = ["Disabling all persistence telemetry requires elevated confirmation."];
        if (policy.MaximumCommandLength is < 0 or > 32767 || policy.MaximumTaskXmlBytes is < 1024 or > 1048576)
            errors["metadata"] = ["Metadata bounds are invalid."];
        if (policy.MaximumQueueBytes is < 1048576 or > 4294967296L || policy.MaximumQueueAgeHours is < 1 or > 720)
            errors["queue"] = ["Queue bounds are invalid."];
        if (policy.MaximumBatchEvents is < 1 or > 1000 || policy.MaximumBatchBytes is < 1024 or > 4194304 || policy.FlushSeconds is < 1 or > 300)
            errors["batch"] = ["Batch bounds are invalid."];
        foreach (var pattern in (policy.IncludedServiceNames ?? []).Concat(policy.ExcludedServiceNames ?? []).Concat(policy.IncludedTaskPaths ?? []).Concat(policy.ExcludedTaskPaths ?? []).Concat(policy.IncludedPersistenceCategories ?? []).Concat(policy.ExcludedPersistenceCategories ?? []).Concat(policy.IncludedPersistencePaths ?? []).Concat(policy.ExcludedPersistencePaths ?? []))
            if (UnsafePattern(pattern)) errors[$"pattern.{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pattern ?? "")))[..8]}"] = ["Unsafe match pattern."];
        foreach (var rule in policy.ExclusionRules ?? [])
            if (!Categories.Contains(rule.Category, StringComparer.Ordinal) || UnsafePattern(rule.Pattern)) errors[$"exclusion.{rule.Id}"] = ["Unsafe exclusion."];
        return errors;
    }

    public static string? BoundAndRedact(string? value, PersistenceTelemetryPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(value) || policy.MaximumCommandLength == 0) return null;
        var bounded = value.Length > policy.MaximumCommandLength ? value[..policy.MaximumCommandLength] : value;
        return policy.RedactSecretLikeArguments ? SecretPattern().Replace(bounded, "$1=[REDACTED]") : bounded;
    }

    public static bool TryParseTaskXml(string xml, PersistenceTelemetryPolicy policy,
        out ScheduledTaskAction[] actions, out ScheduledTaskTrigger[] triggers, out string? hash,
        out string? error)
    {
        actions = []; triggers = []; hash = null; error = null;
        if (!policy.CaptureTaskXml) return true;
        if (Encoding.UTF8.GetByteCount(xml) > policy.MaximumTaskXmlBytes) { error = "task-xml-size-limit"; return false; }
        try
        {
            using var sr = new StringReader(xml);
            using var reader = XmlReader.Create(sr, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = policy.MaximumTaskXmlBytes });
            var document = XDocument.Load(reader, LoadOptions.None);
            XNamespace ns = document.Root?.Name.Namespace ?? XNamespace.None;
            actions = document.Descendants(ns + "Actions").Elements().Take(32).Select(x =>
                new ScheduledTaskAction(x.Name.LocalName,
                    x.Element(ns + "Command")?.Value is { } command ? BoundAndRedact(command, policy) : null,
                    policy.CaptureArguments ? BoundAndRedact(x.Element(ns + "Arguments")?.Value, policy) : null,
                    BoundAndRedact(x.Element(ns + "WorkingDirectory")?.Value, policy),
                    x.Element(ns + "ClassId")?.Value, !policy.CaptureArguments)).ToArray();
            triggers = document.Descendants(ns + "Triggers").Elements().Take(64).Select(x =>
                new ScheduledTaskTrigger(x.Name.LocalName,
                    DateTimeOffset.TryParse(x.Element(ns + "StartBoundary")?.Value, out var start) ? start : null,
                    DateTimeOffset.TryParse(x.Element(ns + "EndBoundary")?.Value, out var end) ? end : null,
                    x.Descendants(ns + "Interval").FirstOrDefault()?.Value,
                    x.Descendants(ns + "ExecutionTimeLimit").FirstOrDefault()?.Value)).ToArray();
            hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(xml))).ToLowerInvariant();
            return true;
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException)
        { error = "task-xml-invalid"; return false; }
    }

    public static string EntityId(Guid endpoint, string installation, PersistenceObjectKind kind,
        string canonicalName, long generation) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{endpoint:D}:{installation}:{kind}:{canonicalName.Normalize(NormalizationForm.FormKC).ToUpperInvariant()}:{generation}"))).ToLowerInvariant();
    public static string EvidenceHash<T>(T value) => Convert.ToHexString(SHA256.HashData(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value))).ToLowerInvariant();
    public static bool SafeName(string? value, int maximum = 32767) => !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    static bool UnsafePattern(string? value) => string.IsNullOrWhiteSpace(value) || value.Trim() is "*" or "**" or "\\" or "/" || value.Length > 32767 || value.Any(char.IsControl) || value.Count(x => x is '*' or '?') > 8;
}

public interface IPersistenceTelemetryRepository
{
    Task<PersistenceIngestResult> IngestAsync(string tenant, PersistenceEventBatch batch, PersistenceTelemetryHealth health, CancellationToken ct);
    Task<PersistenceEventPage> SearchAsync(string tenant, PersistenceSearchRequest request, CancellationToken ct);
    Task<PersistenceObservation?> GetAsync(string tenant, Guid eventId, CancellationToken ct);
    Task<PersistenceEventPage> EntityHistoryAsync(string tenant, Guid endpoint, string entityId, int limit, CancellationToken ct);
    Task<PersistenceTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task<IReadOnlyList<PersistenceObservation>> ListAllAsync(CancellationToken ct);
    Task<int> ReconcileEvidenceAsync(int limit, CancellationToken ct);
}
public interface IPersistenceProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(string tenant, PersistenceObservation value, CancellationToken ct);
    Task<PersistenceEventPage> SearchAsync(string tenant, PersistenceSearchRequest request, CancellationToken ct);
    Task<bool> HealthAsync(CancellationToken ct);
}
public interface IPersistencePolicyRepository
{
    Task<IReadOnlyList<PersistencePolicyVersion>> ListAsync(string tenant, CancellationToken ct);
    Task<PersistencePolicyVersion> CreateAsync(string tenant, string actor, string name, PersistenceTelemetryPolicy policy, CancellationToken ct);
    Task AssignAsync(string tenant, Guid policyId, Guid? endpoint, string actor, CancellationToken ct);
    Task<EffectivePersistencePolicy> EffectiveAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task AcknowledgeAsync(string tenant, Guid endpoint, PersistencePolicyAcknowledgement acknowledgement, CancellationToken ct);
}
public sealed record PersistenceExportCreateRequest(string Format, PersistenceSearchRequest Query,
    string[]? Fields = null, int MaximumRecords = 10000);
public sealed record PersistenceExportJob(Guid Id, string TenantId, string CreatedBy,
    FileExportState State, string Format, PersistenceSearchRequest Query, string[] Fields,
    int MaximumRecords, Guid OutputObjectId, Guid ManifestObjectId, Guid MetadataObjectId,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset ExpiresAt,
    DateTimeOffset? StartedAt = null, DateTimeOffset? CompletedAt = null,
    int? RecordCount = null, long? OutputSize = null, string? OutputSha256 = null,
    string? ErrorCode = null, string? ErrorSummary = null);
public interface IPersistenceExportRepository
{
    Task<PersistenceExportJob> CreateAsync(string tenant, string actor, PersistenceExportCreateRequest request, CancellationToken ct);
    Task<PersistenceExportJob?> GetAsync(string tenant, Guid id, CancellationToken ct);
    Task<PersistenceExportJob?> ClaimAsync(CancellationToken ct);
    Task CompleteAsync(Guid id, int count, long size, string sha256, DateTimeOffset at, CancellationToken ct);
    Task FailAsync(Guid id, string code, string summary, CancellationToken ct);
    Task<IReadOnlyList<PersistenceExportJob>> ExpireDueAsync(CancellationToken ct);
}
