using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<IdentityEventKind>))]
public enum IdentityEventKind
{
    LogonStarted, LogonFailed, Logoff, ExplicitCredentialsObserved,
    SessionCreated, SessionEnded, SessionStateChanged,
    TokenObserved, TokenAssigned, PrivilegeAssigned, PrivilegeUsed, GroupContextObserved
}

public sealed record IdentityNativeEvidence(string Channel, string Provider, string? ProviderGuid,
    int EventId, byte? Version, byte? Level, short? Opcode, int? Task, long? RecordId,
    string NativeOperation, string? NativeStatus, string RawEvidenceSha256);
public sealed record AccountIdentity(string? Sid, string? Name, string? Domain, string? CanonicalName,
    bool? MachineAccount, bool? BuiltInService, string? SidType, string Source);
public sealed record LogonIdentity(string EntityId, string? LogonId, int? NativeLogonType,
    string? LogonTypeLabel, string? AuthenticationPackage, string? LogonProcess,
    string? Workstation, string? SourceHost, string? SourceIp, int? SourcePort,
    string? LinkedLogonId, string? Result, string? Status, string? SubStatus,
    string? FailureReason, DateTimeOffset FirstObserved, DateTimeOffset LastObserved,
    DateTimeOffset? StartedAt, DateTimeOffset? EndedAt, bool IncompleteLifecycle);
public sealed record WindowsSessionIdentity(string EntityId, int? SessionId, int? TerminalSessionId,
    string? Protocol, bool? Remote, string? ClientAddress, string? ClientName,
    string? State, DateTimeOffset FirstObserved, DateTimeOffset LastObserved,
    DateTimeOffset? CreatedAt, DateTimeOffset? EndedAt, long Generation);
public sealed record TokenIdentity(string EntityId, string Provenance, string? TokenType,
    string? ImpersonationLevel, string? ElevationType, bool? Elevated, string? IntegrityLevel,
    string? IntegritySid, bool? Restricted, bool? AppContainer, bool? VirtualizationAllowed,
    bool? VirtualizationEnabled, int? SessionId, string? TokenSource, string? LinkedTokenId,
    DateTimeOffset FirstObserved, DateTimeOffset LastObserved);
public sealed record PrivilegeIdentity(string Name, string State, bool? Enabled, bool? EnabledByDefault,
    bool? Removed, bool? UsedForAccess, string Source);
public sealed record IdentityProcessRelationship(string ProcessEntityId, int ProcessId,
    DateTimeOffset ProcessStartTime, string? ImagePath, int? SessionId, string Mechanism,
    string Confidence, bool PidReuseProtected);
public sealed record GroupIdentity(string Sid, string? Name, uint? Attributes, string Source);

public sealed record IdentityObservation(Guid EventId, string SchemaVersion, IdentityEventKind Kind,
    Guid EndpointId, Guid AgentId, string InstallationId, string CollectorId, string CollectorSource,
    string CollectorVersion, string SourcePlatform, IdentityNativeEvidence Native, long Sequence,
    DateTimeOffset ObservedAt, DateTimeOffset? ReceivedAt, DateTimeOffset? IngestedAt,
    string NormalizationVersion, string EvidenceSha256, string[] DataQualityFlags,
    string QualityState, AccountIdentity? Account, LogonIdentity? Logon,
    WindowsSessionIdentity? Session, TokenIdentity? Token, PrivilegeIdentity[] Privileges,
    GroupIdentity[] Groups, IdentityProcessRelationship? Process, string? Principal,
    bool Late = false, bool OutOfOrder = false);
public sealed record IdentityEventBatch(Guid BatchId, Guid EndpointId, Guid AgentId,
    string InstallationId, long FirstSequence, long LastSequence,
    IReadOnlyList<IdentityObservation> Events, string ContentSha256,
    string SchemaVersion = "identity-batch.v1", string Compression = "gzip");
public sealed record IdentityBatchAcknowledgement(Guid BatchId, IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds, IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough, bool GapDetected);
public sealed record IdentityIngestResult(IdentityBatchAcknowledgement Acknowledgement,
    int Accepted, int Duplicates, int Rejected, int SequenceGaps);
public sealed record IdentitySearchRequest(Guid? EndpointId = null, string? Account = null,
    string? Sid = null, string? Domain = null, int? LogonType = null, string? Result = null,
    string? SourceIp = null, bool? RemoteSession = null, int? SessionId = null,
    string? IntegrityLevel = null, bool? ElevatedToken = null, string? Privilege = null,
    string? Process = null, string? Quality = null, IdentityEventKind? Kind = null,
    DateTimeOffset? From = null, DateTimeOffset? To = null, int PageSize = 100,
    string? Cursor = null);
public sealed record IdentityEventPage(IReadOnlyList<IdentityObservation> Items, string? NextCursor);

public sealed record IdentityTelemetryHealth(Guid EndpointId, bool Enabled, string SecurityCollectorState,
    string SessionCollectorState, string TokenCollectorState, DateTimeOffset? LastSourceEvent,
    DateTimeOffset? LastAcceptedEvent, long SuccessfulLogons, long FailedLogons, long Logoffs,
    long SessionEvents, long RdpEvents, long TokenObservations, long PrivilegeObservations,
    long ProcessRelationshipFailures, long MissingLogonCorrelation, long SourceGaps,
    long SequenceGaps, long QueueDepth, long OldestQueuedSeconds, long QueueDrops,
    long ExcludedEvents, long Duplicates, long Rejections, string PolicyVersion,
    int? AppliedVersion, bool Drift, DateTimeOffset? LastUpload, long LastSequence,
    bool Elevated, string[] KnownLimitations, double? ProjectionLatencyMilliseconds = null,
    double? SearchLatencyMilliseconds = null);
public sealed record IdentityExclusionRule(Guid Id, string Category, string Pattern,
    bool Enabled = true, string Reason = "", string Creator = "",
    DateTimeOffset? CreatedAt = null, long MatchCount = 0);
public sealed record IdentityTelemetryPolicy(string Version = "identity-policy.v1",
    bool Enabled = true, bool SuccessfulLogons = true, bool FailedLogons = true,
    bool Logoffs = true, bool SessionState = true, bool RdpSessions = true,
    bool SpecialPrivileges = true, bool GroupContext = true, bool TokenState = true,
    bool IntegrityElevation = true, bool ProcessRelationships = true,
    bool SourceIpMetadata = true, int[]? IncludedLogonTypes = null,
    int[]? ExcludedLogonTypes = null, string[]? ExcludedAccounts = null,
    string[]? ExcludedSids = null, string[]? ExcludedDomains = null,
    string[]? ExcludedProcesses = null, string[]? ExcludedPrivileges = null,
    bool ExcludeMachineAccounts = false, bool ExcludeServiceAccounts = false,
    long MaximumQueueBytes = 128 * 1024 * 1024, int MaximumQueueAgeHours = 24,
    int MaximumBatchEvents = 200, int MaximumBatchBytes = 1024 * 1024,
    int FlushSeconds = 5, int TokenSnapshotSeconds = 30,
    int MaximumTokenProcesses = 512, int MaximumGroups = 256,
    int MaximumPrivileges = 128, bool DiagnosticMode = false,
    bool ElevatedWholeTelemetryDisableConfirmed = false,
    IReadOnlyList<IdentityExclusionRule>? ExclusionRules = null);
public sealed record IdentityPolicyVersion(Guid Id, string TenantId, string Name, int Version,
    IdentityTelemetryPolicy Policy, string Sha256, string Status, DateTimeOffset CreatedAt,
    string CreatedBy);
public sealed record EffectiveIdentityPolicy(IdentityPolicyVersion Policy, string AssignmentSource,
    Guid EndpointId, DateTimeOffset? AcknowledgedAt, int? AppliedVersion, int? RejectedVersion,
    string? ValidationError, bool Drift);
public sealed record IdentityPolicyAcknowledgement(Guid PolicyId, int Version, bool Applied,
    string? ValidationError, DateTimeOffset AcknowledgedAt);

public static partial class IdentitySafety
{
    static readonly string[] Categories = ["account-sid", "account-name", "domain", "machine-account",
        "logon-type", "session-type", "process", "privilege"];
    [GeneratedRegex("^S-1-(?:\\d+-){1,14}\\d+$", RegexOptions.CultureInvariant)]
    private static partial Regex SidPattern();
    [GeneratedRegex("^[A-Za-z][A-Za-z0-9]{1,127}Privilege$", RegexOptions.CultureInvariant)]
    private static partial Regex PrivilegePattern();
    public static bool ValidSid(string? value) => value is not null && value.Length <= 184 && SidPattern().IsMatch(value);
    public static bool ValidPrivilege(string? value) => value is not null && PrivilegePattern().IsMatch(value);
    public static bool ValidHash(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    public static bool ValidObservation(IdentityObservation value, Guid endpoint, Guid agent, string installation)
    {
        var entity = value.Logon?.EntityId ?? value.Session?.EntityId ?? value.Token?.EntityId ?? value.Process?.ProcessEntityId;
        return value.EventId != Guid.Empty && value.SchemaVersion == "identity-event.v1" &&
            value.EndpointId == endpoint && value.AgentId == agent && value.InstallationId == installation &&
            value.Sequence > 0 && value.ObservedAt != default && entity is { Length: 64 } && ValidHash(entity) &&
            ValidHash(value.EvidenceSha256) && ValidHash(value.Native.RawEvidenceSha256) &&
            SafeText(value.Native.Channel, 256) && SafeText(value.Native.Provider, 256) &&
            SafeText(value.Native.NativeOperation, 256) && SafeText(value.Native.NativeStatus, 256) &&
            (value.Account?.Sid is null || ValidSid(value.Account.Sid)) &&
            SafeText(value.Account?.Name, 256) && SafeText(value.Account?.Domain, 256) &&
            SafeText(value.Account?.CanonicalName, 512) && SafeText(value.Principal, 512) &&
            (value.Logon?.SourceIp is null || System.Net.IPAddress.TryParse(value.Logon.SourceIp, out _)) &&
            (value.Token?.IntegritySid is null || ValidSid(value.Token.IntegritySid)) &&
            value.Privileges is { Length: <= 512 } && value.Privileges.All(x => ValidPrivilege(x.Name) && SafeText(x.State, 64)) &&
            value.Groups is { Length: <= 1024 } && value.Groups.All(x => ValidSid(x.Sid) && SafeText(x.Name, 256)) &&
            (value.Process is null || value.Process.ProcessId > 0 && value.Process.ProcessStartTime != default &&
                value.Process.ProcessEntityId is { Length: 64 } && ValidHash(value.Process.ProcessEntityId) && SafeText(value.Process.ImagePath, 32767));
    }
    public static string LogonTypeLabel(int value) => value switch
    {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        12 => "CachedRemoteInteractive",
        13 => "CachedUnlock",
        _ => $"Native-{value}"
    };
    public static IReadOnlyDictionary<string, string[]> Validate(IdentityTelemetryPolicy policy)
    {
        var errors = new Dictionary<string, string[]>();
        if (!policy.Enabled && !policy.ElevatedWholeTelemetryDisableConfirmed)
            errors["enabled"] = ["Disabling all identity telemetry requires elevated confirmation."];
        if (policy.MaximumQueueBytes is < 1048576 or > 4294967296L || policy.MaximumQueueAgeHours is < 1 or > 720)
            errors["queue"] = ["Queue bounds are invalid."];
        if (policy.MaximumBatchEvents is < 1 or > 1000 || policy.MaximumBatchBytes is < 1024 or > 4194304 || policy.FlushSeconds is < 1 or > 300)
            errors["batch"] = ["Batch bounds are invalid."];
        if (policy.TokenSnapshotSeconds is < 5 or > 3600 || policy.MaximumTokenProcesses is < 1 or > 4096 || policy.MaximumGroups is < 0 or > 1024 || policy.MaximumPrivileges is < 0 or > 512)
            errors["enrichment"] = ["Token enrichment bounds are invalid."];
        foreach (var sid in policy.ExcludedSids ?? []) if (!ValidSid(sid)) errors[$"sid.{Hash8(sid)}"] = ["Malformed SID."];
        foreach (var value in (policy.ExcludedAccounts ?? []).Concat(policy.ExcludedDomains ?? []).Concat(policy.ExcludedProcesses ?? []))
            if (Unsafe(value)) errors[$"pattern.{Hash8(value)}"] = ["Unsafe exclusion pattern."];
        foreach (var value in policy.ExcludedPrivileges ?? []) if (!ValidPrivilege(value)) errors[$"privilege.{Hash8(value)}"] = ["Malformed privilege name."];
        foreach (var rule in policy.ExclusionRules ?? [])
            if (!Categories.Contains(rule.Category, StringComparer.Ordinal) || Unsafe(rule.Pattern) || rule.Category == "account-sid" && !ValidSid(rule.Pattern))
                errors[$"exclusion.{rule.Id}"] = ["Unsafe identity exclusion."];
        return errors;
    }
    public static string LogonEntityId(Guid endpoint, string installation, string? luid,
        string? sid, DateTimeOffset observed) => Hash($"{endpoint:D}:{installation}:logon:{luid ?? $"unknown:{observed.UtcTicks}"}:{sid ?? "unknown"}");
    public static string SessionEntityId(Guid endpoint, string installation, int? session,
        long generation) => Hash($"{endpoint:D}:{installation}:session:{session?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"}:{generation}");
    public static string TokenEntityId(Guid endpoint, string processEntity, string? tokenType,
        string? sid) => Hash($"{endpoint:D}:token:{processEntity}:{tokenType}:{sid}");
    public static string EvidenceHash<T>(T value) => Hash(JsonSerializer.Serialize(value));
    public static bool SafeText(string? value, int maximum = 32767) => value is null || value.Length <= maximum && !value.Any(char.IsControl);
    static bool Unsafe(string? value) => string.IsNullOrWhiteSpace(value) || value.Trim() is "*" or "**" or "\\" or "/" || value.Length > 256 || value.Any(char.IsControl) || value.Count(x => x is '*' or '?') > 4;
    static string Hash8(string? value) => Hash(value ?? "")[..8];
    static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.Normalize(NormalizationForm.FormKC)))).ToLowerInvariant();
}

public interface IIdentityTelemetryRepository
{
    Task<IdentityIngestResult> IngestAsync(string tenant, IdentityEventBatch batch, IdentityTelemetryHealth health, CancellationToken ct);
    Task<IdentityEventPage> SearchAsync(string tenant, IdentitySearchRequest request, CancellationToken ct);
    Task<IdentityObservation?> GetAsync(string tenant, Guid eventId, CancellationToken ct);
    Task<IdentityEventPage> EntityHistoryAsync(string tenant, Guid endpoint, string entityId, int limit, CancellationToken ct);
    Task<IdentityTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task<IReadOnlyList<IdentityObservation>> ListAllAsync(CancellationToken ct);
}
public interface IIdentityProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(string tenant, IdentityObservation value, CancellationToken ct);
    Task<IdentityEventPage> SearchAsync(string tenant, IdentitySearchRequest request, CancellationToken ct);
    Task<bool> HealthAsync(CancellationToken ct);
}
public interface IIdentityPolicyRepository
{
    Task<IReadOnlyList<IdentityPolicyVersion>> ListAsync(string tenant, CancellationToken ct);
    Task<IdentityPolicyVersion> CreateAsync(string tenant, string actor, string name, IdentityTelemetryPolicy policy, CancellationToken ct);
    Task AssignAsync(string tenant, Guid policyId, Guid? endpoint, string actor, CancellationToken ct);
    Task<EffectiveIdentityPolicy> EffectiveAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task AcknowledgeAsync(string tenant, Guid endpoint, IdentityPolicyAcknowledgement acknowledgement, CancellationToken ct);
}
public sealed record IdentityExportCreateRequest(string Format, IdentitySearchRequest Query,
    string[]? Fields = null, int MaximumRecords = 10000);
public sealed record IdentityExportJob(Guid Id, string TenantId, string CreatedBy,
    FileExportState State, string Format, IdentitySearchRequest Query, string[] Fields,
    int MaximumRecords, Guid OutputObjectId, Guid ManifestObjectId, Guid MetadataObjectId,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset ExpiresAt,
    DateTimeOffset? StartedAt = null, DateTimeOffset? CompletedAt = null, int? RecordCount = null,
    long? OutputSize = null, string? OutputSha256 = null, string? ErrorCode = null,
    string? ErrorSummary = null);
public interface IIdentityExportRepository
{
    Task<IdentityExportJob> CreateAsync(string tenant, string actor, IdentityExportCreateRequest request, CancellationToken ct);
    Task<IdentityExportJob?> GetAsync(string tenant, Guid id, CancellationToken ct);
    Task<IdentityExportJob?> ClaimAsync(CancellationToken ct);
    Task CompleteAsync(Guid id, int count, long size, string sha256, DateTimeOffset at, CancellationToken ct);
    Task FailAsync(Guid id, string code, string summary, CancellationToken ct);
}
