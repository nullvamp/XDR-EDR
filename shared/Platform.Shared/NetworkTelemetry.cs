using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<NetworkEventKind>))]
public enum NetworkEventKind { ConnectionAttempted, ConnectionEstablished, ConnectionFailed, ConnectionClosed, ListenerStarted, ListenerStopped, DatagramObserved, OperationObserved }
[JsonConverter(typeof(JsonStringEnumConverter<NetworkDirection>))]
public enum NetworkDirection { Unknown, Outbound, Inbound, Local }
[JsonConverter(typeof(JsonStringEnumConverter<NetworkConnectionState>))]
public enum NetworkConnectionState { Unknown, Attempted, Established, Failed, Closed, Listening }
[JsonConverter(typeof(JsonStringEnumConverter<NetworkLifecycleCompleteness>))]
public enum NetworkLifecycleCompleteness { Unknown, EventOnly, Partial, Complete, Unsupported }

public sealed record NetworkSocketEndpoint(
    string NativeAddress,
    string Address,
    string AddressBytesBase64,
    int Port,
    string AddressFamily,
    int? ScopeId = null,
    int? InterfaceIndex = null,
    string? InterfaceName = null,
    bool Loopback = false,
    bool Broadcast = false,
    bool Multicast = false,
    bool Wildcard = false
)
{
    public static bool TryCreate(string address, int port, out NetworkSocketEndpoint? endpoint)
    {
        endpoint = null;
        if (port is < 0 or > 65535 || !IPAddress.TryParse(address, out var ip)) return false;
        var bytes = ip.GetAddressBytes();
        var family = bytes.Length == 4 ? "IPv4" : "IPv6";
        var multicast = bytes.Length == 4 ? bytes[0] is >= 224 and <= 239 : bytes[0] == 0xff;
        var wildcard = IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip);
        var broadcast = IPAddress.Broadcast.Equals(ip);
        endpoint = new(address, ip.ToString(), Convert.ToBase64String(bytes), port, family,
            ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? (int?)ip.ScopeId : null,
            null, null, IPAddress.IsLoopback(ip), broadcast, multicast, wildcard);
        return true;
    }
}

public sealed record NetworkProcessRelationship(
    string? ProcessEntityId,
    int? ProcessId,
    DateTimeOffset? ProcessStartTime,
    string? Image,
    string? Path,
    string? CommandLine,
    string? User,
    int? SessionId,
    int? ThreadId,
    string Source,
    string Confidence
);

public sealed record NetworkHostnameContext(
    string? Hostname,
    string Source,
    string SourceVersion,
    DateTimeOffset? ObservedAt,
    DateTimeOffset? EnrichedAt,
    string Confidence,
    DateTimeOffset? ExpiresAt,
    string? FailureState
);

public sealed record NetworkObservation(
    Guid EventId,
    string SchemaVersion,
    NetworkEventKind Kind,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    string CollectorId,
    string CollectorSource,
    string CollectorVersion,
    string SourcePlatform,
    string NativeProvider,
    string? NativeProviderId,
    string? NativeEventId,
    int? NativeOpcode,
    int? NativeVersion,
    int? NativeStatus,
    string NativeOperation,
    long Sequence,
    DateTimeOffset ObservedAt,
    string NormalizationVersion,
    string? RawSha256,
    string? CorrelationId,
    string? TraceId,
    string[] DataQualityFlags,
    string SourceConfidence,
    string ConnectionEntityId,
    NetworkSocketEndpoint Local,
    NetworkSocketEndpoint? Remote,
    string Protocol,
    string SocketType,
    NetworkDirection Direction,
    NetworkConnectionState State,
    string? Result,
    int? FailureCode,
    string? FailureCategory,
    string? NativeConnectionId,
    string? CompartmentId,
    string? NetworkNamespace,
    DateTimeOffset? ConnectionStartedAt,
    DateTimeOffset? ConnectionEndedAt,
    long? DurationMilliseconds,
    NetworkLifecycleCompleteness LifecycleCompleteness,
    string AttributionConfidence,
    NetworkProcessRelationship? Process,
    string? User,
    NetworkHostnameContext? Hostname,
    bool Late = false,
    bool OutOfOrder = false,
    DateTimeOffset? ReceivedAt = null,
    DateTimeOffset? IngestedAt = null
)
{
    public static string StableConnectionEntityId(Guid endpointId, string installationId,
        string? nativeConnectionId, string? processEntityId, DateTimeOffset? processStart,
        NetworkSocketEndpoint local, NetworkSocketEndpoint? remote, string protocol,
        DateTimeOffset observedAt, long sequence)
    {
        var strongest = !string.IsNullOrWhiteSpace(nativeConnectionId)
            ? $"native:{nativeConnectionId}"
            : $"event:{processEntityId ?? "unknown"}:{processStart?.UtcTicks.ToString(CultureInfo.InvariantCulture) ?? "unknown"}:{local.AddressBytesBase64}:{local.Port.ToString(CultureInfo.InvariantCulture)}:{remote?.AddressBytesBase64 ?? "none"}:{remote?.Port.ToString(CultureInfo.InvariantCulture) ?? "none"}:{protocol}:{observedAt.UtcTicks.ToString(CultureInfo.InvariantCulture)}:{sequence.ToString(CultureInfo.InvariantCulture)}";
        var material = $"{endpointId:D}:{installationId}:{strongest}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }
}

public sealed record NetworkEventBatch(Guid BatchId, Guid EndpointId, Guid AgentId,
    string InstallationId, long FirstSequence, long LastSequence,
    IReadOnlyList<NetworkObservation> Events, string ContentSha256,
    string SchemaVersion = "network-batch.v1", string Compression = "gzip",
    int UncompressedBytes = 0, int CompressedBytes = 0,
    string CapabilityVersion = "network.v1");
public sealed record NetworkBatchAcknowledgement(Guid BatchId, IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds, IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough, bool GapDetected);
public sealed record NetworkIngestResult(NetworkBatchAcknowledgement Acknowledgement,
    int Accepted, int Duplicates, int Rejected, int SequenceGaps);

public sealed record NetworkConnectionView(string TenantId, Guid EndpointId,
    string ConnectionEntityId, string? ProcessEntityId, string Protocol, string AddressFamily,
    NetworkSocketEndpoint Local, NetworkSocketEndpoint? Remote, NetworkDirection Direction,
    DateTimeOffset FirstObserved, DateTimeOffset LastObserved, DateTimeOffset? AttemptedAt,
    DateTimeOffset? EstablishedAt, DateTimeOffset? FailedAt, DateTimeOffset? ClosedAt,
    long? DurationMilliseconds, NetworkConnectionState State, Guid LatestEventId,
    string SourceConfidence, string[] DataQualityFlags,
    NetworkLifecycleCompleteness LifecycleCompleteness, NetworkProcessRelationship? Process,
    string? User, NetworkHostnameContext? Hostname);

public sealed record NetworkSearchRequest(Guid? EndpointId = null, DateTimeOffset? From = null,
    DateTimeOffset? To = null, string? LocalAddress = null, string? RemoteAddress = null,
    int? LocalPort = null, int? RemotePort = null, string? Protocol = null,
    string? AddressFamily = null, NetworkDirection? Direction = null,
    NetworkConnectionState? State = null, NetworkEventKind? Operation = null,
    string? Process = null, string? User = null, string? Collector = null,
    string? DataQuality = null, bool? Listener = null, int PageSize = 100,
    string? Cursor = null);
public sealed record NetworkEventPage(IReadOnlyList<NetworkObservation> Items, string? NextCursor);
public sealed record NetworkConnectionPage(IReadOnlyList<NetworkConnectionView> Items, string? NextCursor);
public sealed record NetworkProjectionRebuildProgress(Guid RebuildId, string TargetVersion,
    string Scope, string State, DateTimeOffset StartedAt, DateTimeOffset UpdatedAt,
    DateTimeOffset? CompletedAt, int PostgreSqlSourceCount, int IndexedCount, int FailureCount,
    string CurrentAlias, string? ErrorSummary, bool RollbackAvailable);

public sealed record NetworkTelemetryHealth(Guid EndpointId, bool Enabled, string CollectorSource,
    string CollectorVersion, string NativeProvider, DateTimeOffset? LastSourceEvent,
    DateTimeOffset? LastAcceptedEvent, long QueueDepth, long OldestQueuedSeconds,
    long DroppedEvents, long ExcludedEvents, long SourceLosses, long SequenceGaps,
    long TcpEvents, long UdpEvents, long Ipv4Events, long Ipv6Events, long Attempts,
    long Established, long Failed, long Closed, long AcceptedInbound, long ListenerEvents,
    long AttributionFailures, long UserAttributionFailures, long PidReuseConflicts,
    long LifecycleCorrelationFailures, string LastUploadResult, string PolicyVersion,
    int? AppliedVersion, bool Drift, DateTimeOffset? LastUpload, long LastSequence,
    string[] KnownLimitations, long NativeSourceEvents = 0, long NormalizedEvents = 0,
    long Batches = 0, long UploadFailures = 0, long AcceptedEvents = 0,
    long DuplicateEvents = 0, long RejectedEvents = 0);

public sealed record NetworkExclusionRule(Guid Id, string Category, string Pattern,
    bool Enabled = true, string Reason = "", string Creator = "",
    DateTimeOffset? CreatedAt = null, long MatchCount = 0, DateTimeOffset? LastMatch = null);
public sealed record NetworkTelemetryPolicy(string Version = "network-policy.v1", bool Enabled = true,
    bool TcpEnabled = true, bool UdpEnabled = true, bool Ipv4Enabled = true,
    bool Ipv6Enabled = true, bool AttemptsEnabled = true, bool EstablishedEnabled = true,
    bool FailedEnabled = true, bool ClosedEnabled = true, bool InboundEnabled = true,
    bool ListenerEnabled = true, string[]? IncludedProtocols = null,
    string[]? IncludedCidrs = null, string[]? ExcludedCidrs = null,
    string[]? IncludedPorts = null, string[]? ExcludedPorts = null,
    string[]? ExcludedProcesses = null, string[]? ExcludedUsers = null,
    long MaximumQueueBytes = 128 * 1024 * 1024, int MaximumQueueAgeHours = 24,
    int MaximumBatchEvents = 200, int MaximumBatchBytes = 1024 * 1024,
    int FlushSeconds = 5, string CollectorSource = "auto", bool DiagnosticMode = false,
    IReadOnlyList<NetworkExclusionRule>? ExclusionRules = null);
public sealed record NetworkPolicyVersion(Guid Id, string TenantId, string Name, int Version,
    NetworkTelemetryPolicy Policy, string Sha256, string Status, DateTimeOffset CreatedAt,
    string CreatedBy);
public sealed record EffectiveNetworkPolicy(NetworkPolicyVersion Policy, string AssignmentSource,
    Guid EndpointId, DateTimeOffset? AcknowledgedAt, int? AppliedVersion, int? RejectedVersion,
    string? ValidationError, bool Drift);
public sealed record NetworkPolicyAcknowledgement(Guid PolicyId, int Version, bool Applied,
    string? ValidationError, DateTimeOffset AcknowledgedAt);

public static class NetworkPolicyValidation
{
    static readonly string[] Collectors = ["auto", "windows.etw-network", "linux.falco-json"];
    static readonly string[] Protocols = ["TCP", "UDP"];
    static readonly string[] Categories = ["cidr", "address", "port", "protocol", "process", "user", "direction"];
    public static IReadOnlyDictionary<string, string[]> Validate(NetworkTelemetryPolicy p)
    {
        var e = new Dictionary<string, string[]>();
        if (!Collectors.Contains(p.CollectorSource, StringComparer.Ordinal)) e["collectorSource"] = ["Unsupported network collector source."];
        if (p.IncludedProtocols?.Any(x => !Protocols.Contains(x, StringComparer.OrdinalIgnoreCase)) == true) e["includedProtocols"] = ["Only TCP and UDP are supported."];
        if (p.MaximumQueueBytes is < 1024 * 1024 or > 4L * 1024 * 1024 * 1024) e["maximumQueueBytes"] = ["Queue must be between 1 MiB and 4 GiB."];
        if (p.MaximumQueueAgeHours is < 1 or > 720) e["maximumQueueAgeHours"] = ["Queue age must be between 1 and 720 hours."];
        if (p.MaximumBatchEvents is < 1 or > 1000 || p.MaximumBatchBytes is < 1024 or > 4 * 1024 * 1024) e["batch"] = ["Batch bounds are invalid."];
        if (p.FlushSeconds is < 1 or > 300) e["flushSeconds"] = ["Flush interval must be between 1 and 300 seconds."];
        foreach (var cidr in (p.IncludedCidrs ?? []).Concat(p.ExcludedCidrs ?? [])) if (!TryCidr(cidr)) e[$"cidr.{cidr}"] = ["CIDR is invalid or non-canonical."];
        foreach (var range in (p.IncludedPorts ?? []).Concat(p.ExcludedPorts ?? [])) if (!TryPortRange(range)) e[$"port.{range}"] = ["Port or range must be within 0..65535."];
        if (p.ExclusionRules is { Count: > 64 }) e["exclusionRules"] = ["At most 64 exclusions are allowed."];
        foreach (var r in p.ExclusionRules ?? [])
        {
            if (!Categories.Contains(r.Category, StringComparer.Ordinal)) e[$"exclusion.{r.Id}"] = ["Unsupported exclusion category."];
            if (string.IsNullOrWhiteSpace(r.Pattern) || r.Pattern is "*" or "**" || r.Pattern.Length > 256 || r.Pattern.Any(char.IsControl) || r.Pattern.Count(x => x is '*' or '?') > 4) e[$"exclusion.{r.Id}"] = ["Empty, match-all, unsafe, or excessive-wildcard exclusion."];
            if (r.Category == "cidr" && !TryCidr(r.Pattern)) e[$"exclusion.{r.Id}"] = ["CIDR exclusion is invalid."];
            if (r.Category == "port" && !TryPortRange(r.Pattern)) e[$"exclusion.{r.Id}"] = ["Port exclusion is invalid."];
        }
        return e;
    }
    public static bool TryCidr(string value)
    {
        var parts = value.Split('/', StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)) return false;
        var bytes = ip.GetAddressBytes();
        if (prefix < 0 || prefix > bytes.Length * 8) return false;
        var wholeBytes = prefix / 8;
        var remainder = prefix % 8;
        if (remainder != 0 && (bytes[wholeBytes] & (byte)(0xff >> remainder)) != 0) return false;
        return bytes.Skip(wholeBytes + (remainder == 0 ? 0 : 1)).All(x => x == 0);
    }
    public static bool TryPortRange(string value) { var p = value.Split('-', StringSplitOptions.TrimEntries); return p.Length is 1 or 2 && p.All(x => int.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 65535) && (p.Length == 1 || int.Parse(p[0], CultureInfo.InvariantCulture) <= int.Parse(p[1], CultureInfo.InvariantCulture)); }
}

public interface INetworkTelemetryRepository
{
    Task<NetworkIngestResult> IngestAsync(string tenantId, NetworkEventBatch batch, NetworkTelemetryHealth health, CancellationToken ct);
    Task<NetworkEventPage> SearchAsync(string tenantId, NetworkSearchRequest request, CancellationToken ct);
    Task<NetworkObservation?> GetEventAsync(string tenantId, Guid eventId, CancellationToken ct);
    Task<NetworkConnectionView?> GetConnectionAsync(string tenantId, Guid endpointId, string entityId, CancellationToken ct);
    Task<NetworkEventPage> ConnectionHistoryAsync(string tenantId, Guid endpointId, string entityId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<NetworkEventPage> EndpointTimelineAsync(string tenantId, Guid endpointId, NetworkSearchRequest request, CancellationToken ct);
    Task<NetworkEventPage> ProcessNetworkAsync(string tenantId, Guid endpointId, string processEntityId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<NetworkConnectionPage> ListenersAsync(string tenantId, Guid endpointId, int limit, CancellationToken ct);
    Task<NetworkTelemetryHealth?> HealthAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task<IReadOnlyList<NetworkObservation>> ListAllAsync(CancellationToken ct);
}
public interface INetworkProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(string tenantId, NetworkObservation observation, CancellationToken ct);
    Task<NetworkEventPage> SearchAsync(string tenantId, NetworkSearchRequest request, CancellationToken ct);
    Task<ProcessProjectionRebuildResult> RebuildAsync(IReadOnlyList<NetworkObservation> events, CancellationToken ct);
    NetworkProjectionRebuildProgress GetRebuildProgress();
    Task<bool> HealthAsync(CancellationToken ct);
}
public interface INetworkPolicyRepository
{
    Task<IReadOnlyList<NetworkPolicyVersion>> ListAsync(string tenantId, CancellationToken ct);
    Task<NetworkPolicyVersion> CreateAsync(string tenantId, string actor, string name, NetworkTelemetryPolicy policy, CancellationToken ct);
    Task AssignAsync(string tenantId, Guid policyId, Guid? endpointId, string actor, CancellationToken ct);
    Task<EffectiveNetworkPolicy> EffectiveAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task AcknowledgeAsync(string tenantId, Guid endpointId, NetworkPolicyAcknowledgement acknowledgement, CancellationToken ct);
    Task<NetworkPolicyVersion> RollbackAsync(string tenantId, Guid policyId, int version, string actor, CancellationToken ct);
}
public static class NetworkEvidence { public static string CanonicalSha256<T>(T value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value))).ToLowerInvariant(); }
