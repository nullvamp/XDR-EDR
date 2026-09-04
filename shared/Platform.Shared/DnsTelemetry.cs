using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<DnsEventKind>))]
public enum DnsEventKind { QueryObserved, ResponseObserved, QueryFailed, TransactionObserved }
[JsonConverter(typeof(JsonStringEnumConverter<DnsQueryState>))]
public enum DnsQueryState { Unknown, Query, Response, Failed, Complete, Incomplete }

public sealed record DnsAnswer(string RecordType, string Value, uint? Ttl = null,
    string? CanonicalName = null, string? ResolvedAddress = null, int? Preference = null,
    int? Priority = null, int? Weight = null, int? Port = null);
public sealed record DnsProcessRelationship(string? ProcessEntityId, int? ProcessId,
    DateTimeOffset? ProcessStartTime, string? Image, string? Path, string? User,
    int? SessionId, string Source, string Confidence);
public sealed record DnsNetworkRelationship(Guid NetworkEventId, string ResolvedAddress,
    string Source, int TimeWindowSeconds, bool ProcessMatch, bool AnswerMatch,
    string Confidence, bool Ambiguous, DateTimeOffset ExpiresAt);

public sealed record DnsObservation(
    Guid EventId, string SchemaVersion, DnsEventKind Kind, Guid EndpointId, Guid AgentId,
    string InstallationId, string CollectorId, string CollectorSource, string CollectorVersion,
    string SourcePlatform, string NativeProvider, string? NativeProviderId, string? NativeEventId,
    int? NativeOpcode, int? NativeVersion, int? NativeStatus, long Sequence,
    DateTimeOffset ObservedAt, string NormalizationVersion, string? RawSha256,
    string[] DataQualityFlags, string SourceConfidence, string? TransactionEntityId,
    string? NativeTransactionId, string OriginalQueryName, string CanonicalQueryName,
    string? RecordType, string? RecordClass, string? ResponseCode, DnsQueryState State,
    string? ResolverAddress, string? LocalAddress, string? Protocol, ushort? QueryFlags,
    ushort? ResponseFlags, bool? RecursionDesired, bool? RecursionAvailable, bool? Truncated,
    bool? AuthoritativeAnswer, int? AnswerCount, int? AuthorityCount, int? AdditionalCount,
    long? ResponseLatencyMilliseconds, IReadOnlyList<DnsAnswer> Answers,
    DnsProcessRelationship? Process, string? User, string TransactionConfidence,
    IReadOnlyList<DnsNetworkRelationship>? NetworkRelationships = null, bool Late = false,
    bool OutOfOrder = false, DateTimeOffset? ReceivedAt = null, DateTimeOffset? IngestedAt = null)
{
    public static bool TryCanonicalizeName(string value, out string canonical, out string? error)
    {
        canonical = ""; error = null;
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl)) { error = "DNS name is empty or contains control characters."; return false; }
        var trimmed = value.Trim().TrimEnd('.');
        try
        {
            var idn = new IdnMapping { UseStd3AsciiRules = true };
            var labels = trimmed.Split('.');
            if (labels.Any(x => x.Length == 0)) { error = "DNS name contains an empty label."; return false; }
            var ascii = labels.Select(label => idn.GetAscii(label)).ToArray();
            if (ascii.Any(x => x.Length is < 1 or > 63)) { error = "DNS label exceeds 63 octets."; return false; }
            canonical = string.Join('.', ascii).ToLowerInvariant();
            if (Encoding.ASCII.GetByteCount(canonical) > 253) { canonical = ""; error = "DNS name exceeds 253 octets."; return false; }
            return true;
        }
        catch (ArgumentException) { error = "DNS name is not valid IDN/Punycode."; return false; }
    }

    public static string StableTransactionEntityId(Guid endpointId, string installationId,
        string? nativeTransactionId, int? pid, DateTimeOffset? processStart, string canonicalName,
        string? recordType, string? resolver, long sequence)
    {
        var evidence = !string.IsNullOrWhiteSpace(nativeTransactionId)
            ? $"native:{nativeTransactionId}:{pid}:{processStart?.UtcTicks}:{canonicalName}:{recordType}:{resolver}"
            : $"event:{sequence}:{canonicalName}:{recordType}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{endpointId:D}:{installationId}:{evidence}"))).ToLowerInvariant();
    }
}

public sealed record DnsEventBatch(Guid BatchId, Guid EndpointId, Guid AgentId,
    string InstallationId, long FirstSequence, long LastSequence, IReadOnlyList<DnsObservation> Events,
    string ContentSha256, string SchemaVersion = "dns-batch.v1", string Compression = "gzip",
    int UncompressedBytes = 0, int CompressedBytes = 0, string CapabilityVersion = "dns.v1");
public sealed record DnsBatchAcknowledgement(Guid BatchId, IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds, IReadOnlyDictionary<Guid, string> RejectedEventIds,
    long AcknowledgedThrough, bool GapDetected);
public sealed record DnsIngestResult(DnsBatchAcknowledgement Acknowledgement, int Accepted,
    int Duplicates, int Rejected, int SequenceGaps);
public sealed record DnsSearchRequest(Guid? EndpointId = null, DateTimeOffset? From = null,
    DateTimeOffset? To = null, string? QueryName = null, string? Suffix = null,
    string? RecordType = null, string? ResponseCode = null, string? ResolvedAddress = null,
    string? ResolvedCidr = null, string? Process = null, string? User = null,
    string? Resolver = null, string? Collector = null, string? Quality = null,
    int PageSize = 100, string? Cursor = null);
public sealed record DnsEventPage(IReadOnlyList<DnsObservation> Items, string? NextCursor);
public sealed record DnsTelemetryHealth(Guid EndpointId, bool Enabled, string CollectorSource,
    string CollectorVersion, string NativeProvider, DateTimeOffset? LastSourceEvent,
    DateTimeOffset? LastAcceptedEvent, long NativeEvents, long Queries, long Responses,
    long Failures, long NormalizedEvents, long UnansweredQueries, long UnpairedResponses,
    long CorrelationFailures, long AttributionFailures, long SourceDrops, long SequenceGaps,
    long QueueDepth, long OldestQueuedSeconds, long QueueDrops, long ExcludedEvents,
    long Uploads, long Duplicates, long Rejections, string LastUploadResult,
    string PolicyVersion, int? AppliedVersion, bool Drift, DateTimeOffset? LastUpload,
    long LastSequence, string[] KnownLimitations);

public sealed record DnsExclusionRule(Guid Id, string Category, string Pattern,
    bool Enabled = true, string Reason = "", string Creator = "", DateTimeOffset? CreatedAt = null,
    long MatchCount = 0, DateTimeOffset? LastMatch = null);
public sealed record DnsTelemetryPolicy(string Version = "dns-policy.v1", bool Enabled = true,
    bool QueryCollection = true, bool ResponseCollection = true, bool FailedQueryCollection = true,
    bool ProcessAttribution = true, bool AnswerMetadata = true, string[]? IncludedRecordTypes = null,
    string[]? ExcludedRecordTypes = null, string[]? IncludedDomains = null,
    string[]? ExcludedDomains = null, string[]? ExcludedProcesses = null,
    string[]? ExcludedUsers = null, long MaximumQueueBytes = 128 * 1024 * 1024,
    int MaximumQueueAgeHours = 24, int MaximumBatchEvents = 200,
    int MaximumBatchBytes = 1024 * 1024, int FlushSeconds = 5,
    string CollectorSource = "auto", bool DiagnosticMode = false,
    bool ElevatedWholeDnsExclusionConfirmed = false,
    IReadOnlyList<DnsExclusionRule>? ExclusionRules = null);
public sealed record DnsPolicyVersion(Guid Id, string TenantId, string Name, int Version,
    DnsTelemetryPolicy Policy, string Sha256, string Status, DateTimeOffset CreatedAt, string CreatedBy);
public sealed record EffectiveDnsPolicy(DnsPolicyVersion Policy, string AssignmentSource,
    Guid EndpointId, DateTimeOffset? AcknowledgedAt, int? AppliedVersion, int? RejectedVersion,
    string? ValidationError, bool Drift);
public sealed record DnsPolicyAcknowledgement(Guid PolicyId, int Version, bool Applied,
    string? ValidationError, DateTimeOffset AcknowledgedAt);

public static class DnsPolicyValidation
{
    static readonly string[] Categories = ["domain", "suffix", "record-type", "process", "user"];
    public static IReadOnlyDictionary<string, string[]> Validate(DnsTelemetryPolicy p)
    {
        var e = new Dictionary<string, string[]>();
        if (p.CollectorSource is not ("auto" or "windows.dns-client-etw" or "linux.unsupported")) e["collectorSource"] = ["Unsupported DNS collector source."];
        if (p.MaximumQueueBytes is < 1048576 or > 4294967296L || p.MaximumQueueAgeHours is < 1 or > 720) e["queue"] = ["Queue bounds are invalid."];
        if (p.MaximumBatchEvents is < 1 or > 1000 || p.MaximumBatchBytes is < 1024 or > 4194304 || p.FlushSeconds is < 1 or > 300) e["batch"] = ["Batch bounds are invalid."];
        foreach (var d in (p.IncludedDomains ?? []).Concat(p.ExcludedDomains ?? []))
            if (!DnsObservation.TryCanonicalizeName(d.TrimStart('.', '*'), out _, out _)) e[$"domain.{d}"] = ["Domain suffix is malformed."];
        if ((p.ExcludedDomains ?? []).Any(x => x.Trim() is "*" or "." or "**") && !p.ElevatedWholeDnsExclusionConfirmed) e["excludedDomains"] = ["Whole-DNS exclusion requires elevated confirmation."];
        if (p.ExclusionRules is { Count: > 64 }) e["exclusionRules"] = ["At most 64 exclusions are allowed."];
        foreach (var r in p.ExclusionRules ?? [])
        {
            if (!Categories.Contains(r.Category, StringComparer.Ordinal)) e[$"exclusion.{r.Id}"] = ["Unsupported exclusion category."];
            if (string.IsNullOrWhiteSpace(r.Pattern) || r.Pattern.Trim() is "*" or "**" or "." || r.Pattern.Any(char.IsControl) || r.Pattern.Length > 253 || r.Pattern.Count(x => x is '*' or '?') > 2) e[$"exclusion.{r.Id}"] = ["Unsafe or match-all exclusion."];
        }
        return e;
    }
}

public interface IDnsTelemetryRepository
{
    Task<DnsIngestResult> IngestAsync(string tenantId, DnsEventBatch batch, DnsTelemetryHealth health, CancellationToken ct);
    Task<DnsEventPage> SearchAsync(string tenantId, DnsSearchRequest request, CancellationToken ct);
    Task<DnsObservation?> GetEventAsync(string tenantId, Guid eventId, CancellationToken ct);
    Task<DnsEventPage> HistoryAsync(string tenantId, Guid endpointId, string transactionId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<DnsEventPage> ProcessDnsAsync(string tenantId, Guid endpointId, string processEntityId, DateTimeOffset from, DateTimeOffset toInclusive, int limit, CancellationToken ct);
    Task<DnsTelemetryHealth?> HealthAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task<IReadOnlyList<DnsObservation>> ListAllAsync(CancellationToken ct);
}
public interface IDnsProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertAsync(string tenantId, DnsObservation observation, CancellationToken ct);
    Task<DnsEventPage> SearchAsync(string tenantId, DnsSearchRequest request, CancellationToken ct);
    Task<bool> HealthAsync(CancellationToken ct);
}
public interface IDnsPolicyRepository
{
    Task<IReadOnlyList<DnsPolicyVersion>> ListAsync(string tenantId, CancellationToken ct);
    Task<DnsPolicyVersion> CreateAsync(string tenantId, string actor, string name, DnsTelemetryPolicy policy, CancellationToken ct);
    Task AssignAsync(string tenantId, Guid policyId, Guid? endpointId, string actor, CancellationToken ct);
    Task<EffectiveDnsPolicy> EffectiveAsync(string tenantId, Guid endpointId, CancellationToken ct);
    Task AcknowledgeAsync(string tenantId, Guid endpointId, DnsPolicyAcknowledgement acknowledgement, CancellationToken ct);
}
public static class DnsEvidence { public static string CanonicalSha256<T>(T value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value))).ToLowerInvariant(); }
public static class DnsObservationValidation
{
    public static string? Error(DnsObservation x, DateTimeOffset now)
    {
        if (x.SchemaVersion != "dns-event.v1") return "schema-unsupported";
        if (!DnsObservation.TryCanonicalizeName(x.OriginalQueryName, out var canonical, out _) || canonical != x.CanonicalQueryName) return "query-name-invalid";
        if (x.Answers.Count > 256) return "answer-count-exceeded";
        if (x.Answers.Any(a => a.Value.Length > 4096)) return "answer-value-oversized";
        if (x.Answers.Any(a => a.ResolvedAddress is not null && !IPAddress.TryParse(a.ResolvedAddress, out _))) return "answer-address-invalid";
        if (x.ResolverAddress is not null && !IPAddress.TryParse(x.ResolverAddress, out _)) return "resolver-invalid";
        if (x.ObservedAt < now.AddDays(-30) || x.ObservedAt > now.AddMinutes(5)) return "timestamp-invalid";
        return null;
    }
}
