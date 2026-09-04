using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<ThreatIndicatorType>))]
public enum ThreatIndicatorType { IPv4, IPv6, Cidr, Domain, Hostname, Url, Sha256, Sha1, Md5, CertificateThumbprint, Signer, Registry, ProcessPath }
[JsonConverter(typeof(JsonStringEnumConverter<IntelligenceSourceType>))]
public enum IntelligenceSourceType { Manual, Csv, Json, Stix, TaxiiAdapter, NativeFeed }
[JsonConverter(typeof(JsonStringEnumConverter<ThreatMatchMode>))]
public enum ThreatMatchMode { Live, Historical, Simulation }
[JsonConverter(typeof(JsonStringEnumConverter<ThreatJobState>))]
public enum ThreatJobState { Queued, Running, Completed, Cancelled, Failed }
[JsonConverter(typeof(JsonStringEnumConverter<ThreatExclusionScope>))]
public enum ThreatExclusionScope { Endpoint, Process, User, Indicator, Source, Domain, Ip, FileHash, Entity }

public sealed record IntelligenceSource(Guid SourceId, string TenantId, string Name,
    IntelligenceSourceType Type, int Reliability, int DefaultConfidence, bool Enabled,
    bool GlobalScope, DateTimeOffset? LastSuccessfulSync, string? FailureState,
    int RateLimitPerMinute, string? License, string? Handling, string? Checkpoint,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, int Version = 1);

public sealed record ThreatIndicator(Guid IndicatorId, string TenantId, Guid SourceId,
    string? SourceRecordId, int Version, string? SourceVersion, ThreatIndicatorType Type,
    string CanonicalValue, string OriginalValue, string NormalizedValue, int Confidence,
    int Reliability, int? Severity, DateTimeOffset? FirstSeen, DateTimeOffset? LastSeen,
    DateTimeOffset ValidFrom, DateTimeOffset? ValidUntil, bool Revoked, bool Expired,
    string[] Tags, string Tlp, string? Campaign, string? MalwareFamily, string? ThreatActor,
    string[] AttackMappings, string? SourceReference, string NormalizationVersion,
    string Provenance, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)
{
    public bool ActiveAt(DateTimeOffset at) => !Revoked && ValidFrom <= at &&
        (ValidUntil is null || ValidUntil > at);
}

public sealed record ThreatIndicatorInput(Guid SourceId, ThreatIndicatorType Type, string Value,
    string? SourceRecordId = null, string? SourceVersion = null, int? Confidence = null,
    int? Reliability = null, int? Severity = null, DateTimeOffset? FirstSeen = null,
    DateTimeOffset? LastSeen = null, DateTimeOffset? ValidFrom = null,
    DateTimeOffset? ValidUntil = null, bool Revoked = false, string[]? Tags = null,
    string Tlp = "TLP:CLEAR", string? Campaign = null, string? MalwareFamily = null,
    string? ThreatActor = null, string[]? AttackMappings = null,
    string? SourceReference = null, string Provenance = "manual");

public sealed record ThreatEvidence(Guid EventId, Guid EndpointId, string? ProcessEntityId,
    string? EntityId, DateTimeOffset ObservedAt, ThreatIndicatorType Type, string Field,
    string Value, string EvidenceReference, string[] Quality);

public sealed record ThreatMatch(Guid MatchId, string TenantId, Guid IndicatorId,
    int IndicatorVersion, Guid SourceId, Guid EvidenceEventId, string? EntityId,
    Guid EndpointId, string? ProcessEntityId, string MatchedField, string MatchedValue,
    ThreatIndicatorType MatchType, DateTimeOffset FirstSeen, DateTimeOffset LastSeen,
    int Confidence, string[] TelemetryQuality, ThreatMatchMode Mode, string EngineVersion,
    string EvidenceReference, bool Excluded, Guid? ExclusionId, DateTimeOffset CreatedAt);

public sealed record ThreatRelationship(Guid RelationshipId, string TenantId, Guid SourceId,
    string SourceRecordId, string TargetRecordId, string RelationshipType,
    string? Description, string Provenance, DateTimeOffset CreatedAt);

public sealed record ThreatExclusion(Guid ExclusionId, string TenantId, int Version,
    ThreatExclusionScope Scope, string Value, string Reason, DateTimeOffset ValidFrom,
    DateTimeOffset? ValidUntil, bool Enabled, string Actor, DateTimeOffset CreatedAt);

public sealed record ThreatBackmatchJob(Guid JobId, string TenantId, Guid IndicatorId,
    int IndicatorVersion, DateTimeOffset From, DateTimeOffset To, ThreatMatchMode Mode,
    ThreatJobState State, long Scanned, long Matched, int ProgressPercent,
    string? Error, string RequestedBy, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public sealed record ThreatImportResult(Guid ImportId, int Read, int Imported, int Duplicates,
    int Rejected, string[] Errors, DateTimeOffset CompletedAt);
public sealed record ThreatSearchRequest(ThreatIndicatorType? Type = null, string? Query = null,
    Guid? SourceId = null, bool? Active = null, int PageSize = 100, string? Cursor = null);
public sealed record ThreatMatchSearchRequest(Guid? IndicatorId = null, Guid? EndpointId = null,
    Guid? EvidenceEventId = null, ThreatMatchMode? Mode = null, int PageSize = 100,
    string? Cursor = null);
public sealed record ThreatPage<T>(IReadOnlyList<T> Items, string? NextCursor, long Total);
public sealed record ThreatHealth(long Sources, long ActiveIndicators, long ExpiredIndicators,
    long RevokedIndicators, long Imports, long ImportFailures, long Matches, long ExcludedMatches,
    long BackmatchJobs, long InvalidIndicators, long DuplicateIndicators,
    double LastMatchLatencyMilliseconds, DateTimeOffset UpdatedAt);

public interface IThreatIntelligenceRepository
{
    Task<IntelligenceSource> CreateSourceAsync(string tenant, IntelligenceSource source, string actor, CancellationToken ct);
    Task<IReadOnlyList<IntelligenceSource>> SourcesAsync(string tenant, CancellationToken ct);
    Task<ThreatIndicator> AddAsync(string tenant, ThreatIndicatorInput input, string actor, CancellationToken ct);
    Task<ThreatImportResult> ImportAsync(string tenant, Guid sourceId, string format, Stream content, string actor, CancellationToken ct);
    Task<ThreatPage<ThreatIndicator>> SearchAsync(string tenant, ThreatSearchRequest query, CancellationToken ct);
    Task<ThreatIndicator?> GetAsync(string tenant, Guid id, int? version, CancellationToken ct);
    Task<ThreatIndicator> SetStateAsync(string tenant, Guid id, bool? revoked, DateTimeOffset? validUntil, string actor, CancellationToken ct);
    Task<IReadOnlyList<ThreatMatch>> MatchAsync(string tenant, IReadOnlyList<ThreatEvidence> evidence, ThreatMatchMode mode, CancellationToken ct);
    Task<ThreatPage<ThreatMatch>> SearchMatchesAsync(string tenant, ThreatMatchSearchRequest query, CancellationToken ct);
    Task<ThreatExclusion> AddExclusionAsync(string tenant, ThreatExclusion exclusion, string actor, CancellationToken ct);
    Task<IReadOnlyList<ThreatExclusion>> ExclusionsAsync(string tenant, CancellationToken ct);
    Task<ThreatBackmatchJob> QueueBackmatchAsync(string tenant, Guid indicatorId, int version, DateTimeOffset from, DateTimeOffset until, ThreatMatchMode mode, string actor, CancellationToken ct);
    Task<ThreatBackmatchJob?> GetJobAsync(string tenant, Guid jobId, CancellationToken ct);
    Task<ThreatBackmatchJob?> CancelJobAsync(string tenant, Guid jobId, string actor, CancellationToken ct);
    Task<ThreatHealth> HealthAsync(string tenant, CancellationToken ct);
    Task<(long IndicatorVersions, long Matches)> CountsAsync(string tenant, CancellationToken ct);
}

public interface IThreatIntelligenceProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertIndicatorAsync(ThreatIndicator indicator, CancellationToken ct);
    Task UpsertMatchAsync(ThreatMatch match, CancellationToken ct);
    Task<(long Indicators, long Matches)> CountsAsync(string tenant, CancellationToken ct);
}

public interface IThreatBackmatchProcessor
{
    Task<bool> ProcessNextAsync(CancellationToken ct);
}

public static class ThreatIntelligenceSafety
{
    public const string NormalizationVersion = "ioc-normalization.v1";
    public const string EngineVersion = "ioc-match-engine.v1";
    public const int MaximumImportBytes = 5 * 1024 * 1024;
    public const int MaximumImportRecords = 10_000;
    public const int MaximumBackmatchDays = 31;

    public static string Normalize(ThreatIndicatorType type, string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 32_767 || value.Any(char.IsControl))
            throw new EnrollmentConflictException("IOC_INVALID", "Indicator is empty, oversized, or contains control characters.");
        value = value.Trim();
        return type switch
        {
            ThreatIndicatorType.IPv4 => Ip(value, AddressFamily.InterNetwork),
            ThreatIndicatorType.IPv6 => Ip(value, AddressFamily.InterNetworkV6),
            ThreatIndicatorType.Cidr => Cidr(value),
            ThreatIndicatorType.Domain or ThreatIndicatorType.Hostname => Domain(value),
            ThreatIndicatorType.Sha256 => Hex(value, 64, "SHA-256"),
            ThreatIndicatorType.Sha1 => Hex(value, 40, "SHA-1"),
            ThreatIndicatorType.Md5 => Hex(value, 32, "MD5"),
            ThreatIndicatorType.CertificateThumbprint => Thumbprint(value),
            ThreatIndicatorType.Url => Url(value),
            ThreatIndicatorType.ProcessPath => WindowsPath(value),
            ThreatIndicatorType.Registry => Registry(value),
            ThreatIndicatorType.Signer => Plain(value, 512).ToLowerInvariant(),
            _ => throw new EnrollmentConflictException("IOC_TYPE_UNSUPPORTED", "Indicator type is unsupported.")
        };
    }

    static string Ip(string value, AddressFamily expected)
    {
        if (!IPAddress.TryParse(value, out var ip)) throw new EnrollmentConflictException("IOC_IP_INVALID", "IP address is invalid.");
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != expected) throw new EnrollmentConflictException("IOC_IP_FAMILY", "IP address family does not match indicator type.");
        return ip.ToString().ToLowerInvariant();
    }

    static string Cidr(string value)
    {
        var parts = value.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
            throw new EnrollmentConflictException("IOC_CIDR_INVALID", "CIDR is invalid.");
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var bits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > bits) throw new EnrollmentConflictException("IOC_CIDR_PREFIX", "CIDR prefix is invalid.");
        var bytes = ip.GetAddressBytes();
        for (var bit = prefix; bit < bits; bit++) bytes[bit / 8] &= (byte)~(1 << (7 - bit % 8));
        return $"{new IPAddress(bytes).ToString().ToLowerInvariant()}/{prefix}";
    }

    static string Domain(string value)
    {
        var trimmed = value.TrimEnd('.');
        if (trimmed.Length == 0 || IPAddress.TryParse(trimmed, out _)) throw new EnrollmentConflictException("IOC_DOMAIN_INVALID", "Domain is invalid.");
        try
        {
            var idn = new IdnMapping { UseStd3AsciiRules = true };
            var labels = trimmed.Split('.');
            if (labels.Any(x => x.Length == 0)) throw new ArgumentException("Empty label.", nameof(value));
            var ascii = labels.Select(x => idn.GetAscii(x)).ToArray();
            if (ascii.Any(x => x.Length is < 1 or > 63 || x.StartsWith('-') || x.EndsWith('-'))) throw new ArgumentException("Invalid label.", nameof(value));
            var result = string.Join('.', ascii).ToLowerInvariant();
            if (Encoding.ASCII.GetByteCount(result) > 253) throw new ArgumentException("Domain too long.", nameof(value));
            return result;
        }
        catch (ArgumentException) { throw new EnrollmentConflictException("IOC_DOMAIN_INVALID", "Domain is invalid IDN/Punycode."); }
    }

    static string Hex(string value, int length, string algorithm)
    {
        var compact = value.Replace(" ", "", StringComparison.Ordinal).Replace(":", "", StringComparison.Ordinal);
        if (compact.Length != length || compact.Any(x => !Uri.IsHexDigit(x)))
            throw new EnrollmentConflictException("IOC_HASH_INVALID", $"{algorithm} must contain exactly {length} hexadecimal characters.");
        return compact.ToLowerInvariant();
    }

    static string Thumbprint(string value)
    {
        var compact = value.Replace(" ", "", StringComparison.Ordinal).Replace(":", "", StringComparison.Ordinal);
        if (compact.Length is not (40 or 64) || compact.Any(x => !Uri.IsHexDigit(x)))
            throw new EnrollmentConflictException("IOC_CERT_INVALID", "Certificate thumbprint must be SHA-1 or SHA-256 hexadecimal.");
        return compact.ToLowerInvariant();
    }

    static string Url(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
            throw new EnrollmentConflictException("IOC_URL_INVALID", "Only absolute HTTP(S) URLs without credentials are supported.");
        var host = Domain(uri.IdnHost);
        var builder = new UriBuilder(uri) { Host = host, Scheme = uri.Scheme.ToLowerInvariant(), Fragment = "" };
        if ((builder.Scheme == "http" && builder.Port == 80) || (builder.Scheme == "https" && builder.Port == 443)) builder.Port = -1;
        return builder.Uri.AbsoluteUri;
    }

    static string WindowsPath(string value)
    {
        var path = Plain(value, 32767).Replace('/', '\\');
        if (path.StartsWith("\\??\\", StringComparison.Ordinal)) path = path[4..];
        if (!(path.StartsWith("\\\\", StringComparison.Ordinal) || (path.Length >= 3 && char.IsLetter(path[0]) && path[1] == ':' && path[2] == '\\') || path.StartsWith("%systemroot%\\", StringComparison.OrdinalIgnoreCase)))
            throw new EnrollmentConflictException("IOC_PATH_INVALID", "Process path must be an absolute Windows, UNC, or %SystemRoot% path.");
        return path.ToLowerInvariant();
    }

    static string Registry(string value)
    {
        var text = Plain(value, 32767).Replace('/', '\\').TrimEnd('\\');
        var roots = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["HKLM"] = "hkey_local_machine", ["HKEY_LOCAL_MACHINE"] = "hkey_local_machine", ["HKCU"] = "hkey_current_user", ["HKEY_CURRENT_USER"] = "hkey_current_user", ["HKU"] = "hkey_users", ["HKEY_USERS"] = "hkey_users", ["HKCR"] = "hkey_classes_root", ["HKEY_CLASSES_ROOT"] = "hkey_classes_root" };
        var split = text.IndexOf('\\'); var root = split < 0 ? text : text[..split];
        if (!roots.TryGetValue(root, out var canonical)) throw new EnrollmentConflictException("IOC_REGISTRY_INVALID", "Registry indicator root is unsupported.");
        return (split < 0 ? canonical : canonical + text[split..]).ToLowerInvariant();
    }

    static string Plain(string value, int max) => value.Length <= max && !value.Any(char.IsControl)
        ? value.Trim() : throw new EnrollmentConflictException("IOC_INVALID", "Indicator contains unsafe text.");

    public static Guid StableId(params string[] parts)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', parts)));
        return new Guid(hash.AsSpan(0, 16));
    }

    public static bool Matches(ThreatIndicator indicator, ThreatEvidence evidence)
    {
        if (indicator.Type == ThreatIndicatorType.Cidr && evidence.Type is ThreatIndicatorType.IPv4 or ThreatIndicatorType.IPv6)
            return Contains(indicator.CanonicalValue, evidence.Value);
        if (indicator.Type != evidence.Type) return false;
        try { return string.Equals(indicator.CanonicalValue, Normalize(evidence.Type, evidence.Value), StringComparison.Ordinal); }
        catch (EnrollmentConflictException) { return false; }
    }

    static bool Contains(string cidr, string address)
    {
        var parts = cidr.Split('/'); var network = IPAddress.Parse(parts[0]); var candidate = IPAddress.Parse(address);
        if (candidate.IsIPv4MappedToIPv6) candidate = candidate.MapToIPv4();
        if (network.AddressFamily != candidate.AddressFamily) return false;
        var prefix = int.Parse(parts[1], CultureInfo.InvariantCulture); var a = network.GetAddressBytes(); var b = candidate.GetAddressBytes();
        for (var bit = 0; bit < prefix; bit++) if ((a[bit / 8] & (1 << (7 - bit % 8))) != (b[bit / 8] & (1 << (7 - bit % 8)))) return false;
        return true;
    }
}

public static class ThreatEvidenceMapper
{
    public static IReadOnlyList<ThreatEvidence> FromFile(FileObservation x, string reference)
    {
        var r = new List<ThreatEvidence>(); AddHash(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.FileEntityId, x.ObservedAt, "SHA-256", x.Hash.Sha256, "file.hash", reference, x.DataQualityFlags);
        Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.FileEntityId, x.ObservedAt, ThreatIndicatorType.CertificateThumbprint, "file.signer.thumbprint", x.Hash.CertificateThumbprint, reference, x.DataQualityFlags);
        Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.FileEntityId, x.ObservedAt, ThreatIndicatorType.Signer, "file.signer.subject", x.Hash.Signer, reference, x.DataQualityFlags);
        Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.FileEntityId, x.ObservedAt, ThreatIndicatorType.ProcessPath, "file.path", x.CurrentPath, reference, x.DataQualityFlags); return r;
    }
    public static IReadOnlyList<ThreatEvidence> FromNetwork(NetworkObservation x, string reference)
    {
        var r = new List<ThreatEvidence>(); AddIp(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.ConnectionEntityId, x.ObservedAt, "network.local.ip", x.Local.Address, reference, x.DataQualityFlags);
        if (x.Remote is { } remote) AddIp(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.ConnectionEntityId, x.ObservedAt, "network.remote.ip", remote.Address, reference, x.DataQualityFlags); return r;
    }
    public static IReadOnlyList<ThreatEvidence> FromDns(DnsObservation x, string reference)
    {
        var r = new List<ThreatEvidence>(); Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.TransactionEntityId, x.ObservedAt, ThreatIndicatorType.Domain, "dns.query", x.CanonicalQueryName, reference, x.DataQualityFlags);
        foreach (var answer in x.Answers) { if (IPAddress.TryParse(answer.Value, out _)) AddIp(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.TransactionEntityId, x.ObservedAt, "dns.answer.ip", answer.Value, reference, x.DataQualityFlags); else if (answer.RecordType is "CNAME" or "NS" or "PTR") Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.TransactionEntityId, x.ObservedAt, ThreatIndicatorType.Domain, "dns.answer.name", answer.Value, reference, x.DataQualityFlags); }
        return r;
    }
    public static IReadOnlyList<ThreatEvidence> FromModule(ModuleObservation x, string reference)
    {
        var r = new List<ThreatEvidence>(); AddHash(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.ModuleEntityId, x.ObservedAt, x.Hash.Algorithm, x.Hash.Value, "module.hash", reference, x.DataQualityFlags);
        Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.ModuleEntityId, x.ObservedAt, ThreatIndicatorType.ProcessPath, "module.path", x.NormalizedPath, reference, x.DataQualityFlags);
        Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.ModuleEntityId, x.ObservedAt, ThreatIndicatorType.CertificateThumbprint, "module.signer.thumbprint", x.Signer.Thumbprint, reference, x.DataQualityFlags);
        Add(r, x.EventId, x.EndpointId, x.Process?.ProcessEntityId, x.ModuleEntityId, x.ObservedAt, ThreatIndicatorType.Signer, "module.signer.subject", x.Signer.Subject, reference, x.DataQualityFlags); return r;
    }
    public static IReadOnlyList<ThreatEvidence> FromProcess(ProcessEntityView x, string reference)
    {
        var r = new List<ThreatEvidence>(); Add(r, x.StartEventId, x.EndpointId, x.ProcessEntityId, x.ProcessEntityId, x.StartTime, ThreatIndicatorType.ProcessPath, "process.executable.path", x.ExecutablePath, reference, x.DataQualityFlags);
        AddHash(r, x.StartEventId, x.EndpointId, x.ProcessEntityId, x.ProcessEntityId, x.StartTime, "SHA-256", x.ExecutableMetadata?.Sha256, "process.executable.hash", reference, x.DataQualityFlags); return r;
    }
    static void AddIp(List<ThreatEvidence> r, Guid e, Guid endpoint, string? process, string? entity, DateTimeOffset at, string field, string? value, string reference, string[] quality) { if (!IPAddress.TryParse(value, out var ip)) return; if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4(); Add(r, e, endpoint, process, entity, at, ip.AddressFamily == AddressFamily.InterNetwork ? ThreatIndicatorType.IPv4 : ThreatIndicatorType.IPv6, field, ip.ToString(), reference, quality); }
    static void AddHash(List<ThreatEvidence> r, Guid e, Guid endpoint, string? process, string? entity, DateTimeOffset at, string? algorithm, string? value, string field, string reference, string[] quality) { var type = algorithm?.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant() switch { "SHA256" => ThreatIndicatorType.Sha256, "SHA1" => ThreatIndicatorType.Sha1, "MD5" => ThreatIndicatorType.Md5, _ => (ThreatIndicatorType?)null }; if (type is { } t) Add(r, e, endpoint, process, entity, at, t, field, value, reference, quality); }
    static void Add(List<ThreatEvidence> r, Guid e, Guid endpoint, string? process, string? entity, DateTimeOffset at, ThreatIndicatorType type, string field, string? value, string reference, string[] quality) { if (!string.IsNullOrWhiteSpace(value)) r.Add(new(e, endpoint, process, entity, at, type, field, value, reference, quality)); }
}
