using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<TunnelKind>))]
public enum TunnelKind { SshLocalForward, SshDynamicProxy, SshReverseForward, SocksProxy, HttpProxy, Vpn, DnsTunnel, NestedTunnel, Unknown }
[JsonConverter(typeof(JsonStringEnumConverter<TunnelDirection>))]
public enum TunnelDirection { Local, Outbound, Inbound, Bidirectional, Unknown }
[JsonConverter(typeof(JsonStringEnumConverter<TunnelRelationshipType>))]
public enum TunnelRelationshipType { ProcessOpensListener, ProcessConnectsListener, ProcessConnectsRemote, ListenerServesLocalClient, ProxyForwardsToRemote, ProcessCreatesTunnel, TunnelCarriesProcessTraffic, TunnelUsesUpstreamTunnel, DnsPrecedesTunnelConnection, TunnelProcessChildOf, TunnelProcessParentOf, RemoteEndpointSharedByTunnels, ResolvesTo, MatchesIndicator }
[JsonConverter(typeof(JsonStringEnumConverter<TunnelConfidence>))]
public enum TunnelConfidence { Low, Medium, High }

public sealed record TunnelEndpoint(string Address, int? Port, string? Hostname = null, string? Protocol = null);
public sealed record TunnelEvidence(Guid EventId, string Source, string Reference, DateTimeOffset ObservedAt,
    Guid EndpointId, string? ProcessEntityId, IReadOnlyDictionary<string, string?> Fields, string[] Quality);
public sealed record TunnelRelationship(Guid RelationshipId, string TenantId, string SourceEntityId,
    string DestinationEntityId, TunnelRelationshipType Type, Guid[] EvidenceIds, string[] EvidenceReferences,
    DateTimeOffset FirstObserved, DateTimeOffset LastObserved, int Confidence, string Provenance, bool Ambiguous = false);
public sealed record DnsTunnelFeatures(int QueryCount, int UniqueSubdomains, double UniqueSubdomainRatio,
    double MeanQueryLength, int MaximumQueryLength, double MeanMaximumLabelLength, int MaximumLabelLength,
    double MeanLabelEntropy, double EncodedCharacterRatio, double NxdomainRatio, double MeanIntervalMilliseconds,
    double IntervalCoefficientOfVariation, IReadOnlyDictionary<string, int> RecordTypes, string FormulaVersion = "dns-tunnel-features.v1");
public sealed record TunnelObservation(Guid ObservationId, string TenantId, Guid EndpointId, string? ProcessEntityId,
    TunnelKind Kind, TunnelDirection Direction, TunnelEndpoint? Listener, TunnelEndpoint? Remote,
    DateTimeOffset FirstObserved, DateTimeOffset LastObserved, Guid[] EvidenceIds, string[] EvidenceReferences,
    IReadOnlyDictionary<string, string?> Attributes, string[] DataQuality, DnsTunnelFeatures? DnsFeatures = null,
    string SchemaVersion = "tunnel-observation.v1", string? SessionId = null, string? LogonId = null,
    string? Subtype = null, TunnelEndpoint? LocalClient = null, TunnelEndpoint? Downstream = null,
    string[]? ProcessChain = null, string? ListenerProcessEntityId = null, string[]? ClientProcessEntityIds = null,
    int ConnectionCount = 0, int LocalClientCount = 0, int RemoteDestinationCount = 0,
    bool Ambiguous = false, string[]? AttackMappings = null, string[]? SourceLimitations = null,
    string DerivationVersion = TunnelAnalyticsSafety.EngineVersion);
public sealed record TunnelFinding(Guid FindingId, string TenantId, string RuleId, string RuleName, Guid EndpointId,
    string? ProcessEntityId, TunnelKind Kind, TunnelConfidence Confidence, int Score, DateTimeOffset FirstObserved,
    DateTimeOffset LastObserved, Guid[] ObservationIds, Guid[] EvidenceIds, string[] EvidenceReferences,
    TunnelRelationship[] Relationships, string[] Reasons, string[] MissingTelemetry, bool Excluded,
    Guid? ExclusionId, string EngineVersion = TunnelAnalyticsSafety.EngineVersion, string[]? AttackMappings = null,
    string[]? ThreatIntelligenceContext = null, bool Ambiguous = false, string[]? SourceLimitations = null);
public sealed record TunnelChain(Guid ChainId, string TenantId, Guid EndpointId, Guid[] ObservationIds,
    TunnelRelationship[] Relationships, int Depth, bool Truncated, string[] Gaps);
public sealed record TunnelExclusion(Guid ExclusionId, string TenantId, int Version, string Name, string Field,
    string Value, DateTimeOffset StartsAt, DateTimeOffset EndsAt, string Reason, string CreatedBy,
    DateTimeOffset CreatedAt = default);
public sealed record TunnelRuleDefinition(string RuleId, string Name, TunnelKind Kind, int MinimumScore,
    string[] RequiredSources, string[] MitreTechniques, string Description, string Fixture,
    string QualityNotes, bool Enabled = true);
public sealed record DnsQuerySample(string Query, string? RegisteredDomain, string RecordType, bool Nxdomain,
    DateTimeOffset ObservedAt);
public sealed record TunnelSearchRequest(Guid? EndpointId = null, string? ProcessEntityId = null,
    TunnelKind? Kind = null, TunnelConfidence? MinimumConfidence = null, DateTimeOffset? From = null,
    DateTimeOffset? To = null, int PageSize = 100, string? Cursor = null);
public sealed record TunnelPage<T>(IReadOnlyList<T> Items, string? NextCursor);
public sealed record TunnelHealth(long Observations, long Findings, long Excluded, long RelationshipRejects,
    long BoundedQueryRejects, long EvaluationFailures, int MaximumChainDepth, string IcmpVisibility,
    DateTimeOffset UpdatedAt, long HighConfidenceFindings = 0, long LocalProxyChains = 0,
    long MultiTunnelChains = 0, long DnsEvaluations = 0, long MissingProcessAttribution = 0,
    long LateEvents = 0, double ChainLatencyMilliseconds = 0, double EvaluationLatencyMilliseconds = 0);

public interface ITunnelAnalyticsRepository
{
    Task<IReadOnlyList<TunnelFinding>> IngestAsync(string tenant, IReadOnlyList<TunnelObservation> values, CancellationToken ct);
    Task<TunnelPage<TunnelObservation>> SearchObservationsAsync(string tenant, TunnelSearchRequest query, CancellationToken ct);
    Task<TunnelPage<TunnelFinding>> SearchFindingsAsync(string tenant, TunnelSearchRequest query, CancellationToken ct);
    Task<TunnelObservation?> GetObservationAsync(string tenant, Guid id, CancellationToken ct);
    Task<TunnelFinding?> GetFindingAsync(string tenant, Guid id, CancellationToken ct);
    Task<TunnelChain> BuildChainAsync(string tenant, Guid observationId, int maximumDepth, CancellationToken ct);
    Task<TunnelExclusion> AddExclusionAsync(string tenant, TunnelExclusion exclusion, string actor, CancellationToken ct);
    Task<IReadOnlyList<TunnelExclusion>> ExclusionsAsync(string tenant, CancellationToken ct);
    Task<TunnelHealth> HealthAsync(string tenant, CancellationToken ct);
    Task<(long Observations, long Findings)> CountsAsync(string tenant, CancellationToken ct);
}

public interface ITunnelAnalyticsProjection
{
    Task EnsureAsync(CancellationToken ct);
    Task UpsertObservationAsync(TunnelObservation value, CancellationToken ct);
    Task UpsertFindingAsync(TunnelFinding value, CancellationToken ct);
    Task<(long Observations, long Findings)> CountsAsync(string tenant, CancellationToken ct);
}

public static class TunnelAnalyticsSafety
{
    public const string EngineVersion = "tunnel-analytics.v1";
    public const int MaximumBatch = 256;
    public const int MaximumPageSize = 200;
    public const int MaximumChainDepth = 4;
    public const int MaximumChainNodes = 64;
    public static readonly TimeSpan MaximumQueryRange = TimeSpan.FromDays(31);
    public static readonly TimeSpan MaximumDnsWindow = TimeSpan.FromMinutes(10);

    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))).AsSpan(0, 16));
    public static void ValidateQuery(TunnelSearchRequest q)
    {
        if (q.PageSize is < 1 or > MaximumPageSize) throw new EnrollmentConflictException("TUNNEL_QUERY_BOUNDS", "Page size must be 1-200.");
        if (q.From is not null && q.To is not null && (q.To <= q.From || q.To - q.From > MaximumQueryRange)) throw new EnrollmentConflictException("TUNNEL_QUERY_BOUNDS", "Time range must be positive and no more than 31 days.");
    }
    public static int Cursor(string tenant, string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor)) return 0;
        try { var p = Encoding.UTF8.GetString(Convert.FromBase64String(cursor)).Split('|'); if (p.Length != 2 || p[0] != tenant || !int.TryParse(p[1], out var n) || n < 0) throw new FormatException("Malformed cursor."); return n; }
        catch { throw new EnrollmentConflictException("TUNNEL_CURSOR_INVALID", "Cursor is invalid for this tenant."); }
    }
    public static string Cursor(string tenant, int offset) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{tenant}|{offset}"));
    public static void Validate(TunnelObservation x, string tenant)
    {
        if (x.TenantId != tenant || !Guid.TryParse(tenant, out _) || x.ObservationId == Guid.Empty || x.EndpointId == Guid.Empty) throw new EnrollmentConflictException("TUNNEL_IDENTITY_INVALID", "Canonical tenant, observation, and endpoint identities are required.");
        if (x.LastObserved < x.FirstObserved || x.LastObserved - x.FirstObserved > TimeSpan.FromDays(1)) throw new EnrollmentConflictException("TUNNEL_WINDOW_INVALID", "Observation window is invalid or unbounded.");
        if (x.EvidenceIds.Length is < 1 or > 256 || x.EvidenceIds.Length != x.EvidenceReferences.Length || x.EvidenceReferences.Any(string.IsNullOrWhiteSpace)) throw new EnrollmentConflictException("TUNNEL_EVIDENCE_INVALID", "Every observation requires bounded, addressable source evidence.");
        if (x.Kind == TunnelKind.DnsTunnel && x.DnsFeatures is null) throw new EnrollmentConflictException("TUNNEL_DNS_FEATURES_REQUIRED", "DNS tunnel observations require deterministic feature evidence.");
    }
}

public static class DnsTunnelFeatureExtractor
{
    public static DnsTunnelFeatures Compute(IReadOnlyList<DnsQuerySample> samples)
    {
        if (samples.Count is < 1 or > 10_000) throw new EnrollmentConflictException("TUNNEL_DNS_WINDOW_BOUNDS", "DNS feature windows contain 1-10,000 queries.");
        var ordered = samples.OrderBy(x => x.ObservedAt).ToArray(); if (ordered[^1].ObservedAt - ordered[0].ObservedAt > TunnelAnalyticsSafety.MaximumDnsWindow) throw new EnrollmentConflictException("TUNNEL_DNS_WINDOW_BOUNDS", "DNS feature windows are limited to ten minutes.");
        var queries = ordered.Select(x => DnsObservation.TryCanonicalizeName(x.Query, out var canonical, out _) ? canonical : throw new EnrollmentConflictException("TUNNEL_DNS_NAME_INVALID", "DNS feature input contains an invalid, oversized, or ambiguous IDN name.")).ToArray();
        var labels = queries.SelectMany(x => x.Split('.', StringSplitOptions.RemoveEmptyEntries)).ToArray();
        var maxima = queries.Select(x => x.Split('.').Select(y => y.Length).DefaultIfEmpty().Max()).ToArray();
        var entropy = labels.Select(Entropy).DefaultIfEmpty().Average(); var encoded = labels.Sum(x => x.Count(char.IsLetterOrDigit)); var total = Math.Max(1, labels.Sum(x => x.Length));
        var domains = ordered.Select((x, i) => x.RegisteredDomain is null ? LastTwo(queries[i]) : DnsObservation.TryCanonicalizeName(x.RegisteredDomain, out var canonical, out _) ? canonical : throw new EnrollmentConflictException("TUNNEL_DNS_DOMAIN_INVALID", "Registered-domain context is invalid.")).ToArray();
        var subs = queries.Zip(domains).Select(x => x.First.EndsWith(x.Second, StringComparison.Ordinal) ? x.First[..Math.Max(0, x.First.Length - x.Second.Length)].Trim('.') : x.First).ToArray();
        var intervals = ordered.Zip(ordered.Skip(1), (a, b) => (b.ObservedAt - a.ObservedAt).TotalMilliseconds).ToArray(); var mean = intervals.DefaultIfEmpty().Average();
        var variance = intervals.Length == 0 ? 0 : intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Length;
        return new(samples.Count, subs.Distinct(StringComparer.Ordinal).Count(), subs.Distinct(StringComparer.Ordinal).Count() / (double)samples.Count,
            queries.Average(x => x.Length), queries.Max(x => x.Length), maxima.Average(), maxima.Max(), entropy,
            encoded / (double)total, samples.Count(x => x.Nxdomain) / (double)samples.Count, mean, mean <= 0 ? 0 : Math.Sqrt(variance) / mean,
            ordered.GroupBy(x => x.RecordType.ToUpperInvariant()).ToDictionary(x => x.Key, x => x.Count(), StringComparer.Ordinal));
    }
    static string LastTwo(string q) { var p = q.Trim('.').Split('.'); return p.Length < 2 ? q : string.Join('.', p[^2..]); }
    static double Entropy(string value) { if (value.Length == 0) return 0; return -value.GroupBy(x => x).Sum(g => { var p = g.Count() / (double)value.Length; return p * Math.Log2(p); }); }
}

public static class TunnelProductionPack
{
    public static readonly TunnelRuleDefinition[] Rules =
    [
        R("TUN-001","SSH dynamic SOCKS proxy",TunnelKind.SshDynamicProxy,55,["process","network"],"Command-line proxy intent plus listener/network evidence."),
        R("TUN-002","SSH local port forward",TunnelKind.SshLocalForward,55,["process","network"],"Local forwarding intent plus an observed listener."),
        R("TUN-003","SSH reverse port forward",TunnelKind.SshReverseForward,70,["process","network"],"Reverse-forward intent plus sustained remote connectivity."),
        R("TUN-004","Local proxy used by multiple clients",TunnelKind.SocksProxy,65,["network","process"],"One listener is used by multiple attributed client processes."),
        R("TUN-005","Tunnel fan-out",TunnelKind.NestedTunnel,70,["network"],"One tunnel process connects to many distinct remote endpoints."),
        R("TUN-006","Clients converge on proxy",TunnelKind.SocksProxy,65,["network"],"Distinct clients converge on one attributed proxy listener."),
        R("TUN-007","Evidence-backed nested tunnel",TunnelKind.NestedTunnel,80,["process","network"],"A bounded tunnel chain has at least two source-backed hops."),
        R("TUN-008","Known tunneling tool behavior",TunnelKind.Unknown,60,["process","network"],"Tool identity is corroborated by listener or connection behavior."),
        R("TUN-009","Long-lived proxy listener",TunnelKind.HttpProxy,55,["network"],"A proxy listener persists beyond the configured baseline."),
        R("TUN-010","DNS high unique-subdomain ratio",TunnelKind.DnsTunnel,65,["dns"],"Unique subdomain ratio and volume exceed deterministic bounds."),
        R("TUN-011","DNS long encoded labels",TunnelKind.DnsTunnel,70,["dns"],"Label length and entropy jointly exceed deterministic bounds."),
        R("TUN-012","DNS high-frequency low-jitter channel",TunnelKind.DnsTunnel,70,["dns"],"Query cadence, volume, and low timing variance are jointly unusual."),
        R("TUN-013","DNS tunnel with process attribution",TunnelKind.DnsTunnel,80,["dns","process","network"],"DNS feature anomaly is joined to process and network evidence."),
        R("TUN-014","Concurrent tunnel processes",TunnelKind.NestedTunnel,75,["process","network"],"Multiple tunnel-capable processes overlap on one endpoint.")
    ];
    static TunnelRuleDefinition R(string id, string name, TunnelKind kind, int score, string[] sources, string description) => new(id, name, kind, score, sources, ["T1572"], description, $"sprint24-tunnel-rules.json#{id}", "False-positive guidance, prerequisites, missing fields, and source limits documented; no payload inspection.");
}

public static class TunnelAnalyticsEngine
{
    public static TunnelFinding? Evaluate(TunnelObservation o, IReadOnlyList<TunnelExclusion> exclusions)
    {
        var reasons = new List<string>(); var score = 0; var a = o.Attributes;
        if (o.Kind != TunnelKind.Unknown) { score += 25; reasons.Add($"classified:{o.Kind}"); }
        if (o.Listener is not null) { score += 15; reasons.Add("source-backed-listener"); }
        if (o.Remote is not null) { score += 15; reasons.Add("source-backed-remote"); }
        if (!string.IsNullOrWhiteSpace(o.ProcessEntityId)) { score += 10; reasons.Add("process-attributed"); }
        if (int.TryParse(a.GetValueOrDefault("distinctClients"), out var clients) && clients >= 3) { score += 20; reasons.Add("multiple-clients"); }
        if (int.TryParse(a.GetValueOrDefault("remoteFanOut"), out var fanout) && fanout >= 5) { score += 20; reasons.Add("remote-fan-out"); }
        if (o.LastObserved - o.FirstObserved >= TimeSpan.FromMinutes(5)) { score += 10; reasons.Add("long-lived"); }
        if (o.DnsFeatures is { } d)
        {
            if (d.QueryCount >= 20 && d.UniqueSubdomainRatio >= .8) { score += 25; reasons.Add("dns-unique-subdomains"); }
            if (d.MaximumLabelLength >= 40 && d.MeanLabelEntropy >= 3.5) { score += 25; reasons.Add("dns-long-high-entropy-labels"); }
            if (d.QueryCount >= 30 && d.MeanIntervalMilliseconds <= 2_000 && d.IntervalCoefficientOfVariation <= .35) { score += 20; reasons.Add("dns-high-frequency-low-jitter"); }
            if (d.NxdomainRatio >= .5) { score += 10; reasons.Add("dns-high-nxdomain-ratio"); }
        }
        score = Math.Min(score, 100); var rule = TunnelProductionPack.Rules.Where(x => x.Kind == o.Kind || x.Kind == TunnelKind.Unknown).OrderByDescending(x => x.MinimumScore <= score).ThenBy(x => x.RuleId).First();
        if (score < rule.MinimumScore) return null;
        var now = DateTimeOffset.UtcNow; var exclusion = exclusions.Where(x => x.TenantId == o.TenantId && x.StartsAt <= now && x.EndsAt > now).FirstOrDefault(x => MatchExclusion(x, o));
        var confidence = score >= 80 ? TunnelConfidence.High : score >= 60 ? TunnelConfidence.Medium : TunnelConfidence.Low;
        var relationships = Relationships(o, confidence == TunnelConfidence.High ? 90 : confidence == TunnelConfidence.Medium ? 75 : 55);
        return new(TunnelAnalyticsSafety.StableId(o.TenantId, rule.RuleId, o.ObservationId.ToString("D")), o.TenantId, rule.RuleId, rule.Name, o.EndpointId, o.ProcessEntityId, o.Kind, confidence, score, o.FirstObserved, o.LastObserved, [o.ObservationId], o.EvidenceIds, o.EvidenceReferences, relationships, reasons.ToArray(), Missing(o), exclusion is not null, exclusion?.ExclusionId, AttackMappings: rule.MitreTechniques, Ambiguous: o.Ambiguous, SourceLimitations: o.SourceLimitations);
    }
    static TunnelRelationship[] Relationships(TunnelObservation o, int confidence)
    {
        var values = new List<TunnelRelationship>(); if (o.ProcessEntityId is null) return [];
        void Add(string destination, TunnelRelationshipType type) { values.Add(new(TunnelAnalyticsSafety.StableId(o.TenantId, o.ObservationId.ToString("D"), type.ToString(), destination), o.TenantId, o.ProcessEntityId, destination, type, o.EvidenceIds, o.EvidenceReferences, o.FirstObserved, o.LastObserved, confidence, $"{TunnelAnalyticsSafety.EngineVersion}:exact-observation", o.Ambiguous)); }
        if (o.Listener is { } listener) Add($"listener:{listener.Protocol}:{listener.Address}:{listener.Port}", TunnelRelationshipType.ProcessOpensListener);
        if (o.Remote is { } remote) Add($"remote:{remote.Protocol}:{remote.Address}:{remote.Port}", TunnelRelationshipType.ProcessConnectsRemote);
        if (o.LocalClient is { } client) Add($"client:{client.Protocol}:{client.Address}:{client.Port}", TunnelRelationshipType.ListenerServesLocalClient);
        return values.ToArray();
    }
    static bool MatchExclusion(TunnelExclusion e, TunnelObservation o) => e.Field.ToLowerInvariant() switch { "processentityid" => string.Equals(o.ProcessEntityId, e.Value, StringComparison.OrdinalIgnoreCase), "kind" => string.Equals(o.Kind.ToString(), e.Value, StringComparison.OrdinalIgnoreCase), "remoteaddress" => string.Equals(o.Remote?.Address, e.Value, StringComparison.OrdinalIgnoreCase), "hostname" => string.Equals(o.Remote?.Hostname, e.Value, StringComparison.OrdinalIgnoreCase), _ => false };
    static string[] Missing(TunnelObservation o) { var x = new List<string>(); if (o.ProcessEntityId is null) x.Add("processEntityId"); if (o.Remote is null) x.Add("remoteEndpoint"); if (o.Kind == TunnelKind.DnsTunnel) x.Add("payload:NOT_OBSERVABLE_BY_SOURCE"); return x.ToArray(); }
}
