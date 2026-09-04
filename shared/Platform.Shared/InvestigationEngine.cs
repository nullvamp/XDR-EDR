using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<InvestigationEntityType>))]
public enum InvestigationEntityType { Process, File, Registry, Network, Dns, Module, Persistence, Identity, Execution, ThreatIndicator, ThreatMatch, TunnelObservation, TunnelFinding, DetectionFinding, CorrelatedFinding }
[JsonConverter(typeof(JsonStringEnumConverter<HuntOperator>))]
public enum HuntOperator { Equal, NotEqual, Contains, Prefix, Suffix, Cidr, In, Path, Exists }
[JsonConverter(typeof(JsonStringEnumConverter<HuntBoolean>))]
public enum HuntBoolean { And, Or, Not }

public sealed record InvestigationEntity(
    string TenantId, string EntityId, InvestigationEntityType Type, Guid? EndpointId, string DisplayName,
    DateTimeOffset FirstObserved, DateTimeOffset LastObserved, IReadOnlyDictionary<string, string?> Properties,
    Guid[] EvidenceIds, string[] EvidenceReferences, string Provenance, string[] DataQuality, bool Ambiguous = false,
    int Version = 1);

public sealed record InvestigationRelationship(
    Guid RelationshipId, string TenantId, string SourceEntityId, InvestigationEntityType SourceType,
    string DestinationEntityId, InvestigationEntityType DestinationType, string RelationshipType,
    Guid[] SourceEvidenceIds, string[] EvidenceReferences, DateTimeOffset FirstObserved, DateTimeOffset LastObserved,
    int Confidence, string Provenance, bool Ambiguous, int Version = 1);

public sealed record GraphQuery(
    string RootEntityId, InvestigationEntityType? RootType = null, DateTimeOffset? From = null,
    DateTimeOffset? To = null, int MaximumDepth = 3, int MaximumNodes = 200, int MaximumEdges = 400,
    int MaximumExpansionPerNode = 50, int TimeoutMilliseconds = 5_000, int PageSize = 100,
    string? Cursor = null, InvestigationEntityType[]? NodeTypes = null, string[]? RelationshipTypes = null);

public sealed record InvestigationGraph(
    string RootEntityId, InvestigationEntity[] Nodes, InvestigationRelationship[] Edges, bool Truncated,
    string? NextCursor, int DepthReached, long ElapsedMilliseconds, string[] Gaps);

public sealed record ProcessTreeView(
    string RootProcessEntityId, InvestigationEntity[] Processes, InvestigationRelationship[] Relationships,
    bool Truncated, string? NextCursor, string[] MissingParents, string[] AmbiguousRelationships);

public sealed record AttackStory(
    Guid StoryId, string TenantId, string RootEntityId, DateTimeOffset FirstObserved, DateTimeOffset LastObserved,
    InvestigationEntity[] Entities, InvestigationRelationship[] Relationships, StoryTimelineItem[] Timeline,
    Guid[] DetectionFindingIds, Guid[] CorrelatedFindingIds, string[] MitreMappings, string[] MissingTelemetry,
    string[] Ambiguities, string[] SourceGaps, int Confidence, string Explanation, string Provenance);

public sealed record StoryTimelineItem(DateTimeOffset At, string EntityId, string Kind, Guid[] EvidenceIds, string[] EvidenceReferences, string Description, bool Ambiguous);

public sealed record HuntPredicate(string Field, HuntOperator Operator, string[] Values);
public sealed record HuntClause(HuntBoolean Boolean, HuntPredicate? Predicate = null, HuntClause[]? Children = null);
public sealed record HuntDefinition(
    string SchemaVersion, Guid HuntId, int Version, string TenantId, string Name, string Description,
    InvestigationEntityType[] EntityTypes, DateTimeOffset From, DateTimeOffset To, HuntClause Where,
    int MaximumResults, int TimeoutMilliseconds, int MaximumJoinDepth, string[] JoinRelationships,
    bool Enabled, string Owner, string[] SharedWith, DateTimeOffset CreatedAt);
public sealed record HuntValidation(bool Valid, IReadOnlyDictionary<string, string[]> Errors, int EstimatedCost, string[] Plan);
public sealed record HuntResultRow(string EntityId, InvestigationEntityType EntityType, DateTimeOffset ObservedAt, string DisplayName, IReadOnlyDictionary<string, string?> Fields, Guid[] EvidenceIds, string[] EvidenceReferences);
public sealed record HuntRun(Guid RunId, string TenantId, Guid HuntId, int HuntVersion, string Status, int EstimatedCost, int Examined, int Returned, bool CancelRequested, string[] ExecutionPlan, DateTimeOffset StartedAt, DateTimeOffset? CompletedAt, HuntResultRow[] Results);
public sealed record HuntPivot(string EntityId, InvestigationEntityType EntityType, IReadOnlyDictionary<string, int> AvailableRelationships);
public sealed record InvestigationHealth(long TreeQueries, long GraphQueries, long StoryQueries, long HuntQueries, long NodesTraversed, long EdgesTraversed, long Cancellations, long CostRejections, long Timeouts, long SavedHunts, long RelationshipFailures, double TreeLatencyMilliseconds, double GraphLatencyMilliseconds, double HuntLatencyMilliseconds, double GraphProjectionLagMilliseconds, DateTimeOffset UpdatedAt);

public static class InvestigationSafety
{
    public const int MaximumDepth = 8;
    public const int MaximumNodes = 500;
    public const int MaximumEdges = 1_000;
    public const int MaximumExpansion = 100;
    public const int MaximumPageSize = 200;
    public const int MaximumTimeoutMilliseconds = 10_000;
    public const int MaximumHuntResults = 2_000;
    public const int MaximumHuntNesting = 8;
    public const int MaximumHuntPredicates = 32;
    public static readonly TimeSpan MaximumTimeRange = TimeSpan.FromDays(30);
    static readonly HashSet<string> Fields = new(StringComparer.OrdinalIgnoreCase)
    { "entityId", "type", "displayName", "endpointId", "processEntityId", "parentProcessEntityId", "path", "commandLine", "user", "userSid", "sessionId", "logonId", "integrity", "elevated", "sha256", "signer", "dnsName", "remoteAddress", "remotePort", "operation", "kind", "status", "mitreTechnique", "tunnelKind", "tunnelConfidence", "tunnelRuleId" };
    static readonly HashSet<string> Relationships = new(StringComparer.OrdinalIgnoreCase)
    { "parent-of", "created", "modified", "connected-to", "queried", "loaded", "configured", "executed-as", "executed", "resolved-to", "supports", "contains", "evidence-for", "correlated-with", "opened-listener", "used-proxy", "traverses-tunnel", "matches-indicator" };

    public static IReadOnlyDictionary<string, string[]> Validate(GraphQuery query)
    {
        var e = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(query.RootEntityId) || query.RootEntityId.Length > 512) e["rootEntityId"] = ["Root entity is required and bounded."];
        if (query.MaximumDepth is < 0 or > MaximumDepth) e["maximumDepth"] = [$"Depth must be 0-{MaximumDepth}."];
        if (query.MaximumNodes is < 1 or > MaximumNodes) e["maximumNodes"] = [$"Nodes must be 1-{MaximumNodes}."];
        if (query.MaximumEdges is < 1 or > MaximumEdges) e["maximumEdges"] = [$"Edges must be 1-{MaximumEdges}."];
        if (query.MaximumExpansionPerNode is < 1 or > MaximumExpansion) e["maximumExpansionPerNode"] = [$"Expansion must be 1-{MaximumExpansion}."];
        if (query.TimeoutMilliseconds is < 100 or > MaximumTimeoutMilliseconds) e["timeoutMilliseconds"] = ["Timeout must be 100-10000ms."];
        if (query.PageSize is < 1 or > MaximumPageSize) e["pageSize"] = [$"Page size must be 1-{MaximumPageSize}."];
        if (query.From is not null && query.To is not null && (query.To <= query.From || query.To - query.From > MaximumTimeRange)) e["timeRange"] = ["Time range must be positive and at most 30 days."];
        if (query.RelationshipTypes?.Any(x => !Relationships.Contains(x)) == true) e["relationshipTypes"] = ["Relationship type is not allowlisted."];
        return e;
    }

    public static HuntValidation Validate(HuntDefinition hunt)
    {
        var errors = new Dictionary<string, string[]>(); var predicates = 0; var maxDepth = 0;
        void Walk(HuntClause clause, int depth)
        {
            maxDepth = Math.Max(maxDepth, depth);
            if (clause.Predicate is { } p)
            {
                predicates++;
                if (!Fields.Contains(p.Field)) errors[$"field.{predicates}"] = ["Field is not authorized."];
                if (p.Values.Length is < 1 or > 50 || p.Values.Any(x => x.Length > 2_048)) errors[$"value.{predicates}"] = ["Predicate values are invalid or unbounded."];
                if (p.Values.Any(x => x.Contains("select ", StringComparison.OrdinalIgnoreCase) || x.Contains("script", StringComparison.OrdinalIgnoreCase) || x.Contains("$where", StringComparison.OrdinalIgnoreCase) || x.Contains("(?", StringComparison.Ordinal))) errors[$"injection.{predicates}"] = ["Executable or backend query syntax is prohibited."];
            }
            foreach (var child in clause.Children ?? []) Walk(child, depth + 1);
        }
        Walk(hunt.Where, 1);
        if (hunt.SchemaVersion != "threat-hunt.v1" || hunt.HuntId == Guid.Empty || !Guid.TryParse(hunt.TenantId, out _)) errors["identity"] = ["Schema, hunt, and tenant identity are required."];
        if (hunt.EntityTypes.Length is < 1 or > 15) errors["entityTypes"] = ["One or more bounded entity types are required."];
        if (hunt.To <= hunt.From || hunt.To - hunt.From > MaximumTimeRange) errors["timeRange"] = ["Hunts are bounded to 30 days."];
        if (hunt.MaximumResults is < 1 or > MaximumHuntResults || hunt.TimeoutMilliseconds is < 100 or > MaximumTimeoutMilliseconds || hunt.MaximumJoinDepth is < 0 or > 3) errors["cost"] = ["Result, timeout, or join bounds are invalid."];
        if (maxDepth > MaximumHuntNesting || predicates > MaximumHuntPredicates) errors["complexity"] = ["Hunt nesting or predicate count exceeds the bounded language."];
        if (hunt.JoinRelationships.Any(x => !Relationships.Contains(x))) errors["joins"] = ["Join relationship is not allowlisted."];
        var cost = Math.Min(100_000, hunt.MaximumResults * Math.Max(1, predicates) * (hunt.MaximumJoinDepth + 1));
        return new(errors.Count == 0, errors, cost, [$"tenant={hunt.TenantId}", $"time={hunt.From:O}..{hunt.To:O}", $"types={string.Join(',', hunt.EntityTypes)}", $"predicates={predicates}", $"joinDepth={hunt.MaximumJoinDepth}", $"limit={hunt.MaximumResults}", $"timeoutMs={hunt.TimeoutMilliseconds}"]);
    }

    public static bool Matches(InvestigationEntity entity, HuntClause clause)
    {
        bool Predicate(HuntPredicate p)
        {
            var actual = p.Field switch { "entityId" => entity.EntityId, "type" => entity.Type.ToString(), "displayName" => entity.DisplayName, "endpointId" => entity.EndpointId?.ToString("D"), _ => entity.Properties.GetValueOrDefault(p.Field) } ?? "";
            return p.Operator switch
            {
                HuntOperator.Equal => p.Values.Any(x => string.Equals(actual, x, StringComparison.OrdinalIgnoreCase)),
                HuntOperator.NotEqual => p.Values.All(x => !string.Equals(actual, x, StringComparison.OrdinalIgnoreCase)),
                HuntOperator.Contains => p.Values.Any(x => actual.Contains(x, StringComparison.OrdinalIgnoreCase)),
                HuntOperator.Prefix or HuntOperator.Path => p.Values.Any(x => actual.StartsWith(x, StringComparison.OrdinalIgnoreCase)),
                HuntOperator.Suffix => p.Values.Any(x => actual.EndsWith(x, StringComparison.OrdinalIgnoreCase)),
                HuntOperator.In => p.Values.Contains(actual, StringComparer.OrdinalIgnoreCase),
                HuntOperator.Exists => !string.IsNullOrWhiteSpace(actual),
                HuntOperator.Cidr => p.Values.Any(x => CidrContains(x, actual)),
                _ => false
            };
        }
        var own = clause.Predicate is null || Predicate(clause.Predicate); var children = clause.Children ?? [];
        return clause.Boolean switch { HuntBoolean.And => own && children.All(x => Matches(entity, x)), HuntBoolean.Or => own || children.Any(x => Matches(entity, x)), HuntBoolean.Not => !(own && children.All(x => Matches(entity, x))), _ => false };
    }

    static bool CidrContains(string cidr, string address)
    {
        if (!System.Net.IPAddress.TryParse(address, out var ip) || !cidr.Contains('/')) return false;
        var parts = cidr.Split('/', 2); if (!System.Net.IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var prefix)) return false;
        var a = ip.GetAddressBytes(); var n = network.GetAddressBytes(); if (a.Length != n.Length || prefix < 0 || prefix > a.Length * 8) return false;
        for (var i = 0; i < a.Length; i++) { var bits = Math.Clamp(prefix - i * 8, 0, 8); var mask = bits == 0 ? 0 : 0xff << (8 - bits) & 0xff; if ((a[i] & mask) != (n[i] & mask)) return false; }
        return true;
    }

    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))).AsSpan(0, 16));
    public static string ProtectCursor(string tenant, int offset) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{tenant}|{offset}"));
    public static int UnprotectCursor(string tenant, string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor)) return 0;
        try { var p = Encoding.UTF8.GetString(Convert.FromBase64String(cursor)).Split('|'); if (p.Length != 2 || p[0] != tenant || !int.TryParse(p[1], out var value) || value < 0) throw new FormatException(); return value; }
        catch { throw new EnrollmentConflictException("CURSOR_INVALID", "Investigation cursor is invalid."); }
    }
}

public static class InvestigationProjection
{
    public static (InvestigationEntity[] Nodes, InvestigationRelationship[] Edges) From(CorrelationObservation o)
    {
        var nodes = new List<InvestigationEntity>(); var edges = new List<InvestigationRelationship>(); var evidence = new[] { o.ObservationId }; var refs = new[] { o.EvidenceReference };
        var process = o.ProcessEntityId;
        if (process is not null) nodes.Add(Node(o, process, InvestigationEntityType.Process, o.Fields.GetValueOrDefault("processName") ?? o.Fields.GetValueOrDefault("path") ?? process));
        if (o.ParentProcessEntityId is not null && process is not null)
        {
            nodes.Add(Node(o, o.ParentProcessEntityId, InvestigationEntityType.Process, o.Fields.GetValueOrDefault("parentPath") ?? o.ParentProcessEntityId));
            edges.Add(Edge(o, o.ParentProcessEntityId, InvestigationEntityType.Process, process, InvestigationEntityType.Process, "parent-of", 100, false));
        }
        var type = o.Kind == CorrelationInputKind.DetectionFinding ? o.Domain == DetectionDomain.Tunnel ? InvestigationEntityType.TunnelFinding : InvestigationEntityType.DetectionFinding : DomainType(o.Domain);
        var id = o.Kind == CorrelationInputKind.DetectionFinding ? o.DetectionFindingId?.ToString("D") : o.EntityId;
        if (id is null && type != InvestigationEntityType.Process) id = $"{type.ToString().ToLowerInvariant()}:{o.ObservationId:D}";
        if (id is not null && (process is null || id != process))
        {
            nodes.Add(Node(o, id, type, o.Fields.GetValueOrDefault("path") ?? o.Fields.GetValueOrDefault("dnsName") ?? o.Fields.GetValueOrDefault("remoteAddress") ?? id));
            if (process is not null) edges.Add(Edge(o, process, InvestigationEntityType.Process, id, type, Relationship(o.Domain, o.Kind), o.Incomplete ? 60 : 95, o.Incomplete));
        }
        return (nodes.DistinctBy(x => (x.EntityId, x.Type)).ToArray(), edges.ToArray());
    }

    static InvestigationEntity Node(CorrelationObservation o, string id, InvestigationEntityType type, string display) => new(o.TenantId, id, type, o.EndpointId, display, o.EventTime, o.EventTime, new Dictionary<string, string?>(o.Fields, StringComparer.OrdinalIgnoreCase) { ["processEntityId"] = o.ProcessEntityId, ["parentProcessEntityId"] = o.ParentProcessEntityId, ["entityId"] = o.EntityId, ["type"] = type.ToString() }, [o.ObservationId], [o.EvidenceReference], "canonical-correlation-observation", o.Quality ?? [], o.Incomplete);
    static InvestigationRelationship Edge(CorrelationObservation o, string source, InvestigationEntityType sourceType, string destination, InvestigationEntityType destinationType, string relationship, int confidence, bool ambiguous) => new(InvestigationSafety.StableId(o.TenantId, source, sourceType.ToString(), destination, destinationType.ToString(), relationship), o.TenantId, source, sourceType, destination, destinationType, relationship, [o.ObservationId], [o.EvidenceReference], o.EventTime, o.EventTime, confidence, "canonical-evidence", ambiguous);
    static InvestigationEntityType DomainType(DetectionDomain? d) => d switch { DetectionDomain.File => InvestigationEntityType.File, DetectionDomain.Registry => InvestigationEntityType.Registry, DetectionDomain.Network => InvestigationEntityType.Network, DetectionDomain.Dns => InvestigationEntityType.Dns, DetectionDomain.Module => InvestigationEntityType.Module, DetectionDomain.Persistence => InvestigationEntityType.Persistence, DetectionDomain.Identity => InvestigationEntityType.Identity, DetectionDomain.Execution => InvestigationEntityType.Execution, DetectionDomain.Tunnel => InvestigationEntityType.TunnelObservation, _ => InvestigationEntityType.Process };
    static string Relationship(DetectionDomain? d, CorrelationInputKind kind) => kind == CorrelationInputKind.DetectionFinding ? "evidence-for" : d switch { DetectionDomain.File => "modified", DetectionDomain.Registry => "modified", DetectionDomain.Network => "connected-to", DetectionDomain.Dns => "queried", DetectionDomain.Module => "loaded", DetectionDomain.Persistence => "configured", DetectionDomain.Identity => "executed-as", DetectionDomain.Execution => "executed", DetectionDomain.Tunnel => "supports", _ => "supports" };
}

public interface IInvestigationRepository
{
    Task UpsertObservationAsync(string tenant, CorrelationObservation observation, CancellationToken ct);
    Task UpsertAsync(string tenant, IReadOnlyList<InvestigationEntity> nodes, IReadOnlyList<InvestigationRelationship> edges, CancellationToken ct);
    Task<ProcessTreeView?> ProcessTreeAsync(string tenant, string root, GraphQuery query, bool ancestors, CancellationToken ct);
    Task<InvestigationGraph?> GraphAsync(string tenant, GraphQuery query, CancellationToken ct);
    Task<IReadOnlyList<InvestigationRelationship>> RelationshipAsync(string tenant, Guid id, CancellationToken ct);
    Task<AttackStory?> StoryAsync(string tenant, string root, GraphQuery query, CancellationToken ct);
    Task<HuntValidation> ValidateHuntAsync(string tenant, HuntDefinition hunt, CancellationToken ct);
    Task<HuntRun> ExecuteHuntAsync(string tenant, HuntDefinition hunt, CancellationToken ct);
    Task<HuntRun?> GetRunAsync(string tenant, Guid run, CancellationToken ct);
    Task<HuntRun> CancelRunAsync(string tenant, Guid run, CancellationToken ct);
    Task<HuntPivot?> PivotsAsync(string tenant, string entityId, InvestigationEntityType type, CancellationToken ct);
    Task<HuntDefinition> SaveHuntAsync(string tenant, string actor, HuntDefinition hunt, bool newVersion, CancellationToken ct);
    Task<IReadOnlyList<HuntDefinition>> SavedHuntsAsync(string tenant, CancellationToken ct);
    Task<IReadOnlyList<HuntDefinition>> HuntHistoryAsync(string tenant, Guid id, CancellationToken ct);
    Task DeleteHuntAsync(string tenant, string actor, Guid id, CancellationToken ct);
    Task<InvestigationHealth> HealthAsync(string tenant, CancellationToken ct);
}

public class FileInvestigationRepository : IInvestigationRepository
{
    readonly ConcurrentDictionary<(string Tenant, string Id, InvestigationEntityType Type), InvestigationEntity> _nodes = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), InvestigationRelationship> _edges = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id, int Version), HuntDefinition> _hunts = new();
    readonly ConcurrentDictionary<(string Tenant, Guid Id), HuntRun> _runs = new();
    readonly ConcurrentDictionary<string, long[]> _health = new();
    protected virtual Task PersistAsync(string tenant, IReadOnlyList<InvestigationEntity> nodes, IReadOnlyList<InvestigationRelationship> edges, CancellationToken ct) => Task.CompletedTask;
    protected virtual Task<(InvestigationEntity[] Nodes, InvestigationRelationship[] Edges)> LoadAsync(string tenant, CancellationToken ct) => Task.FromResult((_nodes.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).ToArray(), _edges.Where(x => x.Key.Tenant == tenant).Select(x => x.Value).ToArray()));
    public async Task UpsertObservationAsync(string tenant, CorrelationObservation observation, CancellationToken ct) { if (observation.TenantId != tenant) throw new EnrollmentConflictException("TENANT_MISMATCH", "Observation tenant mismatch."); var projected = InvestigationProjection.From(observation); await UpsertAsync(tenant, projected.Nodes, projected.Edges, ct); }
    public async Task UpsertAsync(string tenant, IReadOnlyList<InvestigationEntity> nodes, IReadOnlyList<InvestigationRelationship> edges, CancellationToken ct)
    {
        if (nodes.Any(x => x.TenantId != tenant) || edges.Any(x => x.TenantId != tenant)) throw new EnrollmentConflictException("TENANT_MISMATCH", "Graph tenant mismatch.");
        foreach (var node in nodes) _nodes.AddOrUpdate((tenant, node.EntityId, node.Type), node, (_, old) => old with { FirstObserved = old.FirstObserved < node.FirstObserved ? old.FirstObserved : node.FirstObserved, LastObserved = old.LastObserved > node.LastObserved ? old.LastObserved : node.LastObserved, Properties = old.Properties.Concat(node.Properties).GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase).ToDictionary(x => x.Key, x => x.Last().Value, StringComparer.OrdinalIgnoreCase), EvidenceIds = old.EvidenceIds.Concat(node.EvidenceIds).Distinct().ToArray(), EvidenceReferences = old.EvidenceReferences.Concat(node.EvidenceReferences).Distinct().ToArray(), DataQuality = old.DataQuality.Concat(node.DataQuality).Distinct().ToArray(), Ambiguous = old.Ambiguous || node.Ambiguous });
        foreach (var edge in edges)
        {
            if (!nodes.Any(x => x.EntityId == edge.SourceEntityId) && !_nodes.Keys.Any(x => x.Tenant == tenant && x.Id == edge.SourceEntityId) || !nodes.Any(x => x.EntityId == edge.DestinationEntityId) && !_nodes.Keys.Any(x => x.Tenant == tenant && x.Id == edge.DestinationEntityId)) { _health.GetOrAdd(tenant, _ => new long[13])[12]++; throw new EnrollmentConflictException("RELATIONSHIP_EVIDENCE_REQUIRED", "Relationship endpoints require evidence-backed entities."); }
            if (edge.SourceEvidenceIds.Length == 0 || edge.EvidenceReferences.Length == 0) { _health.GetOrAdd(tenant, _ => new long[13])[12]++; throw new EnrollmentConflictException("RELATIONSHIP_EVIDENCE_REQUIRED", "Relationship requires exact evidence."); }
            _edges.AddOrUpdate((tenant, edge.RelationshipId), edge, (_, old) => old with { FirstObserved = old.FirstObserved < edge.FirstObserved ? old.FirstObserved : edge.FirstObserved, LastObserved = old.LastObserved > edge.LastObserved ? old.LastObserved : edge.LastObserved, SourceEvidenceIds = old.SourceEvidenceIds.Concat(edge.SourceEvidenceIds).Distinct().ToArray(), EvidenceReferences = old.EvidenceReferences.Concat(edge.EvidenceReferences).Distinct().ToArray(), Ambiguous = old.Ambiguous || edge.Ambiguous });
        }
        await PersistAsync(tenant, nodes, edges, ct);
    }
    public async Task<InvestigationGraph?> GraphAsync(string tenant, GraphQuery query, CancellationToken ct)
    {
        var errors = InvestigationSafety.Validate(query); if (errors.Count > 0) throw new EnrollmentConflictException("GRAPH_BOUNDS", string.Join(' ', errors.Values.SelectMany(x => x)));
        var started = Environment.TickCount64; var all = await LoadAsync(tenant, ct); var root = all.Nodes.FirstOrDefault(x => x.EntityId == query.RootEntityId && (query.RootType is null || x.Type == query.RootType)); if (root is null) return null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(query.TimeoutMilliseconds); var selected = new Dictionary<(string, InvestigationEntityType), InvestigationEntity> { [(root.EntityId, root.Type)] = root }; var edgeMap = new Dictionary<Guid, InvestigationRelationship>(); var frontier = new[] { root.EntityId }; var depth = 0;
        try
        {
            while (frontier.Length > 0 && depth < query.MaximumDepth && selected.Count < query.MaximumNodes && edgeMap.Count < query.MaximumEdges)
            {
                timeout.Token.ThrowIfCancellationRequested(); var next = new HashSet<string>();
                foreach (var id in frontier)
                {
                    var edges = all.Edges.Where(x => x.SourceEntityId == id || x.DestinationEntityId == id).Where(x => query.From is null || x.LastObserved >= query.From).Where(x => query.To is null || x.FirstObserved <= query.To).Where(x => query.RelationshipTypes is null || query.RelationshipTypes.Contains(x.RelationshipType, StringComparer.OrdinalIgnoreCase)).OrderBy(x => x.FirstObserved).ThenBy(x => x.RelationshipId).Take(query.MaximumExpansionPerNode);
                    foreach (var edge in edges)
                    {
                        if (edgeMap.Count >= query.MaximumEdges || selected.Count >= query.MaximumNodes) break; edgeMap[edge.RelationshipId] = edge; var other = edge.SourceEntityId == id ? edge.DestinationEntityId : edge.SourceEntityId; foreach (var node in all.Nodes.Where(x => x.EntityId == other && (query.NodeTypes is null || query.NodeTypes.Contains(x.Type)))) { selected[(node.EntityId, node.Type)] = node; next.Add(node.EntityId); }
                    }
                }
                frontier = next.Except(selected.Keys.Select(x => x.Item1).Except(next)).ToArray(); depth++;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { _health.GetOrAdd(tenant, _ => new long[13])[8]++; }
        var orderedNodes = selected.Values.OrderBy(x => x.FirstObserved).ThenBy(x => x.EntityId).ToArray(); var offset = InvestigationSafety.UnprotectCursor(tenant, query.Cursor); var page = orderedNodes.Skip(offset).Take(query.PageSize).ToArray(); var nextCursor = offset + page.Length < orderedNodes.Length ? InvestigationSafety.ProtectCursor(tenant, offset + page.Length) : null; var h = _health.GetOrAdd(tenant, _ => new long[13]); h[1]++; h[4] += page.Length; h[5] += edgeMap.Count; h[10] = Environment.TickCount64 - started;
        return new(root.EntityId, page, edgeMap.Values.OrderBy(x => x.FirstObserved).ThenBy(x => x.RelationshipId).ToArray(), nextCursor is not null || selected.Count >= query.MaximumNodes || edgeMap.Count >= query.MaximumEdges, nextCursor, depth, Environment.TickCount64 - started, edgeMap.Values.Where(x => x.Ambiguous).Select(x => $"ambiguous:{x.RelationshipId:D}").ToArray());
    }
    public async Task<ProcessTreeView?> ProcessTreeAsync(string tenant, string root, GraphQuery query, bool ancestors, CancellationToken ct)
    {
        var q = query with { RootEntityId = root, RootType = InvestigationEntityType.Process, NodeTypes = [InvestigationEntityType.Process], RelationshipTypes = ["parent-of"] }; var graph = await GraphAsync(tenant, q, ct); if (graph is null) return null; var h = _health.GetOrAdd(tenant, _ => new long[13]); h[0]++; h[9] = graph.ElapsedMilliseconds;
        var edges = ancestors ? graph.Edges.Where(e => graph.Nodes.Any(n => n.EntityId == e.SourceEntityId)).ToArray() : graph.Edges; return new(root, graph.Nodes, edges, graph.Truncated, graph.NextCursor, graph.Nodes.Where(x => x.Properties.GetValueOrDefault("parentProcessEntityId") is { Length: > 0 } p && graph.Nodes.All(n => n.EntityId != p)).Select(x => x.EntityId).ToArray(), edges.Where(x => x.Ambiguous).Select(x => x.RelationshipId.ToString("D")).ToArray());
    }
    public async Task<IReadOnlyList<InvestigationRelationship>> RelationshipAsync(string tenant, Guid id, CancellationToken ct) { var all = await LoadAsync(tenant, ct); return all.Edges.Where(x => x.RelationshipId == id).ToArray(); }
    public async Task<AttackStory?> StoryAsync(string tenant, string root, GraphQuery query, CancellationToken ct)
    {
        var graph = await GraphAsync(tenant, query with { RootEntityId = root }, ct); if (graph is null) return null; _health.GetOrAdd(tenant, _ => new long[13])[2]++;
        var timeline = graph.Nodes.Select(x => new StoryTimelineItem(x.FirstObserved, x.EntityId, x.Type.ToString(), x.EvidenceIds, x.EvidenceReferences, $"{x.Type}: {x.DisplayName}", x.Ambiguous)).Concat(graph.Edges.Select(x => new StoryTimelineItem(x.FirstObserved, x.SourceEntityId, x.RelationshipType, x.SourceEvidenceIds, x.EvidenceReferences, $"{x.SourceEntityId} {x.RelationshipType} {x.DestinationEntityId}", x.Ambiguous))).OrderBy(x => x.At).ThenBy(x => x.EntityId).ToArray();
        var detections = graph.Nodes.Where(x => x.Type == InvestigationEntityType.DetectionFinding).Select(x => Guid.TryParse(x.EntityId, out var id) ? id : Guid.Empty).Where(x => x != Guid.Empty).ToArray(); var correlated = graph.Nodes.Where(x => x.Type == InvestigationEntityType.CorrelatedFinding).Select(x => Guid.TryParse(x.EntityId, out var id) ? id : Guid.Empty).Where(x => x != Guid.Empty).ToArray(); var missing = graph.Nodes.SelectMany(x => x.DataQuality.Where(q => q.Contains("missing", StringComparison.OrdinalIgnoreCase))).Distinct().ToArray(); var ambiguous = graph.Edges.Where(x => x.Ambiguous).Select(x => x.RelationshipId.ToString("D")).ToArray();
        return new(InvestigationSafety.StableId(tenant, root, string.Join(',', graph.Nodes.Select(x => x.EntityId))), tenant, root, timeline.Min(x => x.At), timeline.Max(x => x.At), graph.Nodes, graph.Edges, timeline, detections, correlated, graph.Nodes.Select(x => x.Properties.GetValueOrDefault("mitreTechnique")).Where(x => x is not null).Cast<string>().Distinct().ToArray(), missing, ambiguous, graph.Gaps, Math.Clamp(graph.Edges.Length == 0 ? 0 : (int)graph.Edges.Average(x => x.Confidence) - ambiguous.Length * 5, 0, 100), $"Deterministic story over {graph.Nodes.Length} evidence-backed entities and {graph.Edges.Length} relationships rooted at {root}.", "authoritative-evidence-view");
    }
    public Task<HuntValidation> ValidateHuntAsync(string tenant, HuntDefinition hunt, CancellationToken ct) => Task.FromResult(hunt.TenantId == tenant ? InvestigationSafety.Validate(hunt) : new HuntValidation(false, new Dictionary<string, string[]> { ["tenant"] = ["Tenant mismatch."] }, 0, []));
    public virtual async Task<HuntRun> ExecuteHuntAsync(string tenant, HuntDefinition hunt, CancellationToken ct)
    {
        var validation = await ValidateHuntAsync(tenant, hunt, ct); if (!validation.Valid) { _health.GetOrAdd(tenant, _ => new long[13])[7]++; throw new EnrollmentConflictException("HUNT_INVALID", string.Join(' ', validation.Errors.Values.SelectMany(x => x))); }
        var id = Guid.NewGuid(); var started = DateTimeOffset.UtcNow; var all = await LoadAsync(tenant, ct); using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(hunt.TimeoutMilliseconds); HuntResultRow[] rows;
        try { rows = all.Nodes.Where(x => hunt.EntityTypes.Contains(x.Type) && x.LastObserved >= hunt.From && x.FirstObserved <= hunt.To && InvestigationSafety.Matches(x, hunt.Where)).OrderBy(x => x.FirstObserved).ThenBy(x => x.EntityId).Take(hunt.MaximumResults).Select(x => new HuntResultRow(x.EntityId, x.Type, x.FirstObserved, x.DisplayName, x.Properties, x.EvidenceIds, x.EvidenceReferences)).ToArray(); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { _health.GetOrAdd(tenant, _ => new long[13])[8]++; rows = []; }
        var run = new HuntRun(id, tenant, hunt.HuntId, hunt.Version, "completed", validation.EstimatedCost, all.Nodes.Length, rows.Length, false, validation.Plan, started, DateTimeOffset.UtcNow, rows); _runs[(tenant, id)] = run; var h = _health.GetOrAdd(tenant, _ => new long[13]); h[3]++; h[11] = (long)(DateTimeOffset.UtcNow - started).TotalMilliseconds; return run;
    }
    public virtual Task<HuntRun?> GetRunAsync(string tenant, Guid run, CancellationToken ct) => Task.FromResult(_runs.GetValueOrDefault((tenant, run)));
    public virtual Task<HuntRun> CancelRunAsync(string tenant, Guid run, CancellationToken ct) { if (!_runs.TryGetValue((tenant, run), out var value)) throw new KeyNotFoundException(); value = value with { Status = "cancelled", CancelRequested = true, CompletedAt = DateTimeOffset.UtcNow }; _runs[(tenant, run)] = value; _health.GetOrAdd(tenant, _ => new long[13])[6]++; return Task.FromResult(value); }
    public async Task<HuntPivot?> PivotsAsync(string tenant, string entityId, InvestigationEntityType type, CancellationToken ct) { var all = await LoadAsync(tenant, ct); if (!all.Nodes.Any(x => x.EntityId == entityId && x.Type == type)) return null; return new(entityId, type, all.Edges.Where(x => x.SourceEntityId == entityId || x.DestinationEntityId == entityId).GroupBy(x => x.RelationshipType).ToDictionary(x => x.Key, x => x.Count())); }
    public virtual Task<HuntDefinition> SaveHuntAsync(string tenant, string actor, HuntDefinition hunt, bool newVersion, CancellationToken ct) { if (hunt.TenantId != tenant || hunt.Owner != actor && hunt.HuntId != Guid.Empty) throw new EnrollmentConflictException("HUNT_OWNERSHIP", "Saved hunt owner mismatch."); var id = hunt.HuntId == Guid.Empty ? Guid.NewGuid() : hunt.HuntId; var version = newVersion ? _hunts.Keys.Where(x => x.Tenant == tenant && x.Id == id).Select(x => x.Version).DefaultIfEmpty(0).Max() + 1 : Math.Max(1, hunt.Version); var value = hunt with { HuntId = id, Version = version, TenantId = tenant, Owner = actor, CreatedAt = DateTimeOffset.UtcNow, SharedWith = hunt.SharedWith.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().Take(100).ToArray() }; var validation = InvestigationSafety.Validate(value); if (!validation.Valid) throw new EnrollmentConflictException("HUNT_INVALID", string.Join(' ', validation.Errors.Values.SelectMany(x => x))); _hunts[(tenant, id, version)] = value; return Task.FromResult(value); }
    public virtual Task<IReadOnlyList<HuntDefinition>> SavedHuntsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<HuntDefinition>>(_hunts.Where(x => x.Key.Tenant == tenant).GroupBy(x => x.Key.Id).Select(x => x.OrderByDescending(v => v.Key.Version).First().Value).OrderBy(x => x.Name).ToArray());
    public virtual Task<IReadOnlyList<HuntDefinition>> HuntHistoryAsync(string tenant, Guid id, CancellationToken ct) => Task.FromResult<IReadOnlyList<HuntDefinition>>(_hunts.Where(x => x.Key.Tenant == tenant && x.Key.Id == id).OrderByDescending(x => x.Key.Version).Select(x => x.Value).ToArray());
    public virtual Task DeleteHuntAsync(string tenant, string actor, Guid id, CancellationToken ct) { var values = _hunts.Where(x => x.Key.Tenant == tenant && x.Key.Id == id).ToArray(); if (values.Any(x => x.Value.Owner != actor)) throw new EnrollmentConflictException("HUNT_OWNERSHIP", "Only the owner can delete a hunt."); foreach (var x in values) _hunts.TryRemove(x.Key, out _); return Task.CompletedTask; }
    public virtual Task<InvestigationHealth> HealthAsync(string tenant, CancellationToken ct) { var h = _health.GetOrAdd(tenant, _ => new long[13]); return Task.FromResult(new InvestigationHealth(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], _hunts.Keys.Count(x => x.Tenant == tenant), h[12], h[9], h[10], h[11], 0, DateTimeOffset.UtcNow)); }
}
