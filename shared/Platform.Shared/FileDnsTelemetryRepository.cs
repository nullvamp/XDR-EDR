namespace OpenSecurityPlatform.Foundation;

public sealed class FileDnsTelemetryRepository : IDnsTelemetryRepository, IDnsProjection
{
    readonly object _gate = new();
    readonly List<(string Tenant, DnsObservation Event)> _events = [];
    readonly HashSet<(string Tenant, Guid Event)> _ids = [];
    readonly Dictionary<(string Tenant, Guid Endpoint), DnsTelemetryHealth> _health = [];
    IEnumerable<DnsObservation> Filter(string tenant, DnsSearchRequest q) => _events
        .Where(x => x.Tenant == tenant).Select(x => x.Event).Where(x =>
            (q.EndpointId is null || x.EndpointId == q.EndpointId) &&
            (q.From is null || x.ObservedAt >= q.From) && (q.To is null || x.ObservedAt <= q.To) &&
            (string.IsNullOrWhiteSpace(q.QueryName) || x.CanonicalQueryName.Equals(q.QueryName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)) &&
            (string.IsNullOrWhiteSpace(q.Suffix) || x.CanonicalQueryName.EndsWith(q.Suffix.TrimStart('.'), StringComparison.OrdinalIgnoreCase)) &&
            (string.IsNullOrWhiteSpace(q.RecordType) || string.Equals(x.RecordType, q.RecordType, StringComparison.OrdinalIgnoreCase)) &&
            (string.IsNullOrWhiteSpace(q.ResponseCode) || x.ResponseCode == q.ResponseCode) &&
            (string.IsNullOrWhiteSpace(q.ResolvedAddress) || x.Answers.Any(a => a.ResolvedAddress == q.ResolvedAddress)) &&
            (string.IsNullOrWhiteSpace(q.Process) || x.Process?.ProcessEntityId == q.Process || (x.Process?.Image?.Contains(q.Process, StringComparison.OrdinalIgnoreCase) ?? false)) &&
            (string.IsNullOrWhiteSpace(q.User) || x.User == q.User) &&
            (string.IsNullOrWhiteSpace(q.Resolver) || x.ResolverAddress == q.Resolver) &&
            (string.IsNullOrWhiteSpace(q.Collector) || x.CollectorSource == q.Collector) &&
            (string.IsNullOrWhiteSpace(q.Quality) || x.DataQualityFlags.Contains(q.Quality)));
    public Task<DnsIngestResult> IngestAsync(string tenant, DnsEventBatch batch, DnsTelemetryHealth health, CancellationToken ct)
    {
        lock (_gate)
        {
            var accepted = new List<Guid>(); var duplicates = new List<Guid>();
            foreach (var x in batch.Events.OrderBy(x => x.Sequence))
                if (_ids.Add((tenant, x.EventId))) { accepted.Add(x.EventId); _events.Add((tenant, x)); }
                else duplicates.Add(x.EventId);
            _health[(tenant, batch.EndpointId)] = health with { QueueDepth = Math.Max(0, health.QueueDepth - accepted.Count - duplicates.Count) };
            return Task.FromResult(new DnsIngestResult(new(batch.BatchId, accepted, duplicates,
                new Dictionary<Guid, string>(), batch.LastSequence, false), accepted.Count, duplicates.Count, 0, 0));
        }
    }
    public Task<DnsEventPage> SearchAsync(string tenant, DnsSearchRequest q, CancellationToken ct)
    { lock (_gate) return Task.FromResult(new DnsEventPage(Filter(tenant, q).OrderByDescending(x => x.ObservedAt).ThenByDescending(x => x.EventId).Take(Math.Clamp(q.PageSize, 1, 500)).ToArray(), null)); }
    public Task<DnsObservation?> GetEventAsync(string tenant, Guid id, CancellationToken ct)
    { lock (_gate) return Task.FromResult(_events.Where(x => x.Tenant == tenant && x.Event.EventId == id).Select(x => (DnsObservation?)x.Event).FirstOrDefault()); }
    Task<DnsEventPage> History(string tenant, Guid endpoint, DateTimeOffset from, DateTimeOffset to, int limit, Func<DnsObservation, bool> predicate)
    { lock (_gate) return Task.FromResult(new DnsEventPage(_events.Where(x => x.Tenant == tenant && x.Event.EndpointId == endpoint && x.Event.ObservedAt >= from && x.Event.ObservedAt <= to && predicate(x.Event)).Select(x => x.Event).OrderBy(x => x.ObservedAt).ThenBy(x => x.EventId).Take(Math.Clamp(limit, 1, 500)).ToArray(), null)); }
    public Task<DnsEventPage> HistoryAsync(string tenant, Guid endpoint, string transaction, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, x => x.TransactionEntityId == transaction);
    public Task<DnsEventPage> ProcessDnsAsync(string tenant, Guid endpoint, string process, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, x => x.Process?.ProcessEntityId == process);
    public Task<DnsTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct)
    { lock (_gate) return Task.FromResult(_health.GetValueOrDefault((tenant, endpoint))); }
    public Task<IReadOnlyList<DnsObservation>> ListAllAsync(CancellationToken ct)
    { lock (_gate) return Task.FromResult<IReadOnlyList<DnsObservation>>(_events.Select(x => x.Event).ToArray()); }
    public Task EnsureAsync(CancellationToken ct) => Task.CompletedTask;
    public Task UpsertAsync(string tenant, DnsObservation x, CancellationToken ct)
    { lock (_gate) if (_ids.Add((tenant, x.EventId))) _events.Add((tenant, x)); return Task.CompletedTask; }
    Task<DnsEventPage> IDnsProjection.SearchAsync(string tenant, DnsSearchRequest q, CancellationToken ct) => SearchAsync(tenant, q, ct);
    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);
}

public sealed class FileDnsPolicyRepository : IDnsPolicyRepository
{
    readonly object _gate = new(); readonly List<DnsPolicyVersion> _versions = [];
    readonly Dictionary<(string, Guid?), Guid> _assignments = [];
    readonly Dictionary<(string, Guid), DnsPolicyAcknowledgement> _acks = [];
    public Task<IReadOnlyList<DnsPolicyVersion>> ListAsync(string t, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<DnsPolicyVersion>>(_versions.Where(x => x.TenantId == t).ToArray()); }
    public Task<DnsPolicyVersion> CreateAsync(string t, string actor, string name, DnsTelemetryPolicy p, CancellationToken ct)
    { var errors = DnsPolicyValidation.Validate(p); if (errors.Count > 0) throw new EnrollmentConflictException("DNS_POLICY_INVALID", string.Join(' ', errors.SelectMany(x => x.Value))); lock (_gate) { var v = new DnsPolicyVersion(Guid.NewGuid(), t, name, _versions.Where(x => x.TenantId == t && x.Name == name).Select(x => x.Version).DefaultIfEmpty().Max() + 1, p, DnsEvidence.CanonicalSha256(p), "active", DateTimeOffset.UtcNow, actor); _versions.Add(v); return Task.FromResult(v); } }
    public Task AssignAsync(string t, Guid id, Guid? endpoint, string actor, CancellationToken ct) { lock (_gate) { if (!_versions.Any(x => x.TenantId == t && x.Id == id)) throw new EnrollmentConflictException("DNS_POLICY_NOT_FOUND", "DNS policy was not found in this tenant."); _assignments[(t, endpoint)] = id; } return Task.CompletedTask; }
    public Task<EffectiveDnsPolicy> EffectiveAsync(string t, Guid endpoint, CancellationToken ct)
    { lock (_gate) { var id = _assignments.GetValueOrDefault((t, endpoint)); if (id == Guid.Empty) id = _assignments.GetValueOrDefault((t, null)); var p = _versions.LastOrDefault(x => x.TenantId == t && x.Id == id); if (p is null) { p = new DnsPolicyVersion(Guid.Empty, t, "safe-default", 1, new(), DnsEvidence.CanonicalSha256(new DnsTelemetryPolicy()), "default", DateTimeOffset.UnixEpoch, "system"); } var a = _acks.GetValueOrDefault((t, endpoint)); return Task.FromResult(new EffectiveDnsPolicy(p, id == Guid.Empty ? "default" : "assignment", endpoint, a?.AcknowledgedAt, a is { Applied: true } ? a.Version : null, a is { Applied: false } ? a.Version : null, a?.ValidationError, a is null || a.Version != p.Version || !a.Applied)); } }
    public Task AcknowledgeAsync(string t, Guid e, DnsPolicyAcknowledgement a, CancellationToken ct) { lock (_gate) _acks[(t, e)] = a; return Task.CompletedTask; }
}
