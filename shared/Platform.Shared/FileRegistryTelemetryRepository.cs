namespace OpenSecurityPlatform.Foundation;

public sealed class FileRegistryTelemetryRepository : IRegistryTelemetryRepository, IRegistryProjection
{
    private readonly object _gate = new();
    private readonly List<(string Tenant, RegistryObservation Event)> _events = [];
    private readonly HashSet<(string Tenant, Guid Event)> _ids = [];
    private readonly Dictionary<string, RegistryKeyView> _keys = [];
    private readonly Dictionary<string, RegistryValueView> _values = [];
    private readonly Dictionary<(string Tenant, Guid Endpoint), RegistryTelemetryHealth> _health = [];
    private RegistryProjectionRebuildProgress _progress = new(Guid.Empty, "filesystem", "global", "idle", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, null, 0, 0, 0, "filesystem", null, false);

    public Task EnsureAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<RegistryIngestResult> IngestAsync(string tenant, RegistryEventBatch batch, RegistryTelemetryHealth health, CancellationToken ct)
    {
        lock (_gate)
        {
            var accepted = new List<Guid>();
            var duplicates = new List<Guid>();
            foreach (var x in batch.Events.OrderBy(x => x.Sequence))
            {
                if (!_ids.Add((tenant, x.EventId))) { duplicates.Add(x.EventId); continue; }
                accepted.Add(x.EventId);
                _events.Add((tenant, x));
                Apply(tenant, x);
            }
            _health[(tenant, batch.EndpointId)] = health;
            return Task.FromResult(new RegistryIngestResult(new(batch.BatchId, accepted, duplicates, new Dictionary<Guid, string>(), batch.LastSequence, false), accepted.Count, duplicates.Count, 0, 0));
        }
    }

    private void Apply(string tenant, RegistryObservation x)
    {
        var keyId = $"{tenant}:{x.EndpointId}:{x.RegistryKeyEntityId}";
        var priorKey = _keys.GetValueOrDefault(keyId);
        var priorPaths = priorKey?.PreviousPaths.ToList() ?? [];
        if (priorKey is not null && priorKey.CurrentKeyPath != x.KeyPath && !priorPaths.Contains(priorKey.CurrentKeyPath, StringComparer.OrdinalIgnoreCase)) priorPaths.Add(priorKey.CurrentKeyPath);
        _keys[keyId] = new(tenant, x.EndpointId, x.RegistryKeyEntityId, x.Hive, x.DestinationKeyPath ?? x.KeyPath, priorPaths, x.ParentKeyPath, priorKey?.FirstObserved ?? x.ObservedAt, x.ObservedAt, x.Kind == RegistryEventKind.KeyCreated ? x.ObservedAt : priorKey?.CreatedAt, x.Kind == RegistryEventKind.KeyDeleted ? x.ObservedAt : priorKey?.DeletedAt, State(x.Kind), x.EventId, x.SourceConfidence, x.DataQualityFlags, x.Process, x.UserSid);
        if (x.RegistryValueEntityId is null || x.ValueName is null) return;
        var valueId = $"{tenant}:{x.EndpointId}:{x.RegistryValueEntityId}";
        var priorValue = _values.GetValueOrDefault(valueId);
        _values[valueId] = new(tenant, x.EndpointId, x.RegistryValueEntityId, x.RegistryKeyEntityId, x.Hive, x.KeyPath, x.ValueName, x.Value, priorValue?.FirstObserved ?? x.ObservedAt, x.ObservedAt, priorValue?.CreatedAt, x.Kind == RegistryEventKind.ValueDeleted ? x.ObservedAt : priorValue?.DeletedAt, State(x.Kind), x.EventId, x.SourceConfidence, x.DataQualityFlags, x.Process, x.UserSid);
    }

    private static RegistryEntityState State(RegistryEventKind kind) => kind switch { RegistryEventKind.KeyDeleted or RegistryEventKind.ValueDeleted => RegistryEntityState.Deleted, RegistryEventKind.KeyRenamed => RegistryEntityState.Renamed, _ => RegistryEntityState.Present };

    public Task<RegistryEventPage> SearchAsync(string tenant, RegistrySearchRequest q, CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult(new RegistryEventPage(Filter(tenant, q).OrderByDescending(x => x.ObservedAt).ThenByDescending(x => x.EventId).Take(Math.Clamp(q.PageSize, 1, 500)).ToArray(), null));
    }

    private IEnumerable<RegistryObservation> Filter(string tenant, RegistrySearchRequest q) => _events.Where(x => x.Tenant == tenant).Select(x => x.Event).Where(x =>
        (q.EndpointId is null || x.EndpointId == q.EndpointId) && (q.From is null || x.ObservedAt >= q.From) && (q.To is null || x.ObservedAt <= q.To) &&
        (string.IsNullOrWhiteSpace(q.Hive) || x.Hive.Equals(q.Hive, StringComparison.OrdinalIgnoreCase)) &&
        (string.IsNullOrWhiteSpace(q.KeyPath) || x.KeyPath.Contains(q.KeyPath, StringComparison.OrdinalIgnoreCase)) &&
        (string.IsNullOrWhiteSpace(q.ValueName) || (x.ValueName?.Contains(q.ValueName, StringComparison.OrdinalIgnoreCase) ?? false)) &&
        (q.Operation is null || x.Kind == q.Operation) &&
        (string.IsNullOrWhiteSpace(q.Process) || (x.Process?.Image?.Contains(q.Process, StringComparison.OrdinalIgnoreCase) ?? false) || x.Process?.ProcessEntityId == q.Process) &&
        (string.IsNullOrWhiteSpace(q.User) || x.UserSid == q.User) &&
        (string.IsNullOrWhiteSpace(q.ValueType) || x.Value.ValueType == q.ValueType) &&
        (string.IsNullOrWhiteSpace(q.Collector) || x.CollectorSource == q.Collector) &&
        (string.IsNullOrWhiteSpace(q.DataQuality) || x.DataQualityFlags.Contains(q.DataQuality)) &&
        (string.IsNullOrWhiteSpace(q.ContentHash) || x.Value.Sha256 == q.ContentHash));

    public Task<RegistryObservation?> GetEventAsync(string tenant, Guid id, CancellationToken ct) { lock (_gate) return Task.FromResult(_events.Where(x => x.Tenant == tenant && x.Event.EventId == id).Select(x => (RegistryObservation?)x.Event).FirstOrDefault()); }
    public Task<RegistryKeyView?> GetKeyAsync(string tenant, Guid endpoint, string id, CancellationToken ct) { lock (_gate) return Task.FromResult(_keys.GetValueOrDefault($"{tenant}:{endpoint}:{id}")); }
    public Task<RegistryValueView?> GetValueAsync(string tenant, Guid endpoint, string id, CancellationToken ct) { lock (_gate) return Task.FromResult(_values.GetValueOrDefault($"{tenant}:{endpoint}:{id}")); }
    public Task<RegistryEventPage> KeyHistoryAsync(string tenant, Guid endpoint, string id, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, x => x.RegistryKeyEntityId == id);
    public Task<RegistryEventPage> ValueHistoryAsync(string tenant, Guid endpoint, string id, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, x => x.RegistryValueEntityId == id);
    public Task<RegistryEventPage> EndpointTimelineAsync(string tenant, Guid endpoint, RegistrySearchRequest request, CancellationToken ct) => SearchAsync(tenant, request with { EndpointId = endpoint }, ct);
    public Task<RegistryEventPage> ProcessRegistryAsync(string tenant, Guid endpoint, string id, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, x => x.Process?.ProcessEntityId == id);
    private Task<RegistryEventPage> History(string tenant, Guid endpoint, DateTimeOffset from, DateTimeOffset to, int limit, Func<RegistryObservation, bool> predicate) { lock (_gate) return Task.FromResult(new RegistryEventPage(_events.Where(x => x.Tenant == tenant && x.Event.EndpointId == endpoint && x.Event.ObservedAt >= from && x.Event.ObservedAt <= to && predicate(x.Event)).Select(x => x.Event).OrderBy(x => x.ObservedAt).ThenBy(x => x.EventId).Take(Math.Clamp(limit, 1, 500)).ToArray(), null)); }
    public Task<RegistryTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct) { lock (_gate) return Task.FromResult(_health.GetValueOrDefault((tenant, endpoint))); }
    public Task<IReadOnlyList<RegistryObservation>> ListAllAsync(CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<RegistryObservation>>(_events.Select(x => x.Event).ToArray()); }
    public Task UpsertAsync(string tenantId, RegistryObservation observation, CancellationToken ct) { lock (_gate) { if (_ids.Add((tenantId, observation.EventId))) _events.Add((tenantId, observation)); Apply(tenantId, observation); } return Task.CompletedTask; }
    Task<RegistryEventPage> IRegistryProjection.SearchAsync(string tenantId, RegistrySearchRequest request, CancellationToken ct) => SearchAsync(tenantId, request, ct);
    public Task<ProcessProjectionRebuildResult> RebuildAsync(IReadOnlyList<RegistryObservation> events, CancellationToken ct) { var now = DateTimeOffset.UtcNow; _progress = new(Guid.NewGuid(), "filesystem", "global", "completed", now, now, now, events.Count, events.Count, 0, "filesystem", null, false); return Task.FromResult(new ProcessProjectionRebuildResult("filesystem", events.Count, TimeSpan.Zero, true)); }
    public RegistryProjectionRebuildProgress GetRebuildProgress() => _progress;
    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);
}
