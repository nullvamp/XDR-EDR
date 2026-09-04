namespace OpenSecurityPlatform.Foundation;

public sealed class FileProcessTelemetryRepository : IProcessTelemetryRepository, IProcessProjection
{
    private readonly object _gate = new();
    private readonly Dictionary<string, ProcessEntityView> _entities = [];
    private readonly Dictionary<Guid, ProcessTelemetryHealth> _health = [];
    private readonly HashSet<Guid> _events = [];

    public Task<ProcessIngestResult> IngestAsync(
        string tenantId,
        ProcessEventBatch batch,
        ProcessTelemetryHealth health,
        CancellationToken ct
    )
    {
        lock (_gate)
        {
            var accepted = new List<Guid>();
            var duplicates = new List<Guid>();
            foreach (var item in batch.Events)
            {
                if (!_events.Add(item.EventId))
                {
                    duplicates.Add(item.EventId);
                    continue;
                }
                accepted.Add(item.EventId);
                var key = $"{tenantId}:{item.EndpointId}:{item.ProcessEntityId}";
                if (_entities.TryGetValue(key, out var old))
                    _entities[key] = old with
                    {
                        ExitTime = item.ExitTime ?? old.ExitTime,
                        ExitEventId =
                            item.Kind == ProcessEventKind.Exited ? item.EventId : old.ExitEventId,
                        LastUpdatedAt = item.ObservedAt,
                        DurationMilliseconds =
                            item.DurationMilliseconds ?? old.DurationMilliseconds,
                        ExitCode = item.ExitCode ?? old.ExitCode,
                    };
                else
                    _entities[key] = From(tenantId, item);
            }
            _health[batch.EndpointId] = health;
            return Task.FromResult(
                new ProcessIngestResult(
                    new(
                        batch.BatchId,
                        accepted,
                        duplicates,
                        new Dictionary<Guid, string>(),
                        batch.LastSequence,
                        false
                    ),
                    accepted.Count,
                    duplicates.Count,
                    0,
                    0
                )
            );
        }
    }

    public Task<ProcessPage> SearchAsync(
        string tenantId,
        ProcessSearchRequest request,
        CancellationToken ct
    )
    {
        lock (_gate)
        {
            var values = _entities
                .Values.Where(x =>
                    x.TenantId == tenantId
                    && x.StartTime >= request.From
                    && x.StartTime <= request.To
                    && (request.EndpointId is null || x.EndpointId == request.EndpointId)
                )
                .OrderByDescending(x => x.StartTime)
                .Take(Math.Clamp(request.PageSize, 1, 500))
                .ToArray();
            return Task.FromResult(new ProcessPage(values, null));
        }
    }

    public Task<ProcessEntityView?> GetAsync(
        string tenantId,
        Guid endpointId,
        string processEntityId,
        CancellationToken ct
    )
    {
        lock (_gate)
            return Task.FromResult(
                _entities.GetValueOrDefault($"{tenantId}:{endpointId}:{processEntityId}")
            );
    }

    public async Task<IReadOnlyList<ProcessEntityView>> TimelineAsync(
        string tenantId,
        Guid endpointId,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct
    ) => (await SearchAsync(tenantId, new(endpointId, from, to, PageSize: limit), ct)).Items;

    public async Task<ProcessTreeNode?> TreeAsync(
        string tenantId,
        Guid endpointId,
        string rootProcessEntityId,
        int depth,
        CancellationToken ct
    )
    {
        var root = await GetAsync(tenantId, endpointId, rootProcessEntityId, ct);
        return root is null
            ? null
            : new(
                root,
                [],
                root.ParentProcessEntityId is not null,
                root.LineageState != LineageState.Resolved
            );
    }

    public Task<ProcessLineageView?> LineageAsync(
        string tenantId,
        Guid endpointId,
        string selectedProcessEntityId,
        int ancestorDepth,
        int descendantDepth,
        CancellationToken ct
    )
    {
        lock (_gate)
        {
            var all = _entities.Values
                .Where(x => x.TenantId == tenantId && x.EndpointId == endpointId)
                .ToArray();
            var byId = all.ToDictionary(x => x.ProcessEntityId, StringComparer.Ordinal);
            if (!byId.TryGetValue(selectedProcessEntityId, out var selected))
                return Task.FromResult<ProcessLineageView?>(null);
            bool MissingParent(ProcessEntityView item) => item.ParentProcessId is not null && (item.ParentProcessEntityId is null || !byId.ContainsKey(item.ParentProcessEntityId));
            ProcessTreeNode Build(ProcessEntityView item, int remaining, HashSet<string> path)
            {
                if (remaining == 0 || !path.Add(item.ProcessEntityId))
                    return new(item, [], MissingParent(item), item.LineageState != LineageState.Resolved);
                var children = all.Where(x => x.ParentProcessEntityId == item.ProcessEntityId).OrderBy(x => x.StartTime).Take(100).Select(x => Build(x, remaining - 1, new(path))).ToArray();
                return new(item, children, MissingParent(item), item.LineageState != LineageState.Resolved);
            }
            int CountDescendants(ProcessEntityView item, int remaining, HashSet<string> path)
            {
                if (remaining == 0 || !path.Add(item.ProcessEntityId))
                    return 0;
                var direct = all.Where(x => x.ParentProcessEntityId == item.ProcessEntityId).Take(100).ToArray();
                return direct.Length + direct.Sum(child => CountDescendants(child, remaining - 1, new(path)));
            }
            var count = 0;
            var current = selected;
            var seen = new HashSet<string>(StringComparer.Ordinal) { selected.ProcessEntityId };
            while (count < Math.Clamp(ancestorDepth, 0, 16) && current.ParentProcessEntityId is { } parentId && byId.TryGetValue(parentId, out var parent) && seen.Add(parent.ProcessEntityId))
            {
                current = parent;
                count++;
            }
            // Build from the earliest observed ancestor so sibling branches and every
            // bounded child are visible. The former selected-only wrapper made a valid
            // lineage look like a one- or two-node chain even when the repository held
            // additional children of an observed ancestor.
            var descendants = CountDescendants(selected, Math.Clamp(descendantDepth, 0, 8), []);
            var tree = Build(current, count + Math.Clamp(descendantDepth, 0, 8), []);
            return Task.FromResult<ProcessLineageView?>(new(selectedProcessEntityId, tree, count, descendants, MissingParent(current)));
        }
    }

    public Task<ProcessTelemetryHealth?> HealthAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        lock (_gate)
            return Task.FromResult(_health.GetValueOrDefault(endpointId));
    }

    public Task<IReadOnlyList<ProcessEntityView>> ListAllAsync(CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<ProcessEntityView>>(_entities.Values.ToArray());
    }

    public Task UpsertAsync(ProcessEntityView process, string eventId, CancellationToken ct)
    {
        lock (_gate)
            _entities[$"{process.TenantId}:{process.EndpointId}:{process.ProcessEntityId}"] =
                process;
        return Task.CompletedTask;
    }

    Task<ProcessPage> IProcessProjection.SearchAsync(
        string tenantId,
        ProcessSearchRequest request,
        CancellationToken ct
    ) => SearchAsync(tenantId, request, ct);

    public Task<ProcessProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<ProcessEntityView> processes,
        CancellationToken ct
    ) =>
        Task.FromResult(
            new ProcessProjectionRebuildResult("filesystem", processes.Count, TimeSpan.Zero, true)
        );

    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);

    private static ProcessEntityView From(string tenant, ProcessObservation item) =>
        new(
            tenant,
            item.EndpointId,
            item.ProcessEntityId,
            item.ProcessId,
            item.ProcessStartTime,
            item.ExitTime,
            item.ParentProcessEntityId,
            item.ParentProcessId,
            item.LineageState,
            item.ExecutableName,
            item.ExecutablePath,
            item.CommandLine,
            item.WorkingDirectory,
            item.UserName,
            item.UserId,
            item.SessionId,
            item.IntegrityLevel,
            item.Elevated,
            item.Architecture,
            item.ContainerId,
            item.ExecutableMetadata,
            item.EventId,
            item.Kind == ProcessEventKind.Exited ? item.EventId : null,
            item.ObservedAt,
            item.ObservedAt,
            item.CollectorType,
            item.CollectorVersion,
            item.SchemaVersion,
            item.NormalizationVersion,
            item.DataQualityFlags,
            false,
            item.DurationMilliseconds,
            item.ExitCode
        );
}
