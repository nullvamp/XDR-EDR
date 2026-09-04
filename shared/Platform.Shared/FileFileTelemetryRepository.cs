namespace OpenSecurityPlatform.Foundation;

public sealed class FileFileTelemetryRepository : IFileTelemetryRepository, IFileProjection
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FileEntityView> _entities = [];
    private readonly List<(string Tenant, FileObservation Event)> _events = [];
    private readonly HashSet<(string Tenant, Guid Event)> _ids = [];
    private readonly Dictionary<(string Tenant, Guid Endpoint), FileTelemetryHealth> _health = [];
    private FileProjectionRebuildProgress _progress = new(
        Guid.Empty,
        "filesystem",
        "global",
        "idle",
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch,
        null,
        0,
        0,
        0,
        "filesystem",
        null,
        false
    );

    public Task EnsureAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<FileIngestResult> IngestAsync(
        string tenant,
        FileEventBatch batch,
        FileTelemetryHealth health,
        CancellationToken ct
    )
    {
        lock (_gate)
        {
            var accepted = new List<Guid>();
            var duplicates = new List<Guid>();
            foreach (var x in batch.Events)
            {
                if (!_ids.Add((tenant, x.EventId)))
                {
                    duplicates.Add(x.EventId);
                    continue;
                }
                accepted.Add(x.EventId);
                _events.Add((tenant, x));
                var key = $"{tenant}:{x.EndpointId}:{x.FileEntityId}";
                var prior = _entities.GetValueOrDefault(key);
                var paths = prior?.PreviousPaths.ToList() ?? [];
                if (
                    prior is not null
                    && prior.CurrentPath != x.CurrentPath
                    && !paths.Contains(prior.CurrentPath, StringComparer.Ordinal)
                )
                    paths.Add(prior.CurrentPath);
                _entities[key] = new(
                    tenant,
                    x.EndpointId,
                    x.FileEntityId,
                    x.NativeIdentity,
                    x.CurrentPath,
                    paths,
                    prior?.FirstObserved ?? x.ObservedAt,
                    x.ObservedAt,
                    x.Metadata.CreatedAt,
                    x.Kind == FileEventKind.Deleted ? x.ObservedAt : prior?.DeletedAt,
                    x.Kind switch
                    {
                        FileEventKind.Deleted => FileEntityState.Deleted,
                        FileEventKind.Renamed => FileEntityState.Renamed,
                        FileEventKind.Moved => FileEntityState.Moved,
                        _ => FileEntityState.Present,
                    },
                    x.Metadata,
                    x.Hash,
                    x.Process,
                    x.UserName,
                    x.SourceConfidence,
                    x.EventId,
                    x.DataQualityFlags,
                    x.CollectorType,
                    x.CollectorVersion
                );
            }
            _health[(tenant, batch.EndpointId)] = health;
            return Task.FromResult(
                new FileIngestResult(
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

    public Task<FilePage> SearchAsync(string tenant, FileSearchRequest q, CancellationToken ct)
    {
        lock (_gate)
        {
            var values = _entities
                .Values.Where(x =>
                    x.TenantId == tenant
                    && (q.EndpointId is null || x.EndpointId == q.EndpointId)
                    && (
                        string.IsNullOrWhiteSpace(q.Path)
                        || x.CurrentPath.Contains(q.Path, StringComparison.OrdinalIgnoreCase)
                    )
                    && (
                        string.IsNullOrWhiteSpace(q.FileName)
                        || Path.GetFileName(x.CurrentPath)
                            .Contains(q.FileName, StringComparison.OrdinalIgnoreCase)
                    )
                    && (
                        string.IsNullOrWhiteSpace(q.Extension)
                        || Path.GetExtension(x.CurrentPath)
                            .Equals(
                                "." + q.Extension.TrimStart('.'),
                                StringComparison.OrdinalIgnoreCase
                            )
                    )
                    && (string.IsNullOrWhiteSpace(q.Sha256) || x.Hash.Sha256 == q.Sha256)
                    && (
                        string.IsNullOrWhiteSpace(q.PreviousPath)
                        || x.PreviousPaths.Any(p =>
                            p.Contains(q.PreviousPath, StringComparison.OrdinalIgnoreCase)
                        )
                    )
                    && (
                        string.IsNullOrWhiteSpace(q.NativeFileId)
                        || x.NativeIdentity.FileId == q.NativeFileId
                    )
                    && (string.IsNullOrWhiteSpace(q.VolumeId) || x.NativeIdentity.VolumeId == q.VolumeId)
                    && (q.DeviceId is null || x.NativeIdentity.DeviceId == q.DeviceId)
                    && (q.Inode is null || x.NativeIdentity.Inode == q.Inode)
                )
                .OrderByDescending(x => x.LastObserved)
                .Take(Math.Clamp(q.PageSize, 1, 500))
                .ToArray();
            return Task.FromResult(new FilePage(values, null));
        }
    }

    public Task<FileObservation?> GetEventAsync(string tenant, Guid eventId, CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult(
                _events
                    .Where(x => x.Tenant == tenant && x.Event.EventId == eventId)
                    .Select(x => x.Event)
                    .FirstOrDefault()
            );
    }

    public Task<FileEntityView?> GetAsync(
        string tenant,
        Guid endpoint,
        string id,
        CancellationToken ct
    )
    {
        lock (_gate)
            return Task.FromResult(_entities.GetValueOrDefault($"{tenant}:{endpoint}:{id}"));
    }

    public Task<FileEventPage> HistoryAsync(
        string tenant,
        Guid endpoint,
        string id,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    ) => Events(tenant, endpoint, from, toInclusive, limit, x => x.FileEntityId == id);

    public Task<FileEventPage> EndpointTimelineAsync(
        string tenant,
        Guid endpoint,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    ) => Events(tenant, endpoint, from, toInclusive, limit, _ => true);

    public Task<FileEventPage> ProcessFilesAsync(
        string tenant,
        Guid endpoint,
        string id,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    ) => Events(tenant, endpoint, from, toInclusive, limit, x => x.Process?.ProcessEntityId == id);

    private Task<FileEventPage> Events(
        string tenant,
        Guid endpoint,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        Func<FileObservation, bool> filter
    )
    {
        lock (_gate)
            return Task.FromResult(
                new FileEventPage(
                    _events
                        .Where(x =>
                            x.Tenant == tenant
                            && x.Event.EndpointId == endpoint
                            && x.Event.ObservedAt >= from
                            && x.Event.ObservedAt <= to
                            && filter(x.Event)
                        )
                        .Select(x => x.Event)
                        .OrderBy(x => x.ObservedAt)
                        .Take(Math.Clamp(limit, 1, 500))
                        .ToArray(),
                    null
                )
            );
    }

    public Task<FileTelemetryHealth?> HealthAsync(
        string tenant,
        Guid endpoint,
        CancellationToken ct
    )
    {
        lock (_gate)
            return Task.FromResult(_health.GetValueOrDefault((tenant, endpoint)));
    }

    public Task<IReadOnlyList<FileEntityView>> ListAllAsync(CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<FileEntityView>>(_entities.Values.ToArray());
    }

    public Task UpsertAsync(FileEntityView file, string eventId, CancellationToken ct)
    {
        lock (_gate)
            _entities[$"{file.TenantId}:{file.EndpointId}:{file.FileEntityId}"] = file;
        return Task.CompletedTask;
    }

    Task<FilePage> IFileProjection.SearchAsync(
        string tenantId,
        FileSearchRequest request,
        CancellationToken ct
    ) => SearchAsync(tenantId, request, ct);

    public Task<ProcessProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<FileEntityView> files,
        CancellationToken ct
    )
    {
        var now = DateTimeOffset.UtcNow;
        _progress = new(
            Guid.NewGuid(),
            "filesystem",
            "global",
            "completed",
            now,
            now,
            now,
            files.Count,
            files.Count,
            0,
            "filesystem",
            null,
            false
        );
        return Task.FromResult(
            new ProcessProjectionRebuildResult("filesystem", files.Count, TimeSpan.Zero, true)
        );
    }

    public FileProjectionRebuildProgress GetRebuildProgress() => _progress;

    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);
}
