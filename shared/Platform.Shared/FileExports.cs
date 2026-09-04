namespace OpenSecurityPlatform.Foundation;

[System.Text.Json.Serialization.JsonConverter(
    typeof(System.Text.Json.Serialization.JsonStringEnumConverter<FileExportState>)
)]
public enum FileExportState
{
    Pending,
    Running,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

public sealed record FileExportCreateRequest(
    string Format,
    FileSearchRequest Query,
    string[]? Fields = null,
    int MaximumRecords = 500
);

public sealed record FileExportJob(
    Guid Id,
    string TenantId,
    string CreatedBy,
    FileExportState State,
    string Format,
    FileSearchRequest Query,
    string[] Fields,
    int MaximumRecords,
    Guid OutputObjectId,
    Guid ManifestObjectId,
    Guid MetadataObjectId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? StartedAt = null,
    DateTimeOffset? CompletedAt = null,
    int? RecordCount = null,
    long? OutputSize = null,
    string? OutputSha256 = null,
    string? ErrorCode = null,
    string? ErrorSummary = null
);

public sealed record FileExportManifest(
    string SchemaVersion,
    Guid ExportId,
    string TenantBinding,
    string Format,
    int RecordCount,
    FileSearchRequest Query,
    string[] Fields,
    DateTimeOffset CreatedAt,
    DateTimeOffset CompletedAt,
    long ObjectSize,
    string Sha256,
    string SourceApplicationVersion,
    string FileEventSchemaVersion,
    Guid OutputObjectId,
    Guid MetadataObjectId
);

public interface IFileExportRepository
{
    Task<FileExportJob> CreateAsync(
        string tenantId,
        string actor,
        FileExportCreateRequest request,
        CancellationToken ct
    );
    Task<FileExportJob?> GetAsync(string tenantId, Guid exportId, CancellationToken ct);
    Task<FileExportJob?> ClaimAsync(CancellationToken ct);
    Task CompleteAsync(
        Guid exportId,
        int records,
        long size,
        string sha256,
        DateTimeOffset completedAt,
        CancellationToken ct
    );
    Task FailAsync(Guid exportId, string code, string summary, CancellationToken ct);
    Task<IReadOnlyList<FileExportJob>> ExpireDueAsync(CancellationToken ct);
    Task AuditDownloadAsync(string tenantId, Guid exportId, string actor, CancellationToken ct);
    Task<IReadOnlyDictionary<string, int>> CountByStateAsync(CancellationToken ct);
}

public sealed class FileFileExportRepository : IFileExportRepository
{
    readonly object _gate = new();
    readonly Dictionary<Guid, FileExportJob> _jobs = [];

    public Task<FileExportJob> CreateAsync(
        string tenantId,
        string actor,
        FileExportCreateRequest request,
        CancellationToken ct
    )
    {
        var now = DateTimeOffset.UtcNow;
        var value = new FileExportJob(
            Guid.NewGuid(),
            tenantId,
            actor,
            FileExportState.Pending,
            request.Format,
            request.Query,
            request.Fields ?? [],
            request.MaximumRecords,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            now,
            now,
            now.AddMinutes(15)
        );
        lock (_gate)
            _jobs[value.Id] = value;
        return Task.FromResult(value);
    }

    public Task<FileExportJob?> GetAsync(string tenantId, Guid exportId, CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult(
                _jobs.TryGetValue(exportId, out var value) && value.TenantId == tenantId
                    ? value
                    : null
            );
    }

    public Task<FileExportJob?> ClaimAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            var value = _jobs.Values.FirstOrDefault(x => x.State == FileExportState.Pending);
            if (value is null)
                return Task.FromResult<FileExportJob?>(null);
            value = value with
            {
                State = FileExportState.Running,
                StartedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            };
            _jobs[value.Id] = value;
            return Task.FromResult<FileExportJob?>(value);
        }
    }

    public Task CompleteAsync(Guid id, int records, long size, string hash, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate)
            if (_jobs.TryGetValue(id, out var value))
                _jobs[id] = value with
                {
                    State = FileExportState.Completed,
                    RecordCount = records,
                    OutputSize = size,
                    OutputSha256 = hash,
                    CompletedAt = at,
                    UpdatedAt = at,
                };
        return Task.CompletedTask;
    }

    public Task FailAsync(Guid id, string code, string summary, CancellationToken ct)
    {
        lock (_gate)
            if (_jobs.TryGetValue(id, out var value))
                _jobs[id] = value with
                {
                    State = FileExportState.Failed,
                    ErrorCode = code,
                    ErrorSummary = summary,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<FileExportJob>> ExpireDueAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            var values = _jobs.Values
                .Where(x => x.State == FileExportState.Completed && x.ExpiresAt <= DateTimeOffset.UtcNow)
                .ToArray();
            foreach (var value in values)
                _jobs[value.Id] = value with { State = FileExportState.Expired, UpdatedAt = DateTimeOffset.UtcNow };
            return Task.FromResult<IReadOnlyList<FileExportJob>>(values);
        }
    }

    public Task AuditDownloadAsync(string tenantId, Guid exportId, string actor, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyDictionary<string, int>> CountByStateAsync(CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyDictionary<string, int>>(
                _jobs.Values.GroupBy(x => x.State.ToString().ToLowerInvariant()).ToDictionary(x => x.Key, x => x.Count())
            );
    }
}
