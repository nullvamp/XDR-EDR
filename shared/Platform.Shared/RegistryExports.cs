namespace OpenSecurityPlatform.Foundation;

public sealed record RegistryExportCreateRequest(string Format, RegistrySearchRequest Query, string[]? Fields = null, int MaximumRecords = 500);
public sealed record RegistryExportJob(Guid Id, string TenantId, string CreatedBy, FileExportState State, string Format, RegistrySearchRequest Query, string[] Fields, int MaximumRecords, Guid OutputObjectId, Guid ManifestObjectId, Guid MetadataObjectId, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? StartedAt = null, DateTimeOffset? CompletedAt = null, int? RecordCount = null, long? OutputSize = null, string? OutputSha256 = null, string? ErrorCode = null, string? ErrorSummary = null);
public sealed record RegistryExportManifest(string SchemaVersion, Guid ExportId, string TenantBinding, string Format, int RecordCount, RegistrySearchRequest Query, string[] Fields, DateTimeOffset CreatedAt, DateTimeOffset CompletedAt, long ObjectSize, string Sha256, string SourceApplicationVersion, string RegistryEventSchemaVersion, Guid OutputObjectId, Guid MetadataObjectId);
public interface IRegistryExportRepository
{
    Task<RegistryExportJob> CreateAsync(string tenantId, string actor, RegistryExportCreateRequest request, CancellationToken ct);
    Task<RegistryExportJob?> GetAsync(string tenantId, Guid id, CancellationToken ct);
    Task<RegistryExportJob?> ClaimAsync(CancellationToken ct);
    Task CompleteAsync(Guid id, int records, long size, string sha256, DateTimeOffset completedAt, CancellationToken ct);
    Task FailAsync(Guid id, string code, string summary, CancellationToken ct);
    Task<IReadOnlyList<RegistryExportJob>> ExpireDueAsync(CancellationToken ct);
    Task AuditDownloadAsync(string tenantId, Guid id, string actor, CancellationToken ct);
}
public sealed class FileRegistryExportRepository : IRegistryExportRepository
{
    private readonly object _gate = new(); private readonly Dictionary<Guid, RegistryExportJob> _jobs = [];
    public Task<RegistryExportJob> CreateAsync(string tenant, string actor, RegistryExportCreateRequest r, CancellationToken ct) { var now = DateTimeOffset.UtcNow; var v = new RegistryExportJob(Guid.NewGuid(), tenant, actor, FileExportState.Pending, r.Format, r.Query, r.Fields ?? [], r.MaximumRecords, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), now, now, now.AddMinutes(15)); lock (_gate) _jobs[v.Id] = v; return Task.FromResult(v); }
    public Task<RegistryExportJob?> GetAsync(string tenant, Guid id, CancellationToken ct) { lock (_gate) return Task.FromResult(_jobs.TryGetValue(id, out var v) && v.TenantId == tenant ? v : null); }
    public Task<RegistryExportJob?> ClaimAsync(CancellationToken ct) { lock (_gate) { var v = _jobs.Values.FirstOrDefault(x => x.State == FileExportState.Pending); if (v is null) return Task.FromResult<RegistryExportJob?>(null); v = v with { State = FileExportState.Running, StartedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow }; _jobs[v.Id] = v; return Task.FromResult<RegistryExportJob?>(v); } }
    public Task CompleteAsync(Guid id, int records, long size, string hash, DateTimeOffset at, CancellationToken ct) { lock (_gate) if (_jobs.TryGetValue(id, out var v)) _jobs[id] = v with { State = FileExportState.Completed, RecordCount = records, OutputSize = size, OutputSha256 = hash, CompletedAt = at, UpdatedAt = at }; return Task.CompletedTask; }
    public Task FailAsync(Guid id, string code, string summary, CancellationToken ct) { lock (_gate) if (_jobs.TryGetValue(id, out var v)) _jobs[id] = v with { State = FileExportState.Failed, ErrorCode = code, ErrorSummary = summary, UpdatedAt = DateTimeOffset.UtcNow }; return Task.CompletedTask; }
    public Task<IReadOnlyList<RegistryExportJob>> ExpireDueAsync(CancellationToken ct) { lock (_gate) { var values = _jobs.Values.Where(x => x.State == FileExportState.Completed && x.ExpiresAt <= DateTimeOffset.UtcNow).ToArray(); foreach (var v in values) _jobs[v.Id] = v with { State = FileExportState.Expired, UpdatedAt = DateTimeOffset.UtcNow }; return Task.FromResult<IReadOnlyList<RegistryExportJob>>(values); } }
    public Task AuditDownloadAsync(string tenantId, Guid id, string actor, CancellationToken ct) => Task.CompletedTask;
}
