namespace OpenSecurityPlatform.Foundation;
public sealed record NetworkExportCreateRequest(string Format, NetworkSearchRequest Query, string[]? Fields = null, int MaximumRecords = 500);
public sealed record NetworkExportJob(Guid Id, string TenantId, string CreatedBy, FileExportState State, string Format, NetworkSearchRequest Query, string[] Fields, int MaximumRecords, Guid OutputObjectId, Guid ManifestObjectId, Guid MetadataObjectId, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? StartedAt = null, DateTimeOffset? CompletedAt = null, int? RecordCount = null, long? OutputSize = null, string? OutputSha256 = null, string? ErrorCode = null, string? ErrorSummary = null);
public sealed record NetworkExportManifest(string SchemaVersion, Guid ExportId, string TenantBinding, string Format, int RecordCount, NetworkSearchRequest Query, string[] Fields, DateTimeOffset CreatedAt, DateTimeOffset CompletedAt, long ObjectSize, string Sha256, string SourceApplicationVersion, string NetworkEventSchemaVersion, Guid OutputObjectId, Guid MetadataObjectId);
public interface INetworkExportRepository
{
    Task<NetworkExportJob> CreateAsync(string tenantId, string actor, NetworkExportCreateRequest request, CancellationToken ct);
    Task<NetworkExportJob?> GetAsync(string tenantId, Guid id, CancellationToken ct);
    Task<NetworkExportJob?> ClaimAsync(CancellationToken ct);
    Task CompleteAsync(Guid id, int records, long size, string sha256, DateTimeOffset completedAt, CancellationToken ct);
    Task FailAsync(Guid id, string code, string summary, CancellationToken ct);
    Task<IReadOnlyList<NetworkExportJob>> ExpireDueAsync(CancellationToken ct);
    Task AuditDownloadAsync(string tenantId, Guid id, string actor, CancellationToken ct);
}
