namespace OpenSecurityPlatform.Foundation;

public sealed record WorkerLease(
    string JobType,
    string JobId,
    string WorkerId,
    long Generation,
    DateTimeOffset AcquiredAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset HeartbeatAt,
    string State);

public sealed record HaAuditEvent(Guid AuditId, string EventType, string Subject, string Actor,
    long? Generation, DateTimeOffset OccurredAt, string Detail);
public sealed record ServiceInstanceHealth(string ServiceName, string InstanceId, string Region, string Version,
    DateTimeOffset StartedAt, DateTimeOffset HeartbeatAt, bool Live, bool Ready, string? DegradedReason);
public sealed record RecoveryStatus(
    Guid? BackupId, string? BackupState, DateTimeOffset? BackupCompletedAt, long? BackupSizeBytes, string? BackupSha256,
    Guid? DrillId, string? DrillState, DateTimeOffset? DrillCompletedAt, decimal? RtoSeconds, int? TableCount,
    int? DifferenceCount, long InventoriedObjects, long InventoryMismatches);

public interface IHighAvailabilityRepository
{
    Task<WorkerLease?> AcquireAsync(string jobType, string jobId, string workerId, TimeSpan duration, CancellationToken ct);
    Task<WorkerLease?> HeartbeatAsync(WorkerLease lease, TimeSpan duration, CancellationToken ct);
    Task<bool> ReleaseAsync(WorkerLease lease, string state, CancellationToken ct);
    Task<bool> FenceAsync(WorkerLease lease, CancellationToken ct);
    Task<IReadOnlyList<WorkerLease>> ListAsync(CancellationToken ct);
    Task<IReadOnlyList<HaAuditEvent>> AuditAsync(int limit, CancellationToken ct);
    Task RecordAuditAsync(HaAuditEvent value, CancellationToken ct);
    Task RegisterInstanceAsync(ServiceInstanceHealth instance, CancellationToken ct);
    Task<IReadOnlyList<ServiceInstanceHealth>> InstancesAsync(CancellationToken ct);
    Task<RecoveryStatus> RecoveryAsync(CancellationToken ct);
}

public sealed record ArtifactTransferRecord(
    string TenantId,
    Guid EndpointId,
    Guid AgentId,
    string InstallationId,
    ArtifactTransferStart Start,
    ArtifactTransferState State,
    long ReceivedBytes,
    int ReceivedChunks,
    IReadOnlyList<string> ChunkHashes,
    string? ObjectId,
    string? FailureReason,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    long Version);

public interface IArtifactTransferStateRepository
{
    Task<ArtifactTransferRecord?> GetAsync(Guid transferId, CancellationToken ct);
    Task<bool> CreateAsync(ArtifactTransferRecord value, CancellationToken ct);
    Task<bool> CompareExchangeAsync(ArtifactTransferRecord value, long expectedVersion, CancellationToken ct);
    Task<int> CountActiveAsync(string tenant, Guid endpointId, CancellationToken ct);
    Task<IReadOnlyList<ArtifactTransferRecord>> ListOwnerAsync(string tenant, Guid ownerId, CancellationToken ct);
    Task<IReadOnlyList<ArtifactTransferRecord>> ListAsync(CancellationToken ct);
}

public static class HighAvailabilitySafety
{
    public static bool IsCurrent(WorkerLease expected, WorkerLease authoritative, DateTimeOffset now) =>
        expected.JobType == authoritative.JobType && expected.JobId == authoritative.JobId &&
        expected.WorkerId == authoritative.WorkerId && expected.Generation == authoritative.Generation &&
        authoritative.State == "Owned" && authoritative.ExpiresAt > now;

    public static void ValidateTransferAdvance(ArtifactTransferRecord before, ArtifactTransferRecord after)
    {
        if (before.TenantId != after.TenantId || before.EndpointId != after.EndpointId || before.AgentId != after.AgentId ||
            before.InstallationId != after.InstallationId || before.Start != after.Start || after.Version != before.Version + 1 ||
            after.ReceivedBytes < before.ReceivedBytes || after.ReceivedChunks < before.ReceivedChunks ||
            after.ReceivedBytes > before.Start.Size || after.ChunkHashes.Count != after.ReceivedChunks)
            throw new EnrollmentConflictException("HA_TRANSFER_CAS", "Transfer advance violates its immutable binding, monotonic cursor, or fencing version.");
    }
}
