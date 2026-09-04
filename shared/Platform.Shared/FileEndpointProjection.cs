namespace OpenSecurityPlatform.Foundation;

public sealed class FileEndpointProjection(IEndpointRepository repository) : IEndpointProjection
{
    public Task<ProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<EndpointView> endpoints,
        CancellationToken ct
    ) =>
        Task.FromResult(
            new ProjectionRebuildResult("filesystem", endpoints.Count, TimeSpan.Zero, true)
        );

    public ProjectionRebuildProgress GetRebuildProgress() =>
        new(false, "filesystem", 0, 0, null, DateTimeOffset.UtcNow, null);

    public Task UpsertAsync(
        EndpointView endpoint,
        string eventId,
        CancellationToken cancellationToken
    ) => Task.CompletedTask;

    public Task<EndpointPage> SearchAsync(
        string tenantId,
        int pageSize,
        string? cursor,
        string? query,
        EndpointStatus? status,
        CancellationToken cancellationToken
    ) =>
        repository.ListEndpointsAsync(tenantId, pageSize, cursor, query, status, cancellationToken);

    public Task<bool> HealthAsync(CancellationToken cancellationToken) =>
        repository.HealthAsync(cancellationToken);
}
