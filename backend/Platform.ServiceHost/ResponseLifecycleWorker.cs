using OpenSecurityPlatform.Foundation;

sealed class ResponseLifecycleWorker(IResponseActionRepository repository, IObjectStorage objects, ILogger<ResponseLifecycleWorker> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct) { while (!ct.IsCancellationRequested) { try { await repository.SweepAsync(ct); foreach (var expired in await repository.ListExpiredArtifactsAsync(ct)) { await objects.DeleteAsync(expired.TenantId, expired.Artifact.ObjectId, ct); await objects.DeleteAsync(expired.TenantId, expired.Artifact.ManifestObjectId.ToString("D"), ct); await repository.MarkArtifactCleanedAsync(expired.TenantId, expired.Artifact.ArtifactId, ct); } } catch (Exception e) when (e is not OperationCanceledException) { log.LogError(e, "Response lifecycle or artifact-retention sweep failed safely"); } await Task.Delay(TimeSpan.FromSeconds(1), ct); } }
}
