using OpenSecurityPlatform.Foundation;

sealed class LiveResponseLifecycleWorker(ILiveResponseRepository repository, ILogger<LiveResponseLifecycleWorker> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct) { while (!ct.IsCancellationRequested) { try { await repository.SweepAsync(ct); } catch (Exception e) when (e is not OperationCanceledException) { log.LogError(e, "Live Response lifecycle sweep failed"); } await Task.Delay(TimeSpan.FromSeconds(1), ct); } }
}
