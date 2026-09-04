using OpenSecurityPlatform.Foundation;

sealed class PlaybookWorker(IPlaybookWorkSource source, IPlaybookRepository repository, IPlaybookActionExecutor executor, ILogger<PlaybookWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { foreach (var item in await source.ReadyAsync(stoppingToken)) { try { await repository.AdvanceAsync(item.TenantId, item.ExecutionId, executor, stoppingToken); } catch (Exception error) { logger.LogWarning(error, "Bounded playbook work attempt {Attempt} failed", item.Attempts); } } }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) { logger.LogError(error, "Playbook work cycle failed"); }
            await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
        }
    }
}
