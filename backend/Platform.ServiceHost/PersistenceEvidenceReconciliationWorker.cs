using OpenSecurityPlatform.Foundation;

sealed class PersistenceEvidenceReconciliationWorker(
    IPersistenceTelemetryRepository repository,
    ILogger<PersistenceEvidenceReconciliationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var changed = await repository.ReconcileEvidenceAsync(200, stoppingToken);
                if (changed > 0) logger.LogInformation("Reconciled {Count} persistence raw-evidence relationships", changed);
                await Task.Delay(changed > 0 ? 250 : 2000, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception exception)
            {
                logger.LogError(exception, "Persistence evidence reconciliation failed");
                await Task.Delay(5000, stoppingToken);
            }
        }
    }
}
