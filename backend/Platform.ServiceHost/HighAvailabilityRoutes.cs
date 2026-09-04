using System.Collections.Concurrent;
using OpenSecurityPlatform.Foundation;

static class DependencyHealth
{
    public static async Task<bool> Probe(Func<CancellationToken, Task<bool>> check, TimeSpan timeout, CancellationToken outer)
    { using var bounded = CancellationTokenSource.CreateLinkedTokenSource(outer); bounded.CancelAfter(timeout); try { return await check(bounded.Token); } catch (Exception e) when (e is not OperationCanceledException || !outer.IsCancellationRequested) { return false; } }
}

sealed class FileHighAvailabilityRepository : IHighAvailabilityRepository
{
    readonly ConcurrentDictionary<string, WorkerLease> leases = new(); readonly ConcurrentDictionary<string, ServiceInstanceHealth> instances = new(); readonly List<HaAuditEvent> audit = []; readonly object gate = new();
    public Task<WorkerLease?> AcquireAsync(string t, string id, string worker, TimeSpan duration, CancellationToken ct) { lock (gate) { var key = t + "\n" + id; var now = DateTimeOffset.UtcNow; if (leases.TryGetValue(key, out var old) && old.ExpiresAt > now && old.WorkerId != worker) return Task.FromResult<WorkerLease?>(null); var generation = old is null ? 1 : old.WorkerId == worker ? old.Generation : old.Generation + 1; var x = new WorkerLease(t, id, worker, generation, old is not null && old.WorkerId == worker ? old.AcquiredAt : now, now.Add(duration), now, "Owned"); leases[key] = x; audit.Add(new(Guid.NewGuid(), old is null ? "lease.acquired" : "lease.takeover", t + "/" + id, worker, generation, now, "durable development ownership")); return Task.FromResult<WorkerLease?>(x); } }
    public Task<WorkerLease?> HeartbeatAsync(WorkerLease x, TimeSpan duration, CancellationToken ct) { lock (gate) { var key = x.JobType + "\n" + x.JobId; if (!leases.TryGetValue(key, out var v) || v.WorkerId != x.WorkerId || v.Generation != x.Generation || v.State != "Owned") return Task.FromResult<WorkerLease?>(null); v = v with { HeartbeatAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.Add(duration) }; leases[key] = v; return Task.FromResult<WorkerLease?>(v); } }
    public Task<bool> ReleaseAsync(WorkerLease x, string state, CancellationToken ct) { lock (gate) { var key = x.JobType + "\n" + x.JobId; if (!leases.TryGetValue(key, out var v) || v.WorkerId != x.WorkerId || v.Generation != x.Generation) return Task.FromResult(false); leases[key] = v with { State = state, ExpiresAt = DateTimeOffset.UtcNow }; audit.Add(new(Guid.NewGuid(), "lease.released", x.JobType + "/" + x.JobId, x.WorkerId, x.Generation, DateTimeOffset.UtcNow, state)); return Task.FromResult(true); } }
    public Task<bool> FenceAsync(WorkerLease x, CancellationToken ct) { lock (gate) return Task.FromResult(leases.TryGetValue(x.JobType + "\n" + x.JobId, out var v) && v.WorkerId == x.WorkerId && v.Generation == x.Generation && v.State == "Owned" && v.ExpiresAt > DateTimeOffset.UtcNow); }
    public Task<IReadOnlyList<WorkerLease>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WorkerLease>>(leases.Values.ToArray());
    public Task<IReadOnlyList<HaAuditEvent>> AuditAsync(int limit, CancellationToken ct) { lock (gate) return Task.FromResult<IReadOnlyList<HaAuditEvent>>(audit.TakeLast(Math.Clamp(limit, 1, 1000)).Reverse().ToArray()); }
    public Task RecordAuditAsync(HaAuditEvent x, CancellationToken ct) { lock (gate) audit.Add(x); return Task.CompletedTask; }
    public Task RegisterInstanceAsync(ServiceInstanceHealth x, CancellationToken ct) { instances[x.ServiceName + "\n" + x.InstanceId] = x; return Task.CompletedTask; }
    public Task<IReadOnlyList<ServiceInstanceHealth>> InstancesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<ServiceInstanceHealth>>(instances.Values.ToArray());
    public Task<RecoveryStatus> RecoveryAsync(CancellationToken ct) => Task.FromResult(new RecoveryStatus(null, null, null, null, null, null, null, null, null, null, null, 0, 0));
}

sealed class ServiceInstanceHeartbeat(IHighAvailabilityRepository repository, PlatformOptions options, ILogger<ServiceInstanceHeartbeat> log) : BackgroundService
{
    readonly DateTimeOffset started = DateTimeOffset.UtcNow;
    protected override async Task ExecuteAsync(CancellationToken ct) { while (!ct.IsCancellationRequested) { try { await repository.RegisterInstanceAsync(new(options.ServiceName, options.InstanceId, options.Region, ProductRelease.Version, started, DateTimeOffset.UtcNow, true, true, null), ct); } catch (Exception e) when (e is not OperationCanceledException) { log.LogWarning("HA instance heartbeat degraded: {ErrorType}", e.GetType().Name); } await Task.Delay(TimeSpan.FromSeconds(10), ct); } }
}

sealed class SchemaCompatibilityGuard(IHighAvailabilityRepository repository, ICapacityRetentionRepository capacity, PlatformOptions options) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        if (options.AdapterMode != "production") return;
        // These reads cover every Sprint 28 authoritative table family. A gateway
        // must refuse startup instead of silently running against an older schema.
        _ = await repository.ListAsync(ct);
        _ = await repository.InstancesAsync(ct);
        _ = await repository.RecoveryAsync(ct);
        _ = await capacity.OperationalMetricsAsync(ct);
    }
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}

sealed class DependencyTransitionAudit(IHighAvailabilityRepository repository, PlatformOptions options)
{
    readonly ConcurrentDictionary<string, bool> previous = new();
    readonly ConcurrentQueue<HaAuditEvent> pending = new();
    public async Task ObserveAsync(IReadOnlyDictionary<string, bool> current, CancellationToken ct)
    {
        foreach (var item in current)
        {
            if (previous.TryGetValue(item.Key, out var old) && old != item.Value)
                pending.Enqueue(new(Guid.NewGuid(), item.Value ? "service.recovered" : "service.degraded", item.Key, options.InstanceId, null, DateTimeOffset.UtcNow, item.Value ? "dependency probe recovered" : "bounded dependency probe failed"));
            else if (!item.Value && !previous.ContainsKey(item.Key))
                pending.Enqueue(new(Guid.NewGuid(), "service.degraded", item.Key, options.InstanceId, null, DateTimeOffset.UtcNow, "bounded dependency probe failed"));
            previous[item.Key] = item.Value;
        }
        if (!current.TryGetValue("postgresql", out var database) || !database) return;
        while (pending.TryPeek(out var value))
        {
            try { await repository.RecordAuditAsync(value, ct); pending.TryDequeue(out _); }
            catch { break; }
        }
    }
}

sealed class LeasedHostedService<T>(T inner, IHighAvailabilityRepository leases, PlatformOptions options, string jobType, ILogger<LeasedHostedService<T>> log) : BackgroundService where T : class, IHostedService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        WorkerLease? lease = null;
        var duration = TimeSpan.FromSeconds(20);
        while (!ct.IsCancellationRequested && lease is null)
        {
            try { lease = await leases.AcquireAsync(jobType, "singleton", options.InstanceId, duration, ct); }
            catch (Exception e) when (e is not OperationCanceledException) { log.LogWarning("Worker lease {Worker} unavailable: {ErrorType}", jobType, e.GetType().Name); }
            if (lease is null) await Task.Delay(TimeSpan.FromSeconds(3), ct);
        }
        if (lease is null) return;
        await inner.StartAsync(ct);
        var fenced = false;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
                WorkerLease? renewed;
                try { renewed = await leases.HeartbeatAsync(lease, duration, ct); }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    log.LogWarning("Worker {Worker} lease heartbeat temporarily unavailable: {ErrorType}", jobType, e.GetType().Name);
                    if (DateTimeOffset.UtcNow < lease.ExpiresAt) continue;
                    renewed = null;
                }
                if (renewed is null)
                {
                    fenced = true;
                    log.LogError("Worker {Worker} fenced after ownership loss or lease expiry", jobType);
                    break;
                }
                lease = renewed;
            }
            if (fenced)
                try { await leases.RecordAuditAsync(new(Guid.NewGuid(), "worker.fenced", jobType, options.InstanceId, lease.Generation, DateTimeOffset.UtcNow, "lease heartbeat rejected or expired after bounded retry"), CancellationToken.None); }
                catch (Exception e) { log.LogWarning("Worker {Worker} fence audit deferred: {ErrorType}", jobType, e.GetType().Name); }
        }
        finally
        {
            await inner.StopAsync(CancellationToken.None);
            try { await leases.ReleaseAsync(lease, "Released", CancellationToken.None); } catch { }
        }
    }
}

static class LeasedWorkerRegistration
{
    public static IServiceCollection AddLeasedWorker<T>(this IServiceCollection services, string jobType) where T : class, IHostedService { services.AddSingleton<T>(); services.AddSingleton<IHostedService>(p => new LeasedHostedService<T>(p.GetRequiredService<T>(), p.GetRequiredService<IHighAvailabilityRepository>(), p.GetRequiredService<PlatformOptions>(), jobType, p.GetRequiredService<ILogger<LeasedHostedService<T>>>())); return services; }
    public static IServiceCollection AddLeasedCoordinator(this IServiceCollection services, string jobType) { services.AddSingleton<IHostedService>(p => new LeasedCoordinatorService(p.GetRequiredService<IHighAvailabilityRepository>(), p.GetRequiredService<PlatformOptions>(), jobType, p.GetRequiredService<ILogger<LeasedCoordinatorService>>())); return services; }
}

// Request/poll driven domains keep their business state in PostgreSQL and do not
// need an in-memory job runner. This lease still elects one diagnostic/recovery
// coordinator so ownership, takeover, backlog review and maintenance never depend
// on container count. State mutations remain CAS/idempotency fenced in repositories.
sealed class LeasedCoordinatorService(IHighAvailabilityRepository repository, PlatformOptions options, string jobType, ILogger<LeasedCoordinatorService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        WorkerLease? lease = null; var duration = TimeSpan.FromSeconds(20);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                lease = lease is null
                    ? await repository.AcquireAsync(jobType, "coordinator", options.InstanceId, duration, ct)
                    : await repository.HeartbeatAsync(lease, duration, ct);
                if (lease is null) await Task.Delay(TimeSpan.FromSeconds(3), ct);
                else await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                lease = null; log.LogWarning("Coordinator lease {Worker} unavailable: {ErrorType}", jobType, e.GetType().Name);
                await Task.Delay(TimeSpan.FromSeconds(3), ct);
            }
        }
        if (lease is not null) try { await repository.ReleaseAsync(lease, "Released", CancellationToken.None); } catch { }
    }
}

static class HighAvailabilityRoutes
{
    public static async Task<string> Metrics(IHighAvailabilityRepository ha, IArtifactTransferStateRepository transfers, CancellationToken ct)
    {
        var instances = await ha.InstancesAsync(ct); var leases = await ha.ListAsync(ct); var audit = await ha.AuditAsync(1000, ct); var tx = await transfers.ListAsync(ct); var now = DateTimeOffset.UtcNow;
        var gateways = instances.Count(x => x.ServiceName == "gateway" && x.Live); var ready = instances.Count(x => x.ServiceName == "gateway" && x.Ready && x.Live); var unready = instances.Count(x => x.ServiceName == "gateway" && (!x.Ready || !x.Live)); var owned = leases.Count(x => x.State == "Owned" && x.ExpiresAt > now); var takeovers = audit.Count(x => x.EventType == "lease.takeover"); var fenced = audit.Count(x => x.EventType == "worker.fenced"); var active = tx.Count(x => x.State is ArtifactTransferState.Receiving or ArtifactTransferState.Verifying); var recovered = audit.Count(x => x.EventType == "transfer.recovered");
        return $"# TYPE platform_gateway_instances gauge\nplatform_gateway_instances {gateways}\nplatform_gateway_ready_instances {ready}\nplatform_gateway_unready_instances {unready}\nplatform_worker_leases_owned {owned}\nplatform_worker_lease_takeovers_total {takeovers}\nplatform_worker_fenced_total {fenced}\nplatform_artifact_transfers_active {active}\nplatform_artifact_transfer_recoveries_total {recovered}\n";
    }
    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/ha/status", async (HttpContext c, IHighAvailabilityRepository ha, IArtifactTransferStateRepository transfers, PlatformOptions o, CancellationToken ct) => Results.Ok(new ApiEnvelope<object>(new { tier = o.AdapterMode == "production" ? "Tier B - resilient single-site" : "Tier A - single-node development", qualified = "local single-site", multiSite = "NOT QUALIFIED", instances = await ha.InstancesAsync(ct), workers = await ha.ListAsync(ct), transfers = (await transfers.ListAsync(ct)).Select(x => new { x.Start.TransferId, x.TenantId, x.State, x.ReceivedChunks, totalChunks = (x.Start.Size + x.Start.ChunkSize - 1) / x.Start.ChunkSize, x.Version, x.UpdatedAt }), recovery = await ha.RecoveryAsync(ct), dependencies = new { postgresql = "authority; backup/restore qualified separately", nats = "durable single-node; cluster failover not qualified", openSearch = "projection; rebuild supported", minio = "restart recovery; distributed HA not qualified" } }, new(c.TraceIdentifier, "1.0")))).RequirePermission("fleet:read");
        app.MapGet("/api/v1/ha/audit", async (HttpContext c, IHighAvailabilityRepository ha, CancellationToken ct) => Results.Ok(new ApiEnvelope<object>(await ha.AuditAsync(200, ct), new(c.TraceIdentifier, "1.0")))).RequirePermission("fleet:read");
    }
}
