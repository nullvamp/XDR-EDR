using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

static class ProjectionRepairRoutes
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static void MapProjectionRepairRoutes(this WebApplication app, PlatformOptions options)
    {
        app.MapPost(
                "/api/v1/telemetry/projections:repair",
                async (
                    HttpContext context,
                    IDnsProjection dns,
                    IModuleProjection modules,
                    IPersistenceProjection persistence,
                    IIdentityProjection identities,
                    IExecutionProjection execution,
                    IDetectionProjection detections,
                    CancellationToken ct
                ) =>
                {
                    if (options.AdapterMode != "production" || string.IsNullOrWhiteSpace(options.DatabaseUrl))
                        return Results.NotFound();

                    var principal = (PrincipalContext)context.Items["principal"]!;
                    var tenant = Guid.Parse(principal.TenantId);
                    await using var source = NpgsqlDataSource.Create(options.DatabaseUrl);
                    await dns.EnsureAsync(ct);
                    await modules.EnsureAsync(ct);
                    await persistence.EnsureAsync(ct);
                    await identities.EnsureAsync(ct);
                    await execution.EnsureAsync(ct);
                    await detections.EnsureAsync(ct);

                    var counts = new Dictionary<string, int>(StringComparer.Ordinal);
                    counts["dns"] = await RepairAsync<DnsObservation>(source, tenant, "platform.dns_events", dns.UpsertAsync, ct);
                    counts["module"] = await RepairAsync<ModuleObservation>(source, tenant, "platform.module_events", modules.UpsertAsync, ct);
                    counts["persistence"] = await RepairAsync<PersistenceObservation>(source, tenant, "platform.persistence_events", persistence.UpsertAsync, ct);
                    counts["identity"] = await RepairAsync<IdentityObservation>(source, tenant, "platform.identity_events", identities.UpsertAsync, ct);
                    counts["execution"] = await RepairAsync<ExecutionObservation>(source, tenant, "platform.execution_events", execution.UpsertAsync, ct);
                    counts["detection"] = await RepairDetectionsAsync(source, tenant, detections.UpsertAsync, ct);
                    return Results.Ok(new ApiEnvelope<IReadOnlyDictionary<string, int>>(counts, new(context.TraceIdentifier, "1.0")));
                }
            )
            .RequirePermission("system:admin");
    }

    static async Task<int> RepairDetectionsAsync(
        NpgsqlDataSource source,
        Guid tenant,
        Func<DetectionFinding, CancellationToken, Task> upsert,
        CancellationToken ct
    )
    {
        var values = new List<DetectionFinding>();
        await using (var connection = await source.OpenConnectionAsync(ct))
        await using (var command = new NpgsqlCommand(
            "SELECT finding_data FROM platform.detection_findings WHERE tenant_id=$1 ORDER BY created_at,finding_id",
            connection
        ))
        {
            command.Parameters.AddWithValue(tenant);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                values.Add(JsonSerializer.Deserialize<DetectionFinding>(reader.GetString(0), Json)!);
        }

        await BoundedAsync.ForEachAsync(
            values,
            16,
            async (value, token) => await upsert(value, token),
            ct
        );
        return values.Count;
    }

    static async Task<int> RepairAsync<T>(
        NpgsqlDataSource source,
        Guid tenant,
        string table,
        Func<string, T, CancellationToken, Task> upsert,
        CancellationToken ct
    )
    {
        var values = new List<T>();
        await using (var connection = await source.OpenConnectionAsync(ct))
        await using (var command = new NpgsqlCommand($"SELECT event_data FROM {table} WHERE tenant_id=$1 ORDER BY observed_at,event_id", connection))
        {
            command.Parameters.AddWithValue(tenant);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                values.Add(JsonSerializer.Deserialize<T>(reader.GetString(0), Json)!);
        }

        await BoundedAsync.ForEachAsync(
            values,
            16,
            async (value, token) => await upsert(tenant.ToString("D"), value, token),
            ct
        );
        return values.Count;
    }
}
