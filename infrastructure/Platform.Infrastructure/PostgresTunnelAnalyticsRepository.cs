using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresTunnelAnalyticsRepository(string connectionString) : ITunnelAnalyticsRepository, IDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly SemaphoreSlim gate = new(1, 1);

    public async Task<IReadOnlyList<TunnelFinding>> IngestAsync(string tenant, IReadOnlyList<TunnelObservation> values, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try
        {
            var memory = await LoadAsync(tenant, ct); var existing = memory.SnapshotObservations(tenant).Select(x => x.ObservationId).ToHashSet(); var findings = await memory.IngestAsync(tenant, values, ct);
            await using var c = await Open(ct); await using var tx = await c.BeginTransactionAsync(ct);
            foreach (var x in values.Where(x => !existing.Contains(x.ObservationId))) { await Insert(c, tx, "platform.tunnel_observations", "observation_id", x.ObservationId, tenant, x, ct); await Outbox(c, tx, tenant, "tunnel.observation.changed.v1", new { x.ObservationId }, ct); }
            foreach (var x in findings) { await Insert(c, tx, "platform.tunnel_findings", "finding_id", x.FindingId, tenant, x, ct); await Outbox(c, tx, tenant, "tunnel.finding.changed.v1", new { x.FindingId }, ct); }
            await tx.CommitAsync(ct); return findings;
        }
        finally { gate.Release(); }
    }
    public async Task<TunnelPage<TunnelObservation>> SearchObservationsAsync(string tenant, TunnelSearchRequest q, CancellationToken ct) => await (await LoadAsync(tenant, ct)).SearchObservationsAsync(tenant, q, ct);
    public async Task<TunnelPage<TunnelFinding>> SearchFindingsAsync(string tenant, TunnelSearchRequest q, CancellationToken ct) => await (await LoadAsync(tenant, ct)).SearchFindingsAsync(tenant, q, ct);
    public async Task<TunnelObservation?> GetObservationAsync(string tenant, Guid id, CancellationToken ct) => await (await LoadAsync(tenant, ct)).GetObservationAsync(tenant, id, ct);
    public async Task<TunnelFinding?> GetFindingAsync(string tenant, Guid id, CancellationToken ct) => await (await LoadAsync(tenant, ct)).GetFindingAsync(tenant, id, ct);
    public async Task<TunnelChain> BuildChainAsync(string tenant, Guid id, int depth, CancellationToken ct) => await (await LoadAsync(tenant, ct)).BuildChainAsync(tenant, id, depth, ct);
    public async Task<TunnelExclusion> AddExclusionAsync(string tenant, TunnelExclusion x, string actor, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var v = await memory.AddExclusionAsync(tenant, x, actor, ct); await using var c = await Open(ct); await using var q = new NpgsqlCommand("INSERT INTO platform.tunnel_exclusions(tenant_id,exclusion_id,version,exclusion_data) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue(v.ExclusionId); q.Parameters.AddWithValue(v.Version); AddJson(q, v); await q.ExecuteNonQueryAsync(ct); return v; } finally { gate.Release(); }
    }
    public async Task<IReadOnlyList<TunnelExclusion>> ExclusionsAsync(string tenant, CancellationToken ct) => await (await LoadAsync(tenant, ct)).ExclusionsAsync(tenant, ct);
    public async Task<TunnelHealth> HealthAsync(string tenant, CancellationToken ct) { var counts = await CountsAsync(tenant, ct); return new(counts.Observations, counts.Findings, await Count(tenant, "platform.tunnel_findings", "(finding_data->>'excluded')::boolean", ct), 0, 0, 0, TunnelAnalyticsSafety.MaximumChainDepth, "NOT OBSERVABLE BY SOURCE", DateTimeOffset.UtcNow); }
    public async Task<(long Observations, long Findings)> CountsAsync(string tenant, CancellationToken ct) => (await Count(tenant, "platform.tunnel_observations", "true", ct), await Count(tenant, "platform.tunnel_findings", "true", ct));
    async Task<long> Count(string tenant, string table, string predicate, CancellationToken ct) { await using var c = await Open(ct); await using var q = new NpgsqlCommand($"SELECT count(*) FROM {table} WHERE tenant_id=$1 AND {predicate}", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); return (long)(await q.ExecuteScalarAsync(ct) ?? 0L); }
    async Task<FileTunnelAnalyticsRepository> LoadAsync(string tenant, CancellationToken ct) { await using var c = await Open(ct); var o = await Read<TunnelObservation>(c, "SELECT observation_data FROM platform.tunnel_observations WHERE tenant_id=$1", tenant, ct); var e = await Read<TunnelExclusion>(c, "SELECT exclusion_data FROM platform.tunnel_exclusions WHERE tenant_id=$1", tenant, ct); var memory = new FileTunnelAnalyticsRepository(); foreach (var x in e) await memory.AddExclusionAsync(tenant, x, x.CreatedBy, ct); if (o.Count > 0) await memory.IngestAsync(tenant, o, ct); return memory; }
    static async Task<List<T>> Read<T>(NpgsqlConnection c, string sql, string tenant, CancellationToken ct) { await using var q = new NpgsqlCommand(sql, c); q.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await q.ExecuteReaderAsync(ct); var l = new List<T>(); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<T>(r.GetString(0), Json) is { } x) l.Add(x); return l; }
    async Task<NpgsqlConnection> Open(CancellationToken ct) { var c = new NpgsqlConnection(connectionString); await c.OpenAsync(ct); return c; }
    static async Task Insert<T>(NpgsqlConnection c, NpgsqlTransaction tx, string table, string idName, Guid id, string tenant, T value, CancellationToken ct) { await using var q = new NpgsqlCommand($"INSERT INTO {table}(tenant_id,{idName},{(idName == "observation_id" ? "observation_data" : "finding_data")}) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", c, tx); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue(id); AddJson(q, value); await q.ExecuteNonQueryAsync(ct); }
    static void AddJson<T>(NpgsqlCommand q, T value) => q.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(value, Json) });
    static async Task Outbox(NpgsqlConnection c, NpgsqlTransaction tx, string tenant, string subject, object data, CancellationToken ct) { await using var q = new NpgsqlCommand("INSERT INTO platform.outbox(id,tenant_id,topic,subject,message,trace_id) VALUES($1,$2,$3,$4,$5,'')", c, tx); q.Parameters.AddWithValue(Guid.NewGuid()); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue("tunnel"); q.Parameters.AddWithValue(subject); AddJson(q, data); await q.ExecuteNonQueryAsync(ct); }
    public void Dispose() => gate.Dispose();
}
