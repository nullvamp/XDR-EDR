using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresHighAvailabilityRepository : IHighAvailabilityRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource data;
    public PostgresHighAvailabilityRepository(string connectionString) => data = NpgsqlDataSource.Create(connectionString);

    public async Task<WorkerLease?> AcquireAsync(string type, string id, string worker, TimeSpan duration, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        await using var q = new NpgsqlCommand("SELECT worker_id,generation,acquired_at,expires_at,heartbeat_at,state FROM platform.worker_leases WHERE job_type=$1 AND job_id=$2 FOR UPDATE", c, tx);
        q.Parameters.AddWithValue(type); q.Parameters.AddWithValue(id);
        WorkerLease? current = null;
        await using (var r = await q.ExecuteReaderAsync(ct)) if (await r.ReadAsync(ct)) current = Read(type, id, r);
        if (current is not null && current.ExpiresAt > DateTimeOffset.UtcNow && current.WorkerId != worker) { await tx.RollbackAsync(ct); return null; }
        var now = DateTimeOffset.UtcNow; var generation = current is null ? 1 : current.WorkerId == worker ? current.Generation : current.Generation + 1;
        var acquired = current is not null && current.WorkerId == worker ? current.AcquiredAt : now;
        await using var u = new NpgsqlCommand("INSERT INTO platform.worker_leases(job_type,job_id,worker_id,generation,acquired_at,expires_at,heartbeat_at,state) VALUES($1,$2,$3,$4,$5,$6,$5,'Owned') ON CONFLICT(job_type,job_id) DO UPDATE SET worker_id=EXCLUDED.worker_id,generation=EXCLUDED.generation,acquired_at=EXCLUDED.acquired_at,expires_at=EXCLUDED.expires_at,heartbeat_at=EXCLUDED.heartbeat_at,state='Owned'", c, tx);
        object[] values = [type, id, worker, generation, acquired, now.Add(duration)]; for (var i = 0; i < values.Length; i++) u.Parameters.AddWithValue(values[i]); await u.ExecuteNonQueryAsync(ct);
        if (current is not null && current.WorkerId != worker) await Audit(c, tx, "lease.takeover", $"{type}/{id}", worker, generation, "expired owner fenced", ct);
        else if (current is null) await Audit(c, tx, "lease.acquired", $"{type}/{id}", worker, generation, "initial ownership", ct);
        await tx.CommitAsync(ct); return new(type, id, worker, generation, acquired, now.Add(duration), now, "Owned");
    }

    public async Task<WorkerLease?> HeartbeatAsync(WorkerLease lease, TimeSpan duration, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow; await using var c = await data.OpenConnectionAsync(ct);
        await using var q = new NpgsqlCommand("UPDATE platform.worker_leases SET heartbeat_at=$1,expires_at=$2 WHERE job_type=$3 AND job_id=$4 AND worker_id=$5 AND generation=$6 AND state='Owned' AND expires_at>now() RETURNING acquired_at", c);
        object[] v = [now, now.Add(duration), lease.JobType, lease.JobId, lease.WorkerId, lease.Generation]; foreach (var x in v) q.Parameters.AddWithValue(x);
        var acquired = await q.ExecuteScalarAsync(ct); return acquired is DateTime at ? lease with { AcquiredAt = new DateTimeOffset(at), HeartbeatAt = now, ExpiresAt = now.Add(duration) } : null;
    }
    public async Task<bool> ReleaseAsync(WorkerLease lease, string state, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using var q = new NpgsqlCommand("UPDATE platform.worker_leases SET state=$1,expires_at=now(),heartbeat_at=now() WHERE job_type=$2 AND job_id=$3 AND worker_id=$4 AND generation=$5 AND state='Owned'", c, tx); object[] v = [state, lease.JobType, lease.JobId, lease.WorkerId, lease.Generation]; foreach (var x in v) q.Parameters.AddWithValue(x); var ok = await q.ExecuteNonQueryAsync(ct) == 1; if (ok) await Audit(c, tx, "lease.released", $"{lease.JobType}/{lease.JobId}", lease.WorkerId, lease.Generation, state, ct); await tx.CommitAsync(ct); return ok; }
    public async Task<bool> FenceAsync(WorkerLease lease, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM platform.worker_leases WHERE job_type=$1 AND job_id=$2 AND worker_id=$3 AND generation=$4 AND state='Owned' AND expires_at>now())", c); q.Parameters.AddWithValue(lease.JobType); q.Parameters.AddWithValue(lease.JobId); q.Parameters.AddWithValue(lease.WorkerId); q.Parameters.AddWithValue(lease.Generation); return (bool)(await q.ExecuteScalarAsync(ct) ?? false); }
    public async Task<IReadOnlyList<WorkerLease>> ListAsync(CancellationToken ct) { var x = new List<WorkerLease>(); await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT job_type,job_id,worker_id,generation,acquired_at,expires_at,heartbeat_at,state FROM platform.worker_leases ORDER BY job_type,job_id", c); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) x.Add(new(r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt64(3), r.GetFieldValue<DateTimeOffset>(4), r.GetFieldValue<DateTimeOffset>(5), r.GetFieldValue<DateTimeOffset>(6), r.GetString(7))); return x; }
    public async Task<IReadOnlyList<HaAuditEvent>> AuditAsync(int limit, CancellationToken ct) { var x = new List<HaAuditEvent>(); await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT audit_id,event_type,subject,actor,generation,occurred_at,detail FROM platform.ha_audit ORDER BY occurred_at DESC LIMIT $1", c); q.Parameters.AddWithValue(Math.Clamp(limit, 1, 1000)); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) x.Add(new(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.IsDBNull(4) ? null : r.GetInt64(4), r.GetFieldValue<DateTimeOffset>(5), r.GetString(6))); return x; }
    public async Task RecordAuditAsync(HaAuditEvent x, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("INSERT INTO platform.ha_audit(audit_id,event_type,subject,actor,generation,occurred_at,detail) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING", c); object?[] v = [x.AuditId, x.EventType, x.Subject, x.Actor, x.Generation, x.OccurredAt, x.Detail]; foreach (var a in v) q.Parameters.AddWithValue(a ?? DBNull.Value); await q.ExecuteNonQueryAsync(ct); }
    public async Task RegisterInstanceAsync(ServiceInstanceHealth x, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("INSERT INTO platform.service_instances(service_name,instance_id,region,version,started_at,heartbeat_at,live,ready,degraded_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(service_name,instance_id) DO UPDATE SET heartbeat_at=EXCLUDED.heartbeat_at,live=EXCLUDED.live,ready=EXCLUDED.ready,degraded_reason=EXCLUDED.degraded_reason", c); object?[] v = [x.ServiceName, x.InstanceId, x.Region, x.Version, x.StartedAt, x.HeartbeatAt, x.Live, x.Ready, x.DegradedReason]; foreach (var a in v) q.Parameters.AddWithValue(a ?? DBNull.Value); await q.ExecuteNonQueryAsync(ct); }
    public async Task<IReadOnlyList<ServiceInstanceHealth>> InstancesAsync(CancellationToken ct) { var x = new List<ServiceInstanceHealth>(); await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT service_name,instance_id,region,version,started_at,heartbeat_at,live AND heartbeat_at>now()-interval '30 seconds',ready AND heartbeat_at>now()-interval '30 seconds',degraded_reason FROM platform.service_instances ORDER BY service_name,instance_id", c); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) x.Add(new(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<DateTimeOffset>(4), r.GetFieldValue<DateTimeOffset>(5), r.GetBoolean(6), r.GetBoolean(7), r.IsDBNull(8) ? null : r.GetString(8))); return x; }
    public async Task<RecoveryStatus> RecoveryAsync(CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct);
        await using var q = new NpgsqlCommand("""
            SELECT b.backup_id,b.state,b.completed_at,b.size_bytes,b.sha256,
                   d.drill_id,d.state,d.completed_at,d.rto_seconds,d.table_count,d.difference_count,
                   (SELECT count(*) FROM platform.object_recovery_inventory),
                   (SELECT count(*) FROM platform.object_recovery_inventory WHERE state='Mismatch')
            FROM (SELECT * FROM platform.backup_runs ORDER BY started_at DESC LIMIT 1) b
            LEFT JOIN LATERAL (SELECT * FROM platform.dr_drills WHERE backup_id=b.backup_id ORDER BY started_at DESC LIMIT 1) d ON true
            """, c);
        await using var r = await q.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return new(null, null, null, null, null, null, null, null, null, null, null, 0, 0);
        return new(r.GetGuid(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetFieldValue<DateTimeOffset>(2), r.IsDBNull(3) ? null : r.GetInt64(3), r.IsDBNull(4) ? null : r.GetString(4), r.IsDBNull(5) ? null : r.GetGuid(5), r.IsDBNull(6) ? null : r.GetString(6), r.IsDBNull(7) ? null : r.GetFieldValue<DateTimeOffset>(7), r.IsDBNull(8) ? null : r.GetDecimal(8), r.IsDBNull(9) ? null : r.GetInt32(9), r.IsDBNull(10) ? null : r.GetInt32(10), r.GetInt64(11), r.GetInt64(12));
    }
    static WorkerLease Read(string t, string i, NpgsqlDataReader r) => new(t, i, r.GetString(0), r.GetInt64(1), r.GetFieldValue<DateTimeOffset>(2), r.GetFieldValue<DateTimeOffset>(3), r.GetFieldValue<DateTimeOffset>(4), r.GetString(5));
    static async Task Audit(NpgsqlConnection c, NpgsqlTransaction tx, string type, string subject, string actor, long generation, string detail, CancellationToken ct) { await using var q = new NpgsqlCommand("INSERT INTO platform.ha_audit(audit_id,event_type,subject,actor,generation,occurred_at,detail) VALUES($1,$2,$3,$4,$5,now(),$6)", c, tx); object[] v = [Guid.NewGuid(), type, subject, actor, generation, detail]; foreach (var x in v) q.Parameters.AddWithValue(x); await q.ExecuteNonQueryAsync(ct); }
    public async ValueTask DisposeAsync() { await data.DisposeAsync(); GC.SuppressFinalize(this); }
}

public sealed class PostgresArtifactTransferStateRepository : IArtifactTransferStateRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource data; static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public PostgresArtifactTransferStateRepository(string cs) => data = NpgsqlDataSource.Create(cs);
    public async Task<ArtifactTransferRecord?> GetAsync(Guid id, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT data::text FROM platform.artifact_transfers WHERE transfer_id=$1", c); q.Parameters.AddWithValue(id); return await q.ExecuteScalarAsync(ct) is string s ? JsonSerializer.Deserialize<ArtifactTransferRecord>(s, Json) : null; }
    public async Task<bool> CreateAsync(ArtifactTransferRecord x, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("INSERT INTO platform.artifact_transfers(tenant_id,transfer_id,endpoint_id,owner_id,state,version,updated_at,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT DO NOTHING", c); Add(q, x); return await q.ExecuteNonQueryAsync(ct) == 1; }
    public async Task<bool> CompareExchangeAsync(ArtifactTransferRecord x, long expected, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("UPDATE platform.artifact_transfers SET state=$1,version=$2,updated_at=$3,data=$4::jsonb WHERE tenant_id=$5 AND transfer_id=$6 AND version=$7", c); q.Parameters.AddWithValue(x.State.ToString()); q.Parameters.AddWithValue(x.Version); q.Parameters.AddWithValue(x.UpdatedAt); q.Parameters.AddWithValue(JsonSerializer.Serialize(x, Json)); q.Parameters.AddWithValue(Guid.Parse(x.TenantId)); q.Parameters.AddWithValue(x.Start.TransferId); q.Parameters.AddWithValue(expected); return await q.ExecuteNonQueryAsync(ct) == 1; }
    public async Task<int> CountActiveAsync(string t, Guid e, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT count(*) FROM platform.artifact_transfers WHERE tenant_id=$1 AND endpoint_id=$2 AND state IN ('Receiving','Verifying')", c); q.Parameters.AddWithValue(Guid.Parse(t)); q.Parameters.AddWithValue(e); return Convert.ToInt32(await q.ExecuteScalarAsync(ct), System.Globalization.CultureInfo.InvariantCulture); }
    public Task<IReadOnlyList<ArtifactTransferRecord>> ListOwnerAsync(string t, Guid o, CancellationToken ct) => ListWhere("tenant_id=$1 AND owner_id=$2", [Guid.Parse(t), o], ct);
    public Task<IReadOnlyList<ArtifactTransferRecord>> ListAsync(CancellationToken ct) => ListWhere("true", [], ct);
    async Task<IReadOnlyList<ArtifactTransferRecord>> ListWhere(string where, object[] args, CancellationToken ct) { var x = new List<ArtifactTransferRecord>(); await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand($"SELECT data::text FROM platform.artifact_transfers WHERE {where} ORDER BY updated_at", c); foreach (var a in args) q.Parameters.AddWithValue(a); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<ArtifactTransferRecord>(r.GetString(0), Json) is { } v) x.Add(v); return x; }
    static void Add(NpgsqlCommand q, ArtifactTransferRecord x) { object[] v = [Guid.Parse(x.TenantId), x.Start.TransferId, x.EndpointId, x.Start.OwnerId, x.State.ToString(), x.Version, x.UpdatedAt, JsonSerializer.Serialize(x, Json)]; foreach (var a in v) q.Parameters.AddWithValue(a); }
    public async ValueTask DisposeAsync() { await data.DisposeAsync(); GC.SuppressFinalize(this); }
}
