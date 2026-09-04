using System.Globalization;
using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresAgentProtectionRepository : FileAgentProtectionRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource data; static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public PostgresAgentProtectionRepository(string connectionString) => data = NpgsqlDataSource.Create(connectionString);
    protected override async Task<IReadOnlyList<AgentProtectionPolicy>> LoadPoliciesAsync(string tenant, CancellationToken ct) => await Load<AgentProtectionPolicy>("SELECT policy_data::text FROM platform.agent_protection_policies WHERE tenant_id=$1 ORDER BY policy_version DESC LIMIT 1000", tenant, ct);
    protected override async Task<IReadOnlyList<ProtectionSnapshot>> LoadSnapshotsAsync(string tenant, CancellationToken ct) => await Load<ProtectionSnapshot>("SELECT snapshot_data::text FROM platform.agent_protection_snapshots WHERE tenant_id=$1 ORDER BY verified_at DESC LIMIT 10000", tenant, ct);
    protected override async Task<IReadOnlyList<TamperEvent>> LoadEventsAsync(string tenant, CancellationToken ct) => await Load<TamperEvent>("SELECT event_data::text FROM platform.agent_tamper_events WHERE tenant_id=$1 ORDER BY occurred_at DESC LIMIT 10000", tenant, ct);
    protected override async Task<IReadOnlyList<MaintenanceAuthorization>> LoadMaintenanceAsync(string tenant, CancellationToken ct) => await Load<MaintenanceAuthorization>("SELECT authorization_data::text FROM platform.agent_maintenance_authorizations WHERE tenant_id=$1 ORDER BY starts_at DESC LIMIT 10000", tenant, ct);
    protected override async Task<IReadOnlyList<RepairRecord>> LoadRepairsAsync(string tenant, CancellationToken ct) => await Load<RepairRecord>("SELECT repair_data::text FROM platform.agent_protection_repairs WHERE tenant_id=$1 ORDER BY requested_at DESC LIMIT 10000", tenant, ct);
    async Task<IReadOnlyList<T>> Load<T>(string sql, string tenant, CancellationToken ct)
    {
        var values = new List<T>(); await using var c = await data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand(sql, c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<T>(r.GetString(0), Json) is { } x) values.Add(x); return values;
    }
    protected override async Task PersistPolicyAsync(AgentProtectionPolicy p, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.agent_protection_policies(tenant_id,endpoint_id,policy_version,installation_id,policy_hash,policy_data,created_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT DO NOTHING", c, tx)) { object[] values = [Guid.Parse(p.TenantId), p.EndpointId, p.Version, p.InstallationId, p.PolicyHash, JsonSerializer.Serialize(p, Json), p.CreatedAt]; foreach (var x in values) cmd.Parameters.AddWithValue(x); if (await cmd.ExecuteNonQueryAsync(ct) != 1) throw new EnrollmentConflictException("PROTECTION_POLICY_IMMUTABLE", "Protection policy version already exists."); }
        await Audit(c, tx, p.TenantId, p.EndpointId, "policy", p.Version.ToString(CultureInfo.InvariantCulture), "protection.policy.created", p.Author, p.PolicyHash, "immutable version", ct); await tx.CommitAsync(ct);
    }
    protected override async Task PersistReportAsync(ProtectionSnapshot s, TamperEvent[] events, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.agent_protection_snapshots(tenant_id,endpoint_id,installation_id,policy_version,state,verified_at,snapshot_hash,snapshot_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET installation_id=EXCLUDED.installation_id,policy_version=EXCLUDED.policy_version,state=EXCLUDED.state,verified_at=EXCLUDED.verified_at,snapshot_hash=EXCLUDED.snapshot_hash,snapshot_data=EXCLUDED.snapshot_data WHERE platform.agent_protection_snapshots.verified_at<=EXCLUDED.verified_at", c, tx)) { object[] values = [Guid.Parse(s.TenantId), s.EndpointId, s.InstallationId, s.PolicyVersion, s.State.ToString(), s.VerifiedAt, s.SnapshotHash, JsonSerializer.Serialize(s, Json)]; foreach (var x in values) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        foreach (var e in events) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.agent_tamper_events(tenant_id,event_id,endpoint_id,installation_id,event_type,resource_id,occurred_at,event_hash,event_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT DO NOTHING", c, tx); object[] values = [Guid.Parse(e.TenantId), e.EventId, e.EndpointId, e.InstallationId, e.EventType, e.ResourceId, e.OccurredAt, e.EventHash, JsonSerializer.Serialize(e, Json)]; foreach (var x in values) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); await Audit(c, tx, e.TenantId, e.EndpointId, "tamper-event", e.EventId.ToString("D"), e.EventType, "agent", e.EventHash, e.Prevention.ToString(), ct); }
        await tx.CommitAsync(ct);
    }
    protected override async Task PersistMaintenanceAsync(MaintenanceAuthorization value, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.agent_maintenance_authorizations(tenant_id,maintenance_id,endpoint_id,installation_id,state,request_hash,starts_at,expires_at,authorization_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT(tenant_id,maintenance_id) DO UPDATE SET state=EXCLUDED.state,authorization_data=EXCLUDED.authorization_data", c, tx)) { object[] values = [Guid.Parse(value.TenantId), value.MaintenanceId, value.EndpointId, value.InstallationId, value.State.ToString(), value.RequestHash, value.StartsAt, value.ExpiresAt, JsonSerializer.Serialize(value, Json)]; foreach (var x in values) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await Audit(c, tx, value.TenantId, value.EndpointId, "maintenance", value.MaintenanceId.ToString("D"), $"maintenance.{value.State.ToString().ToLowerInvariant()}", value.Approver ?? value.Requester, value.RequestHash, value.Reason, ct); await tx.CommitAsync(ct);
    }
    protected override async Task PersistRepairAsync(RepairRecord value, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.agent_protection_repairs(tenant_id,repair_id,endpoint_id,installation_id,resource_id,state,requested_at,repair_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(tenant_id,repair_id) DO UPDATE SET state=EXCLUDED.state,repair_data=EXCLUDED.repair_data", c, tx)) { object[] values = [Guid.Parse(value.TenantId), value.RepairId, value.EndpointId, value.InstallationId, value.ResourceId, value.State.ToString(), value.RequestedAt, JsonSerializer.Serialize(value, Json)]; foreach (var x in values) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await Audit(c, tx, value.TenantId, value.EndpointId, "repair", value.RepairId.ToString("D"), "protection.repair.requested", value.Requester, value.AuditHash, value.Reason, ct); await tx.CommitAsync(ct);
    }
    static async Task Audit(NpgsqlConnection c, NpgsqlTransaction tx, string tenant, Guid endpoint, string type, string id, string action, string actor, string hash, string reason, CancellationToken ct) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.agent_protection_audit(tenant_id,audit_id,endpoint_id,object_type,object_id,action,actor,object_hash,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", c, tx); object[] values = [Guid.Parse(tenant), Guid.NewGuid(), endpoint, type, id, action, actor, hash, reason]; foreach (var x in values) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
    public async ValueTask DisposeAsync() { await data.DisposeAsync(); Dispose(); GC.SuppressFinalize(this); }
}
