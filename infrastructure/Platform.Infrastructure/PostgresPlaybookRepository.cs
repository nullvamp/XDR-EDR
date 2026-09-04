using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresPlaybookRepository : FilePlaybookRepository, IPlaybookWorkSource, IAsyncDisposable
{
    readonly NpgsqlDataSource data; static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public PostgresPlaybookRepository(string connectionString) => data = NpgsqlDataSource.Create(connectionString);
    protected override async Task<IReadOnlyList<PlaybookDefinition>> LoadDefinitionsAsync(string tenant, CancellationToken ct)
    {
        var values = new List<PlaybookDefinition>(); await using var c = await data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT definition_data::text FROM platform.playbook_definitions WHERE tenant_id=$1 ORDER BY updated_at DESC LIMIT 1000", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<PlaybookDefinition>(r.GetString(0), Json) is { } x) values.Add(x); return values;
    }
    protected override async Task<IReadOnlyList<PlaybookExecution>> LoadExecutionsAsync(string tenant, CancellationToken ct)
    {
        var values = new List<PlaybookExecution>(); await using var c = await data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT execution_data::text FROM platform.playbook_executions WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 10000", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<PlaybookExecution>(r.GetString(0), Json) is { } x) values.Add(x); return values;
    }
    protected override async Task<PlaybookFixtureResult[]> LoadTestsAsync(string tenant, Guid id, int version, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT fixture_data::text FROM platform.playbook_fixture_results WHERE tenant_id=$1 AND playbook_id=$2 AND playbook_version=$3 ORDER BY fixture_name", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); cmd.Parameters.AddWithValue(id); cmd.Parameters.AddWithValue(version); var values = new List<PlaybookFixtureResult>(); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<PlaybookFixtureResult>(r.GetString(0), Json) is { } x) values.Add(x); return values.ToArray();
    }
    protected override async Task PersistDefinitionAsync(PlaybookDefinition value, PlaybookFixtureResult[] results, string actor, string action, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.playbook_definitions(tenant_id,playbook_id,playbook_version,state,version_hash,definition_data,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8) ON CONFLICT(tenant_id,playbook_id,playbook_version) DO UPDATE SET state=EXCLUDED.state,definition_data=EXCLUDED.definition_data,updated_at=EXCLUDED.updated_at WHERE platform.playbook_definitions.version_hash=EXCLUDED.version_hash", c, tx)) { object[] p = [Guid.Parse(value.TenantId), value.PlaybookId, value.Version, value.State.ToString(), value.VersionHash, JsonSerializer.Serialize(value, Json), value.CreatedAt, value.UpdatedAt]; foreach (var x in p) cmd.Parameters.AddWithValue(x); if (await cmd.ExecuteNonQueryAsync(ct) != 1) throw new EnrollmentConflictException("PLAYBOOK_VERSION_TAMPER", "Immutable playbook version hash changed."); }
        foreach (var result in results) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.playbook_fixture_results(tenant_id,playbook_id,playbook_version,fixture_name,fixture_data) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(tenant_id,playbook_id,playbook_version,fixture_name) DO UPDATE SET fixture_data=EXCLUDED.fixture_data", c, tx); object[] p = [Guid.Parse(value.TenantId), value.PlaybookId, value.Version, result.Name, JsonSerializer.Serialize(result, Json)]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await using (var cmd = new NpgsqlCommand("INSERT INTO platform.playbook_audit(tenant_id,audit_id,playbook_id,playbook_version,action,actor,object_hash,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", c, tx)) { object[] p = [Guid.Parse(value.TenantId), Guid.NewGuid(), value.PlaybookId, value.Version, action, actor, value.VersionHash, action]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await tx.CommitAsync(ct);
    }
    protected override async Task PersistExecutionAsync(PlaybookExecution value, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.playbook_executions(tenant_id,execution_id,playbook_id,playbook_version,state,idempotency_key,endpoint_id,source_type,source_object_id,started_at,execution_data,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,now()) ON CONFLICT(tenant_id,execution_id) DO UPDATE SET state=EXCLUDED.state,execution_data=EXCLUDED.execution_data,updated_at=now()", c, tx)) { object[] p = [Guid.Parse(value.TenantId), value.ExecutionId, value.PlaybookId, value.PlaybookVersion, value.State.ToString(), value.IdempotencyKey, value.EndpointId, value.SourceType, value.SourceObjectId, value.StartedAt, JsonSerializer.Serialize(value, Json)]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await using (var work = new NpgsqlCommand("INSERT INTO platform.playbook_work(tenant_id,execution_id,state,attempts,available_at,updated_at) VALUES($1,$2,$3,0,now(),now()) ON CONFLICT(tenant_id,execution_id) DO UPDATE SET state=EXCLUDED.state,updated_at=now()", c, tx)) { work.Parameters.AddWithValue(Guid.Parse(value.TenantId)); work.Parameters.AddWithValue(value.ExecutionId); work.Parameters.AddWithValue(value.State is PlaybookExecutionState.Running or PlaybookExecutionState.Pending ? "pending" : "complete"); await work.ExecuteNonQueryAsync(ct); }
        foreach (var a in value.AuditHistory) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.playbook_execution_audit(tenant_id,audit_id,execution_id,step_id,action,actor,occurred_at,object_hash,reason,provenance) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING", c, tx); object[] p = [Guid.Parse(a.TenantId), a.AuditId, a.ExecutionId, (object?)a.StepId ?? DBNull.Value, a.Action, a.Actor, a.OccurredAt, a.ObjectHash, a.Reason, a.Provenance]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await tx.CommitAsync(ct);
    }
    public async Task<IReadOnlyList<PlaybookWorkItem>> ReadyAsync(CancellationToken ct)
    {
        var values = new List<PlaybookWorkItem>(); await using var c = await data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var select = new NpgsqlCommand("SELECT tenant_id,execution_id,attempts FROM platform.playbook_work WHERE state='pending' AND available_at<=now() ORDER BY available_at LIMIT 25 FOR UPDATE SKIP LOCKED", c, tx)) { await using var r = await select.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) values.Add(new(r.GetGuid(0).ToString("D"), r.GetGuid(1), r.GetInt32(2) + 1)); }
        foreach (var x in values) { await using var update = new NpgsqlCommand("UPDATE platform.playbook_work SET attempts=$3,state=CASE WHEN $3>=100 THEN 'dead-letter' ELSE state END,available_at=now()+interval '2 seconds',updated_at=now(),last_error=CASE WHEN $3>=100 THEN 'bounded orchestration polling exhausted' ELSE last_error END WHERE tenant_id=$1 AND execution_id=$2", c, tx); update.Parameters.AddWithValue(Guid.Parse(x.TenantId)); update.Parameters.AddWithValue(x.ExecutionId); update.Parameters.AddWithValue(x.Attempts); await update.ExecuteNonQueryAsync(ct); }
        await tx.CommitAsync(ct); return values.Where(x => x.Attempts < 100).ToArray();
    }
    public async ValueTask DisposeAsync() { await data.DisposeAsync(); Dispose(); GC.SuppressFinalize(this); }
}
