using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresResponseActionRepository : FileResponseActionRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource _data; static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public PostgresResponseActionRepository(string connectionString) => _data = NpgsqlDataSource.Create(connectionString);
    public override async Task<ResponseTarget?> ResolveTargetAsync(string tenant, Guid endpoint, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT e.id,a.id,a.instance_id,e.os_type,coalesce(e.agent_version,''),e.status FROM platform.endpoints e JOIN platform.agents a ON a.tenant_id=e.tenant_id AND a.endpoint_id=e.id WHERE e.tenant_id=$1 AND e.id=$2 AND e.deleted_at IS NULL ORDER BY a.last_checkin DESC NULLS LAST LIMIT 1", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); cmd.Parameters.AddWithValue(endpoint); await using var r = await cmd.ExecuteReaderAsync(ct); if (!await r.ReadAsync(ct)) return null; return new(r.GetGuid(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetString(4), Enum.TryParse<EndpointStatus>(r.GetString(5), true, out var status) ? status : EndpointStatus.Unknown);
    }
    protected override async Task<IReadOnlyList<ResponseActionRecord>> LoadAsync(string tenant, CancellationToken ct)
    {
        var values = new List<ResponseActionRecord>(); await using var c = await _data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT action_data::text FROM platform.response_actions WHERE tenant_id=$1 ORDER BY requested_at DESC,response_action_id LIMIT 20000", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<ResponseActionRecord>(r.GetString(0), Json) is { } x) values.Add(x); return values;
    }
    protected override async Task<IReadOnlyList<ResponseActionRecord>> LoadAllAsync(CancellationToken ct)
    {
        var values = new List<ResponseActionRecord>(); await using var c = await _data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT action_data::text FROM platform.response_actions ORDER BY requested_at DESC LIMIT 50000", c); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<ResponseActionRecord>(r.GetString(0), Json) is { } x) values.Add(x); return values;
    }
    protected override async Task PersistAsync(ResponseActionRecord value, IReadOnlyList<ResponseAuditEvent> audit, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.response_actions(tenant_id,response_action_id,endpoint_id,agent_id,agent_installation_id,action_type,action_version,analyst_id,state,approval_state,parameter_hash,nonce,requested_at,expires_at,action_revision,action_data,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,now()) ON CONFLICT(tenant_id,response_action_id) DO UPDATE SET state=EXCLUDED.state,approval_state=EXCLUDED.approval_state,action_revision=EXCLUDED.action_revision,action_data=EXCLUDED.action_data,updated_at=now()", c, tx)) { object[] p = [Guid.Parse(value.TenantId), value.ResponseActionId, value.EndpointId, value.AgentId, value.AgentInstallationId, value.ActionType, value.ActionVersion, value.AnalystId, value.State.ToString(), value.ApprovalState.ToString(), value.ParameterHash, value.Nonce, value.RequestedAt, value.ExpiresAt, value.Version, JsonSerializer.Serialize(value, Json)]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        foreach (var a in audit) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.response_action_audit(tenant_id,audit_id,response_action_id,object_version,action,actor,occurred_at,parameter_hash,reason,before_data,after_data,provenance) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12) ON CONFLICT DO NOTHING", c, tx); object[] p = [Guid.Parse(a.TenantId), a.AuditId, a.ActionId, a.ObjectVersion, a.Action, a.Actor, a.OccurredAt, a.ParameterHash, a.Reason, JsonSerializer.Serialize(a.Before, Json), JsonSerializer.Serialize(a.After, Json), a.Provenance]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        foreach (var artifact in value.Result?.Artifacts ?? []) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.response_artifacts(tenant_id,artifact_id,response_action_id,object_id,manifest_object_id,name,media_type,size_bytes,sha256,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING", c, tx); object[] p = [Guid.Parse(value.TenantId), artifact.ArtifactId, value.ResponseActionId, artifact.ObjectId, artifact.ManifestObjectId, artifact.Name, artifact.MediaType, artifact.Size, artifact.Sha256, artifact.CreatedAt, artifact.ExpiresAt]; foreach (var x in p) cmd.Parameters.AddWithValue(x); await cmd.ExecuteNonQueryAsync(ct); }
        await tx.CommitAsync(ct);
    }
    public override async Task<IReadOnlyList<ExpiredResponseArtifact>> ListExpiredArtifactsAsync(CancellationToken ct)
    {
        var values = new List<ExpiredResponseArtifact>(); await using var c = await _data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("SELECT tenant_id,response_action_id,artifact_id,name,media_type,size_bytes,sha256,object_id,manifest_object_id,created_at,expires_at FROM platform.response_artifacts WHERE expires_at<=now() AND cleaned_at IS NULL ORDER BY expires_at LIMIT 100", c); await using var r = await cmd.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) values.Add(new(r.GetGuid(0).ToString("D"), r.GetGuid(1), new(r.GetGuid(2), r.GetString(3), r.GetString(4), r.GetInt64(5), r.GetString(6), r.GetString(7), r.GetGuid(8), r.GetFieldValue<DateTimeOffset>(9), r.GetFieldValue<DateTimeOffset>(10)))); return values;
    }
    public override async Task MarkArtifactCleanedAsync(string tenant, Guid artifactId, CancellationToken ct) { await using var c = await _data.OpenConnectionAsync(ct); await using var cmd = new NpgsqlCommand("UPDATE platform.response_artifacts SET cleaned_at=now() WHERE tenant_id=$1 AND artifact_id=$2 AND cleaned_at IS NULL", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); cmd.Parameters.AddWithValue(artifactId); await cmd.ExecuteNonQueryAsync(ct); }
    public async ValueTask DisposeAsync() { await _data.DisposeAsync(); Dispose(); GC.SuppressFinalize(this); }
}
