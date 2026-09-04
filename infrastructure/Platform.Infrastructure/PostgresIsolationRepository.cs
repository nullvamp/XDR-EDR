using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresIsolationRepository : FileIsolationRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource _data;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public PostgresIsolationRepository(string connectionString, IResponseActionRepository actions) : base(actions) =>
        _data = NpgsqlDataSource.Create(connectionString);

    protected override async Task<EndpointIsolationPolicy?> LoadPolicyAsync(string tenant, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT policy_data::text FROM platform.endpoint_isolation_policies WHERE tenant_id=$1", c);
        cmd.Parameters.AddWithValue(Guid.Parse(tenant));
        return await cmd.ExecuteScalarAsync(ct) is string value ? JsonSerializer.Deserialize<EndpointIsolationPolicy>(value, Json) : null;
    }

    protected override async Task SavePolicyAsync(string tenant, EndpointIsolationPolicy value, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("INSERT INTO platform.endpoint_isolation_policies(tenant_id,policy_version,policy_data,updated_at) VALUES($1,$2,$3::jsonb,now()) ON CONFLICT(tenant_id) DO UPDATE SET policy_version=EXCLUDED.policy_version,policy_data=EXCLUDED.policy_data,updated_at=now()", c);
        cmd.Parameters.AddWithValue(Guid.Parse(tenant)); cmd.Parameters.AddWithValue(value.PolicyVersion); cmd.Parameters.AddWithValue(JsonSerializer.Serialize(value, Json));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    protected override async Task<EndpointIsolationSnapshot?> LoadSnapshotAsync(string tenant, Guid endpoint, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT state_data::text FROM platform.endpoint_isolation_state WHERE tenant_id=$1 AND endpoint_id=$2", c);
        cmd.Parameters.AddWithValue(Guid.Parse(tenant)); cmd.Parameters.AddWithValue(endpoint);
        return await cmd.ExecuteScalarAsync(ct) is string value ? JsonSerializer.Deserialize<EndpointIsolationSnapshot>(value, Json) : null;
    }

    protected override async Task SaveSnapshotAsync(EndpointIsolationSnapshot value, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("INSERT INTO platform.endpoint_isolation_state(tenant_id,endpoint_id,agent_installation_id,effective_state,policy_version,last_verified_at,state_data,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,now()) ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET agent_installation_id=EXCLUDED.agent_installation_id,effective_state=EXCLUDED.effective_state,policy_version=EXCLUDED.policy_version,last_verified_at=EXCLUDED.last_verified_at,state_data=EXCLUDED.state_data,updated_at=now()", c);
        object? verified = value.LastVerificationTime is { } x ? x : DBNull.Value;
        object[] parameters = [Guid.Parse(value.TenantId), value.EndpointId, value.AgentInstallationId, value.EffectiveState.ToString(), value.PolicyVersion, verified, JsonSerializer.Serialize(value, Json)];
        foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async ValueTask DisposeAsync() { await _data.DisposeAsync(); GC.SuppressFinalize(this); }
}
