using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresForensicWorkspaceStore : IForensicWorkspaceStore, IAsyncDisposable
{
    readonly NpgsqlDataSource data; static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public PostgresForensicWorkspaceStore(string connection) => data = NpgsqlDataSource.Create(connection);
    public async Task<ForensicWorkspaceState> LoadAsync(string tenant, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT revision,state_data::text FROM platform.forensic_workspace_states WHERE tenant_id=$1", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await q.ExecuteReaderAsync(ct); return await r.ReadAsync(ct) ? JsonSerializer.Deserialize<ForensicWorkspaceState>(r.GetString(1), Json)! with { Revision = r.GetInt64(0) } : new(0, [], [], [], [], [], [], [], [], []);
    }
    public async Task SaveAsync(string tenant, long expected, ForensicWorkspaceState state, CancellationToken ct)
    {
        await using var c = await data.OpenConnectionAsync(ct); int changed; var json = JsonSerializer.Serialize(state with { Revision = expected + 1 }, Json);
        if (expected == 0) { await using var q = new NpgsqlCommand("INSERT INTO platform.forensic_workspace_states(tenant_id,revision,state_data,updated_at) VALUES($1,1,$2::jsonb,now()) ON CONFLICT DO NOTHING", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue(json); changed = await q.ExecuteNonQueryAsync(ct); }
        else { await using var q = new NpgsqlCommand("UPDATE platform.forensic_workspace_states SET revision=$3,state_data=$4::jsonb,updated_at=now() WHERE tenant_id=$1 AND revision=$2", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue(expected); q.Parameters.AddWithValue(expected + 1); q.Parameters.AddWithValue(json); changed = await q.ExecuteNonQueryAsync(ct); }
        if (changed != 1) throw new EnrollmentConflictException("FORENSIC_WORKSPACE_STALE", "Workspace changed; reload and retry.");
    }
    public ValueTask DisposeAsync() => data.DisposeAsync();
}
