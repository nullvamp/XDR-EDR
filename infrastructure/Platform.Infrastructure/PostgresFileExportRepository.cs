using System.Data;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresFileExportRepository(string connectionString)
    : IFileExportRepository,
        IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly NpgsqlDataSource _data = NpgsqlDataSource.Create(connectionString);
    const string Columns =
        "id,tenant_id::text,created_by,state,format,query::text,fields,maximum_records,output_object_id,manifest_object_id,metadata_object_id,created_at,updated_at,expires_at,started_at,completed_at,record_count,output_size,output_sha256,error_code,error_summary";

    public async Task<FileExportJob> CreateAsync(
        string tenantId,
        string actor,
        FileExportCreateRequest request,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        await using (var cmd = new NpgsqlCommand(
            "INSERT INTO platform.file_export_jobs(tenant_id,id,created_by,state,format,query,fields,maximum_records,output_object_id,manifest_object_id,metadata_object_id,created_at,updated_at,expires_at) VALUES($1,$2,$3,'pending',$4,$5,$6,$7,$8,$9,$10,$11,$11,$12)", c, tx))
        {
            cmd.Parameters.AddWithValue(tenant);
            cmd.Parameters.AddWithValue(id);
            cmd.Parameters.AddWithValue(actor);
            cmd.Parameters.AddWithValue(request.Format);
            cmd.Parameters.Add(new NpgsqlParameter { Value = JsonSerializer.Serialize(request.Query with { Cursor = null }, Json), NpgsqlDbType = NpgsqlDbType.Jsonb });
            cmd.Parameters.AddWithValue(request.Fields ?? []);
            cmd.Parameters.AddWithValue(request.MaximumRecords);
            var output = Guid.NewGuid();
            var manifest = Guid.NewGuid();
            var metadata = Guid.NewGuid();
            cmd.Parameters.AddWithValue(output);
            cmd.Parameters.AddWithValue(manifest);
            cmd.Parameters.AddWithValue(metadata);
            cmd.Parameters.AddWithValue(now);
            cmd.Parameters.AddWithValue(now.AddMinutes(15));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await Audit(c, tx, tenant, actor, "file.export.create", id, ct);
        await tx.CommitAsync(ct);
        return (await GetAsync(tenantId, id, ct))!;
    }

    public async Task<FileExportJob?> GetAsync(string tenantId, Guid exportId, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand($"SELECT {Columns} FROM platform.file_export_jobs WHERE tenant_id=$1 AND id=$2", c);
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue(exportId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Read(r) : null;
    }

    public async Task<FileExportJob?> ClaimAsync(CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        await using var cmd = new NpgsqlCommand(
            $"WITH candidate AS (SELECT id FROM platform.file_export_jobs WHERE state='pending' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE platform.file_export_jobs j SET state='running',started_at=now(),updated_at=now() FROM candidate c WHERE j.id=c.id RETURNING {string.Join(',', Columns.Split(',').Select(x => "j." + x.Replace("tenant_id::text", "tenant_id::text")))}",
            c,
            tx
        );
        await using var r = await cmd.ExecuteReaderAsync(ct);
        var value = await r.ReadAsync(ct) ? Read(r) : null;
        await r.DisposeAsync();
        await tx.CommitAsync(ct);
        return value;
    }

    public async Task CompleteAsync(Guid id, int records, long size, string hash, DateTimeOffset at, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("UPDATE platform.file_export_jobs SET state='completed',record_count=$2,output_size=$3,output_sha256=$4,completed_at=$5,updated_at=$5 WHERE id=$1 AND state='running'", c);
        cmd.Parameters.AddWithValue(id);
        cmd.Parameters.AddWithValue(records);
        cmd.Parameters.AddWithValue(size);
        cmd.Parameters.AddWithValue(hash);
        cmd.Parameters.AddWithValue(at);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task FailAsync(Guid id, string code, string summary, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("UPDATE platform.file_export_jobs SET state='failed',error_code=$2,error_summary=$3,updated_at=now() WHERE id=$1 AND state IN('pending','running')", c);
        cmd.Parameters.AddWithValue(id);
        cmd.Parameters.AddWithValue(code);
        cmd.Parameters.AddWithValue(summary[..Math.Min(summary.Length, 512)]);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<FileExportJob>> ExpireDueAsync(CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand($"UPDATE platform.file_export_jobs SET state='expired',updated_at=now() WHERE state='completed' AND expires_at<=now() RETURNING {Columns}", c);
        var values = new List<FileExportJob>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            values.Add(Read(r));
        return values;
    }

    public async Task AuditDownloadAsync(string tenantId, Guid exportId, string actor, CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await Audit(c, null, Guid.Parse(tenantId), actor, "file.export.download", exportId, ct);
    }

    public async Task<IReadOnlyDictionary<string, int>> CountByStateAsync(CancellationToken ct)
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT state,count(*)::int FROM platform.file_export_jobs GROUP BY state", c);
        var values = new Dictionary<string, int>(StringComparer.Ordinal);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            values[r.GetString(0)] = r.GetInt32(1);
        return values;
    }

    static FileExportJob Read(NpgsqlDataReader r) =>
        new(
            r.GetGuid(0), r.GetString(1), r.GetString(2), Enum.Parse<FileExportState>(r.GetString(3), true),
            r.GetString(4), JsonSerializer.Deserialize<FileSearchRequest>(r.GetString(5), Json)!, r.GetFieldValue<string[]>(6),
            r.GetInt32(7), r.GetGuid(8), r.GetGuid(9), r.GetGuid(10), r.GetFieldValue<DateTimeOffset>(11),
            r.GetFieldValue<DateTimeOffset>(12), r.GetFieldValue<DateTimeOffset>(13),
            r.IsDBNull(14) ? null : r.GetFieldValue<DateTimeOffset>(14), r.IsDBNull(15) ? null : r.GetFieldValue<DateTimeOffset>(15),
            r.IsDBNull(16) ? null : r.GetInt32(16), r.IsDBNull(17) ? null : r.GetInt64(17),
            r.IsDBNull(18) ? null : r.GetString(18), r.IsDBNull(19) ? null : r.GetString(19), r.IsDBNull(20) ? null : r.GetString(20)
        );

    static async Task Audit(NpgsqlConnection c, NpgsqlTransaction? tx, Guid tenant, string actor, string action, Guid id, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("INSERT INTO platform.audit_events(id,tenant_id,occurred_at,actor,action,resource,decision,outcome,request_id,data) VALUES($1,$2,now(),jsonb_build_object('subject',$3),$4,jsonb_build_object('type','file-export','id',$5),'allow','success',$6,'{}'::jsonb)", c, tx);
        cmd.Parameters.AddWithValue(Guid.NewGuid());
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(actor);
        cmd.Parameters.AddWithValue(action);
        cmd.Parameters.AddWithValue(id.ToString("D"));
        cmd.Parameters.AddWithValue(Guid.NewGuid().ToString("N"));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public ValueTask DisposeAsync() => _data.DisposeAsync();
}
