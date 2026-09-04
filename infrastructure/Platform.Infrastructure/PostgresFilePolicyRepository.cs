using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresFilePolicyRepository(string connectionString)
    : IFilePolicyRepository,
        IAsyncDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly NpgsqlDataSource _data = NpgsqlDataSource.Create(connectionString);

    public async Task<IReadOnlyList<FilePolicyVersion>> ListAsync(
        string tenantId,
        CancellationToken ct
    )
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id,tenant_id::text,name,version,policy::text,sha256,status,created_at,created_by FROM platform.file_policy_versions WHERE tenant_id=$1 ORDER BY name,version DESC",
            c
        );
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        var list = new List<FilePolicyVersion>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(Read(r));
        return list;
    }

    public async Task<FilePolicyVersion> CreateAsync(
        string tenantId,
        string actor,
        string name,
        FileTelemetryPolicy policy,
        CancellationToken ct
    )
    {
        if (FilePolicyValidation.Validate(policy).Count > 0)
            throw new EnrollmentConflictException(
                "FILE_POLICY_INVALID",
                "File policy validation failed."
            );
        var tenant = Guid.Parse(tenantId);
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        int version;
        await using (
            var q = new NpgsqlCommand(
                "SELECT COALESCE(max(version),0)+1 FROM platform.file_policy_versions WHERE tenant_id=$1 AND name=$2",
                c,
                tx
            )
        )
        {
            q.Parameters.AddWithValue(tenant);
            q.Parameters.AddWithValue(name);
            version = (int)(await q.ExecuteScalarAsync(ct) ?? 1);
        }
        var value = policy with { Version = $"file-policy.v{version}" };
        var json = JsonSerializer.Serialize(value, Json);
        var hash = Convert
            .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)))
            .ToLowerInvariant();
        var id = Guid.NewGuid();
        await using (
            var cmd = new NpgsqlCommand(
                "INSERT INTO platform.file_policy_versions(id,tenant_id,name,version,policy,sha256,status,created_by) VALUES($1,$2,$3,$4,$5,$6,'active',$7)",
                c,
                tx
            )
        )
        {
            cmd.Parameters.AddWithValue(id);
            cmd.Parameters.AddWithValue(tenant);
            cmd.Parameters.AddWithValue(name);
            cmd.Parameters.AddWithValue(version);
            cmd.Parameters.Add(
                new NpgsqlParameter { Value = json, NpgsqlDbType = NpgsqlDbType.Jsonb }
            );
            cmd.Parameters.AddWithValue(hash);
            cmd.Parameters.AddWithValue(actor);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await Audit(
            c,
            tx,
            tenant,
            actor,
            "file.policy.version.create",
            id,
            null,
            hash,
            ct
        );
        await tx.CommitAsync(ct);
        return new(
            id,
            tenantId,
            name,
            version,
            value,
            hash,
            "active",
            DateTimeOffset.UtcNow,
            actor
        );
    }

    public async Task AssignAsync(
        string tenantId,
        Guid policyId,
        Guid? endpointId,
        string actor,
        CancellationToken ct
    )
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.file_policy_assignments(tenant_id,endpoint_id,policy_id,assigned_by) SELECT $1,$2,id,$3 FROM platform.file_policy_versions WHERE tenant_id=$1 AND id=$4 ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET policy_id=EXCLUDED.policy_id,assigned_at=now(),assigned_by=EXCLUDED.assigned_by",
            c
        );
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue((object?)endpointId ?? DBNull.Value);
        cmd.Parameters.AddWithValue(actor);
        cmd.Parameters.AddWithValue(policyId);
        if (await cmd.ExecuteNonQueryAsync(ct) == 0)
            throw new EnrollmentConflictException(
                "FILE_POLICY_NOT_FOUND",
                "File policy was not found."
            );
        await Audit(
            c,
            null,
            Guid.Parse(tenantId),
            actor,
            "file.policy.assign",
            policyId,
            null,
            endpointId?.ToString(),
            ct
        );
    }

    public async Task<EffectiveFilePolicy> EffectiveAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        const string sql =
            "SELECT v.id,v.tenant_id::text,v.name,v.version,v.policy::text,v.sha256,v.status,v.created_at,v.created_by,a.endpoint_id,k.policy_id,k.acknowledged_at,k.version,k.applied,k.validation_error FROM platform.file_policy_assignments a JOIN platform.file_policy_versions v ON v.tenant_id=a.tenant_id AND v.id=a.policy_id LEFT JOIN platform.file_policy_acknowledgements k ON k.tenant_id=a.tenant_id AND k.endpoint_id=$2 WHERE a.tenant_id=$1 AND (a.endpoint_id=$2 OR a.endpoint_id IS NULL) ORDER BY a.endpoint_id NULLS LAST LIMIT 1";
        await using var cmd = new NpgsqlCommand(sql, c);
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue(endpointId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (await r.ReadAsync(ct))
        {
            var v = new FilePolicyVersion(
                r.GetGuid(0),
                r.GetString(1),
                r.GetString(2),
                r.GetInt32(3),
                JsonSerializer.Deserialize<FileTelemetryPolicy>(r.GetString(4), Json)!,
                r.GetString(5),
                r.GetString(6),
                r.GetFieldValue<DateTimeOffset>(7),
                r.GetString(8)
            );
            var assigned = !r.IsDBNull(9);
            var ackMatchesPolicy = !r.IsDBNull(10) && r.GetGuid(10) == v.Id;
            DateTimeOffset? ackAt =
                !ackMatchesPolicy || r.IsDBNull(11) ? null : r.GetFieldValue<DateTimeOffset>(11);
            int? ackVersion = !ackMatchesPolicy || r.IsDBNull(12) ? null : r.GetInt32(12);
            var applied = ackMatchesPolicy && !r.IsDBNull(13) && r.GetBoolean(13);
            return new(
                v,
                assigned ? "endpoint" : "tenant-default",
                endpointId,
                ackAt,
                applied ? ackVersion : null,
                !applied ? ackVersion : null,
                !ackMatchesPolicy || r.IsDBNull(14) ? null : r.GetString(14),
                !ackMatchesPolicy || !applied || ackVersion != v.Version
            );
        }
        var fallback = new FilePolicyVersion(
            Guid.Empty,
            tenantId,
            "safe-default",
            1,
            new(
                ExcludedPaths:
                    ["/proc/", "/sys/", "/dev/", "/run/", "/var/log/", "/var/lib/docker/overlay2/"]
            ),
            new string('0', 64),
            "implicit",
            DateTimeOffset.UnixEpoch,
            "system"
        );
        return new(fallback, "implicit-default", endpointId, null, null, null, null, true);
    }

    public async Task AcknowledgeAsync(
        string tenantId,
        Guid endpointId,
        FilePolicyAcknowledgement a,
        CancellationToken ct
    )
    {
        await using var c = await _data.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.file_policy_acknowledgements(tenant_id,endpoint_id,policy_id,version,applied,validation_error,acknowledged_at) SELECT $1,$2,id,$4,$5,$6,$7 FROM platform.file_policy_versions WHERE tenant_id=$1 AND id=$3 ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET policy_id=EXCLUDED.policy_id,version=EXCLUDED.version,applied=EXCLUDED.applied,validation_error=EXCLUDED.validation_error,acknowledged_at=EXCLUDED.acknowledged_at",
            c
        );
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue(endpointId);
        cmd.Parameters.AddWithValue(a.PolicyId);
        cmd.Parameters.AddWithValue(a.Version);
        cmd.Parameters.AddWithValue(a.Applied);
        cmd.Parameters.AddWithValue((object?)a.ValidationError ?? DBNull.Value);
        cmd.Parameters.AddWithValue(a.AcknowledgedAt);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<FilePolicyVersion> RollbackAsync(
        string tenantId,
        Guid policyId,
        int version,
        string actor,
        CancellationToken ct
    )
    {
        var source =
            (await ListAsync(tenantId, ct)).SingleOrDefault(x =>
                x.Id == policyId && x.Version == version
            )
            ?? throw new EnrollmentConflictException(
                "FILE_POLICY_NOT_FOUND",
                "Rollback version was not found."
            );
        return await CreateAsync(tenantId, actor, source.Name, source.Policy, ct);
    }

    static FilePolicyVersion Read(NpgsqlDataReader r) =>
        new(
            r.GetGuid(0),
            r.GetString(1),
            r.GetString(2),
            r.GetInt32(3),
            JsonSerializer.Deserialize<FileTelemetryPolicy>(r.GetString(4), Json)!,
            r.GetString(5),
            r.GetString(6),
            r.GetFieldValue<DateTimeOffset>(7),
            r.GetString(8)
        );

    static async Task Audit(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        Guid tenant,
        string actor,
        string action,
        Guid resourceId,
        string? beforeHash,
        string? afterHash,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.audit_events(id,tenant_id,occurred_at,actor,action,resource,decision,outcome,request_id,before_hash,after_hash,data) VALUES($1,$2,now(),jsonb_build_object('subject',$3),$4,jsonb_build_object('type','file-policy','id',$5),'allow','success',$6,$7,$8,'{}'::jsonb)",
            connection,
            transaction
        );
        cmd.Parameters.AddWithValue(Guid.NewGuid());
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(actor);
        cmd.Parameters.AddWithValue(action);
        cmd.Parameters.AddWithValue(resourceId.ToString("D"));
        cmd.Parameters.AddWithValue(Guid.NewGuid().ToString("N"));
        cmd.Parameters.AddWithValue((object?)beforeHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)afterHash ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public ValueTask DisposeAsync() => _data.DisposeAsync();
}
