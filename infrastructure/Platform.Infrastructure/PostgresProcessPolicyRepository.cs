using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresProcessPolicyRepository(string connectionString)
    : IProcessPolicyRepository,
        IAsyncDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly NpgsqlDataSource _source = NpgsqlDataSource.Create(connectionString);

    public async Task<IReadOnlyList<ProcessPolicyVersion>> ListAsync(
        string tenantId,
        CancellationToken ct
    )
    {
        var values = new List<ProcessPolicyVersion>();
        await using var connection = await _source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT id,name,version,content::text,content_hash,status,created_at,created_by FROM platform.process_policy_versions WHERE tenant_id=$1 ORDER BY name,version DESC",
            connection
        );
        command.Parameters.AddWithValue(Guid.Parse(tenantId));
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            values.Add(
                new(
                    reader.GetGuid(0),
                    tenantId,
                    reader.GetString(1),
                    reader.GetInt32(2),
                    JsonSerializer.Deserialize<ProcessTelemetryPolicy>(reader.GetString(3), Json)!,
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetFieldValue<DateTimeOffset>(6),
                    reader.GetString(7)
                )
            );
        return values;
    }

    public async Task<ProcessPolicyVersion> CreateAsync(
        string tenantId,
        string actor,
        string name,
        ProcessTelemetryPolicy policy,
        CancellationToken ct
    )
    {
        var errors = ProcessPolicyValidation.Validate(policy);
        if (errors.Count != 0)
            throw new EnrollmentConflictException(
                "PROCESS_POLICY_INVALID",
                JsonSerializer.Serialize(errors, Json)
            );
        var tenant = Guid.Parse(tenantId);
        await using var connection = await _source.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        int version;
        await using (
            var next = new NpgsqlCommand(
                "SELECT coalesce(max(version),0)+1 FROM platform.process_policy_versions WHERE tenant_id=$1 AND name=$2",
                connection,
                tx
            )
        )
        {
            next.Parameters.AddWithValue(tenant);
            next.Parameters.AddWithValue(name);
            version = Convert.ToInt32(
                await next.ExecuteScalarAsync(ct),
                System.Globalization.CultureInfo.InvariantCulture
            );
        }
        var normalized = policy with { Version = $"process-policy.v{version}" };
        var content = JsonSerializer.Serialize(normalized, Json);
        var hash = Convert
            .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)))
            .ToLowerInvariant();
        var id = Guid.NewGuid();
        await using (
            var supersede = new NpgsqlCommand(
                "UPDATE platform.process_policy_versions SET status='superseded' WHERE tenant_id=$1 AND name=$2 AND status='active'",
                connection,
                tx
            )
        )
        {
            supersede.Parameters.AddWithValue(tenant);
            supersede.Parameters.AddWithValue(name);
            await supersede.ExecuteNonQueryAsync(ct);
        }
        await using (
            var insert = new NpgsqlCommand(
                "INSERT INTO platform.process_policy_versions(tenant_id,id,name,version,content,content_hash,status,created_by) VALUES($1,$2,$3,$4,$5::jsonb,$6,'active',$7)",
                connection,
                tx
            )
        )
        {
            insert.Parameters.AddWithValue(tenant);
            insert.Parameters.AddWithValue(id);
            insert.Parameters.AddWithValue(name);
            insert.Parameters.AddWithValue(version);
            insert.Parameters.AddWithValue(content);
            insert.Parameters.AddWithValue(hash);
            insert.Parameters.AddWithValue(actor);
            await insert.ExecuteNonQueryAsync(ct);
        }
        await Audit(
            connection,
            tx,
            tenant,
            actor,
            "created",
            id,
            null,
            new
            {
                name,
                version,
                hash,
            },
            ct
        );
        await tx.CommitAsync(ct);
        return new(
            id,
            tenantId,
            name,
            version,
            normalized,
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
        var tenant = Guid.Parse(tenantId);
        await using var connection = await _source.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        await using (
            var verify = new NpgsqlCommand(
                "SELECT EXISTS(SELECT 1 FROM platform.process_policy_versions WHERE tenant_id=$1 AND id=$2 AND status='active') AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM platform.endpoints WHERE tenant_id=$1 AND id=$3))",
                connection,
                tx
            )
        )
        {
            verify.Parameters.AddWithValue(tenant);
            verify.Parameters.AddWithValue(policyId);
            verify.Parameters.AddWithValue((object?)endpointId ?? DBNull.Value);
            if (!(bool)(await verify.ExecuteScalarAsync(ct) ?? false))
                throw new EnrollmentConflictException(
                    "PROCESS_POLICY_ASSIGNMENT_INVALID",
                    "Policy or endpoint does not belong to the tenant."
                );
        }
        var deleteSql = endpointId is null
            ? "DELETE FROM platform.process_policy_assignments WHERE tenant_id=$1 AND endpoint_id IS NULL"
            : "DELETE FROM platform.process_policy_assignments WHERE tenant_id=$1 AND endpoint_id=$2";
        await using (var delete = new NpgsqlCommand(deleteSql, connection, tx))
        {
            delete.Parameters.AddWithValue(tenant);
            if (endpointId is not null)
                delete.Parameters.AddWithValue(endpointId.Value);
            await delete.ExecuteNonQueryAsync(ct);
        }
        await using (
            var assign = new NpgsqlCommand(
                "INSERT INTO platform.process_policy_assignments(tenant_id,policy_id,endpoint_id,assigned_by) VALUES($1,$2,$3,$4)",
                connection,
                tx
            )
        )
        {
            assign.Parameters.AddWithValue(tenant);
            assign.Parameters.AddWithValue(policyId);
            assign.Parameters.AddWithValue((object?)endpointId ?? DBNull.Value);
            assign.Parameters.AddWithValue(actor);
            await assign.ExecuteNonQueryAsync(ct);
        }
        await Audit(
            connection,
            tx,
            tenant,
            actor,
            "assigned",
            policyId,
            endpointId,
            new { scope = endpointId is null ? "tenant" : "endpoint" },
            ct
        );
        await tx.CommitAsync(ct);
    }

    public async Task<EffectiveProcessPolicy> EffectiveAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        await using var connection = await _source.OpenConnectionAsync(ct);
        const string sql =
            "SELECT p.id,p.name,p.version,p.content::text,p.content_hash,p.status,p.created_at,p.created_by,a.endpoint_id IS NOT NULL,k.acknowledged_at,k.version,k.applied,k.validation_error,k.policy_id FROM platform.process_policy_assignments a JOIN platform.process_policy_versions p ON p.tenant_id=a.tenant_id AND p.id=a.policy_id LEFT JOIN platform.process_policy_acknowledgements k ON k.tenant_id=a.tenant_id AND k.endpoint_id=$2 WHERE a.tenant_id=$1 AND (a.endpoint_id=$2 OR a.endpoint_id IS NULL) ORDER BY a.endpoint_id NULLS LAST LIMIT 1";
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(endpointId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            var policy = new ProcessTelemetryPolicy();
            return new(
                new(
                    Guid.Empty,
                    tenantId,
                    "safe-default",
                    1,
                    policy,
                    Hash(policy),
                    "implicit",
                    DateTimeOffset.UnixEpoch,
                    "system"
                ),
                "implicit-default",
                endpointId,
                null,
                null,
                null,
                null,
                true
            );
        }
        var value = new ProcessPolicyVersion(
            reader.GetGuid(0),
            tenantId,
            reader.GetString(1),
            reader.GetInt32(2),
            JsonSerializer.Deserialize<ProcessTelemetryPolicy>(reader.GetString(3), Json)!,
            reader.GetString(4),
            reader.GetString(5),
            reader.GetFieldValue<DateTimeOffset>(6),
            reader.GetString(7)
        );
        var acknowledged = reader.IsDBNull(9)
            ? (DateTimeOffset?)null
            : reader.GetFieldValue<DateTimeOffset>(9);
        var ackVersion = reader.IsDBNull(10) ? (int?)null : reader.GetInt32(10);
        var applied = !reader.IsDBNull(11) && reader.GetBoolean(11);
        var acknowledgedPolicy = reader.IsDBNull(13) ? (Guid?)null : reader.GetGuid(13);
        var currentAcknowledgement = acknowledgedPolicy == value.Id;
        return new(
            value,
            reader.GetBoolean(8) ? "endpoint" : "tenant-default",
            endpointId,
            acknowledged,
            currentAcknowledgement && applied ? ackVersion : null,
            currentAcknowledgement && acknowledged is not null && !applied ? ackVersion : null,
            reader.IsDBNull(12) ? null : reader.GetString(12),
            !currentAcknowledgement || !applied || ackVersion != value.Version
        );
    }

    public async Task AcknowledgeAsync(
        string tenantId,
        Guid endpointId,
        ProcessPolicyAcknowledgement ack,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        await using var connection = await _source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "INSERT INTO platform.process_policy_acknowledgements(tenant_id,endpoint_id,policy_id,version,applied,validation_error,acknowledged_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET policy_id=EXCLUDED.policy_id,version=EXCLUDED.version,applied=EXCLUDED.applied,validation_error=EXCLUDED.validation_error,acknowledged_at=EXCLUDED.acknowledged_at",
            connection
        );
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(endpointId);
        command.Parameters.AddWithValue(ack.PolicyId);
        command.Parameters.AddWithValue(ack.Version);
        command.Parameters.AddWithValue(ack.Applied);
        command.Parameters.AddWithValue((object?)ack.ValidationError ?? DBNull.Value);
        command.Parameters.AddWithValue(ack.AcknowledgedAt);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<ProcessPolicyVersion> RollbackAsync(
        string tenantId,
        Guid policyId,
        int version,
        string actor,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        await using var connection = await _source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT name,content::text FROM platform.process_policy_versions WHERE tenant_id=$1 AND id=$2 AND version=$3",
            connection
        );
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(policyId);
        command.Parameters.AddWithValue(version);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            throw new EnrollmentConflictException(
                "PROCESS_POLICY_ROLLBACK_INVALID",
                "Rollback target does not exist in the tenant."
            );
        var name = reader.GetString(0);
        var policy = JsonSerializer.Deserialize<ProcessTelemetryPolicy>(reader.GetString(1), Json)!;
        await reader.DisposeAsync();
        return await CreateAsync(tenantId, actor, name, policy, ct);
    }

    public async Task<IReadOnlyList<ProcessExclusionMetric>> ExclusionMetricsAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        var values = new List<ProcessExclusionMetric>();
        await using var connection = await _source.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT rule_id,category,events_excluded,last_match_at FROM platform.process_exclusion_metrics WHERE tenant_id=$1 AND endpoint_id=$2 ORDER BY rule_id",
            connection
        );
        command.Parameters.AddWithValue(Guid.Parse(tenantId));
        command.Parameters.AddWithValue(endpointId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            values.Add(
                new(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.GetInt64(2),
                    reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3)
                )
            );
        return values;
    }

    private static async Task Audit(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string actor,
        string action,
        Guid policy,
        Guid? endpoint,
        object details,
        CancellationToken ct
    )
    {
        await using var command = new NpgsqlCommand(
            "INSERT INTO platform.process_policy_audit(tenant_id,actor,action,policy_id,endpoint_id,details) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
            c,
            tx
        );
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(actor);
        command.Parameters.AddWithValue(action);
        command.Parameters.AddWithValue(policy);
        command.Parameters.AddWithValue((object?)endpoint ?? DBNull.Value);
        command.Parameters.AddWithValue(JsonSerializer.Serialize(details, Json));
        await command.ExecuteNonQueryAsync(ct);
    }

    private static string Hash(ProcessTelemetryPolicy policy) =>
        Convert
            .ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(policy, Json)))
            .ToLowerInvariant();

    public ValueTask DisposeAsync() => _source.DisposeAsync();
}
