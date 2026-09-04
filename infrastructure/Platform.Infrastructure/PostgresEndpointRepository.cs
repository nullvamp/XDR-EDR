using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresEndpointRepository : IEndpointRepository, IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly NpgsqlDataSource _dataSource;

    public PostgresEndpointRepository(string connectionString)
    {
        var cs = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = true,
            MinPoolSize = 1,
            MaxPoolSize = 40,
            Timeout = 5,
            CommandTimeout = 15,
            KeepAlive = 30,
            NoResetOnClose = false,
        };
        _dataSource = NpgsqlDataSource.Create(cs.ConnectionString);
    }

    public async Task<EnrollmentTokenSecret> CreateEnrollmentTokenAsync(
        string tenantId,
        string actor,
        EnrollmentTokenCreate request,
        byte[] pepper,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        if (
            request.ExpiresAt <= DateTimeOffset.UtcNow
            || request.ExpiresAt > DateTimeOffset.UtcNow.AddDays(90)
        )
            throw new EnrollmentConflictException(
                "TOKEN_EXPIRY_INVALID",
                "Expiration must be in the future and within 90 days."
            );
        if (request.MaximumUses is < 1 or > 100000)
            throw new EnrollmentConflictException(
                "TOKEN_USES_INVALID",
                "Maximum uses is outside policy."
            );
        var secret = EnrollmentSecrets.Generate();
        var id = Guid.NewGuid();
        var hash = EnrollmentSecrets.Hash(secret, pepper);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            ct
        );
        await using (
            var command = new NpgsqlCommand(
                "INSERT INTO platform.enrollment_tokens(tenant_id,id,secret_hash,expires_at,maximum_uses,allowed_platforms,endpoint_group_id,policy_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                connection,
                transaction
            )
        )
        {
            command.Parameters.AddWithValue(tenant);
            command.Parameters.AddWithValue(id);
            command.Parameters.AddWithValue(hash);
            command.Parameters.AddWithValue(request.ExpiresAt);
            command.Parameters.AddWithValue(request.MaximumUses);
            command.Parameters.AddWithValue(request.AllowedPlatforms);
            command.Parameters.AddWithValue(
                (object?)ParseOptional(request.EndpointGroupId) ?? DBNull.Value
            );
            command.Parameters.AddWithValue(
                (object?)ParseOptional(request.PolicyId) ?? DBNull.Value
            );
            command.Parameters.AddWithValue(actor);
            await command.ExecuteNonQueryAsync(ct);
        }
        await InsertAudit(
            connection,
            transaction,
            tenant,
            "enrollment_token.created",
            "success",
            actor,
            Guid.NewGuid().ToString(),
            null,
            ct
        );
        await transaction.CommitAsync(ct);
        return new(
            new(
                id,
                tenantId,
                request.ExpiresAt,
                request.MaximumUses,
                0,
                request.AllowedPlatforms,
                request.EndpointGroupId,
                request.PolicyId,
                false,
                actor,
                DateTimeOffset.UtcNow,
                null
            ),
            secret
        );
    }

    public async Task<IReadOnlyList<EnrollmentTokenMetadata>> ListEnrollmentTokensAsync(
        string tenantId,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        var list = new List<EnrollmentTokenMetadata>();
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT id,expires_at,maximum_uses,uses,allowed_platforms,endpoint_group_id,policy_id,revoked_at,created_by,created_at,last_used_at FROM platform.enrollment_tokens WHERE tenant_id=$1 ORDER BY created_at DESC",
            connection
        );
        command.Parameters.AddWithValue(tenant);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            list.Add(
                new(
                    reader.GetGuid(0),
                    tenantId,
                    reader.GetFieldValue<DateTimeOffset>(1),
                    reader.GetInt32(2),
                    reader.GetInt32(3),
                    reader.GetFieldValue<string[]>(4),
                    reader.IsDBNull(5) ? null : reader.GetGuid(5).ToString(),
                    reader.IsDBNull(6) ? null : reader.GetGuid(6).ToString(),
                    !reader.IsDBNull(7),
                    reader.GetString(8),
                    reader.GetFieldValue<DateTimeOffset>(9),
                    reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10)
                )
            );
        return list;
    }

    public async Task<bool> RevokeEnrollmentTokenAsync(
        string tenantId,
        Guid tokenId,
        string actor,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        await using var command = new NpgsqlCommand(
            "UPDATE platform.enrollment_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND id=$2 RETURNING id",
            connection,
            tx
        );
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(tokenId);
        var found = await command.ExecuteScalarAsync(ct) is not null;
        if (found)
            await InsertAudit(
                connection,
                tx,
                tenant,
                "enrollment_token.revoked",
                "success",
                actor,
                Guid.NewGuid().ToString(),
                null,
                ct
            );
        await tx.CommitAsync(ct);
        return found;
    }

    public async Task<EnrollmentResult> EnrollAsync(
        EnrollmentRequest request,
        string requestHash,
        Func<string, string, string, IssuedAgentCertificate> issueCredential,
        byte[] pepper,
        CancellationToken ct
    )
    {
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable,
            ct
        );
        Guid tenant;
        string tokenHash;
        DateTimeOffset expires;
        int maxUses,
            uses;
        string[] allowed;
        Guid? group,
            policy;
        bool revoked;
        await using (
            var token = new NpgsqlCommand(
                "SELECT tenant_id,secret_hash,expires_at,maximum_uses,uses,allowed_platforms,endpoint_group_id,policy_id,revoked_at IS NOT NULL FROM platform.enrollment_tokens WHERE id=$1 FOR UPDATE",
                connection,
                tx
            )
        )
        {
            token.Parameters.AddWithValue(request.TokenId);
            await using var r = await token.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct))
                throw new EnrollmentConflictException(
                    "ENROLLMENT_REJECTED",
                    "Enrollment material is invalid."
                );
            tenant = r.GetGuid(0);
            tokenHash = r.GetString(1);
            expires = r.GetFieldValue<DateTimeOffset>(2);
            maxUses = r.GetInt32(3);
            uses = r.GetInt32(4);
            allowed = r.GetFieldValue<string[]>(5);
            group = r.IsDBNull(6) ? null : r.GetGuid(6);
            policy = r.IsDBNull(7) ? null : r.GetGuid(7);
            revoked = r.GetBoolean(8);
        }
        var existing = await ReadIdempotency(connection, tx, tenant, request.IdempotencyKey, ct);
        if (existing is not null)
        {
            if (existing.Value.Hash != requestHash)
                throw new EnrollmentConflictException(
                    "IDEMPOTENCY_CONFLICT",
                    "The idempotency key was used with a different request."
                );
            if (existing.Value.Response is not null)
                return JsonSerializer.Deserialize<EnrollmentResult>(
                    existing.Value.Response,
                    JsonOptions
                )!;
        }
        if (
            revoked
            || expires <= DateTimeOffset.UtcNow
            || uses >= maxUses
            || !allowed.Contains(request.Platform, StringComparer.OrdinalIgnoreCase)
            || !EnrollmentSecrets.Verify(request.TokenSecret, tokenHash, pepper)
        )
            throw new EnrollmentConflictException(
                "ENROLLMENT_REJECTED",
                "Enrollment material is invalid or unavailable."
            );
        var nonceHash = Sha256(request.Nonce);
        await using (
            var nonce = new NpgsqlCommand(
                "INSERT INTO platform.enrollment_attempts(tenant_id,token_id,installation_id,nonce_hash,request_hash,outcome) VALUES($1,$2,$3,$4,$5,'processing') RETURNING id",
                connection,
                tx
            )
        )
        {
            nonce.Parameters.AddWithValue(tenant);
            nonce.Parameters.AddWithValue(request.TokenId);
            nonce.Parameters.AddWithValue(request.InstallationId);
            nonce.Parameters.AddWithValue(nonceHash);
            nonce.Parameters.AddWithValue(requestHash);
            try
            {
                await nonce.ExecuteNonQueryAsync(ct);
            }
            catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.UniqueViolation)
            {
                throw new EnrollmentConflictException(
                    "REPLAY_REJECTED",
                    "The enrollment nonce was already used."
                );
            }
        }
        if (existing is null)
            await InsertIdempotency(
                connection,
                tx,
                tenant,
                request.IdempotencyKey,
                requestHash,
                ct
            );
        var deviceIdentity = Sha256(
            request.InstallationId + "\n" + request.CertificateSigningRequest
        );
        var endpointId = await ResolveEndpoint(connection, tx, tenant, deviceIdentity, request, ct);
        var agentId = await ResolveAgent(connection, tx, tenant, endpointId, request, ct);
        var issued = issueCredential(
            request.CertificateSigningRequest,
            tenant.ToString(),
            $"{endpointId}:{agentId}"
        );
        var publicKeyHash = Sha256(request.CertificateSigningRequest);
        await using (
            var credentialMeta = new NpgsqlCommand(
                "INSERT INTO platform.agent_credentials(tenant_id,agent_id,credential_type,public_key_sha256,certificate_thumbprint,certificate_not_before,certificate_not_after) VALUES($1,$2,'x509-mtls',$3,$4,now(),$5) ON CONFLICT(tenant_id,public_key_sha256) DO UPDATE SET certificate_thumbprint=EXCLUDED.certificate_thumbprint,certificate_not_before=EXCLUDED.certificate_not_before,certificate_not_after=EXCLUDED.certificate_not_after,revoked_at=NULL",
                connection,
                tx
            )
        )
        {
            credentialMeta.Parameters.AddWithValue(tenant);
            credentialMeta.Parameters.AddWithValue(agentId);
            credentialMeta.Parameters.AddWithValue(publicKeyHash);
            credentialMeta.Parameters.AddWithValue(issued.Thumbprint);
            credentialMeta.Parameters.AddWithValue(issued.NotAfter);
            await credentialMeta.ExecuteNonQueryAsync(ct);
        }
        await using (
            var useToken = new NpgsqlCommand(
                "UPDATE platform.enrollment_tokens SET uses=uses+1,last_used_at=now() WHERE tenant_id=$1 AND id=$2",
                connection,
                tx
            )
        )
        {
            useToken.Parameters.AddWithValue(tenant);
            useToken.Parameters.AddWithValue(request.TokenId);
            await useToken.ExecuteNonQueryAsync(ct);
        }
        var receipt = Guid.NewGuid();
        var result = new EnrollmentResult(
            receipt,
            tenant.ToString(),
            endpointId,
            agentId,
            issued.CertificatePem,
            issued.CaCertificatePem,
            issued.NotAfter,
            "1.1",
            policy?.ToString() ?? "1",
            30,
            60,
            DateTimeOffset.UtcNow
        );
        await CompleteIdempotency(
            connection,
            tx,
            tenant,
            request.IdempotencyKey,
            JsonSerializer.Serialize(result, JsonOptions),
            ct
        );
        await InsertAudit(
            connection,
            tx,
            tenant,
            "agent.enrolled",
            "success",
            $"agent:{agentId}",
            request.IdempotencyKey,
            endpointId,
            ct
        );
        await InsertOutbox(
            connection,
            tx,
            tenant,
            "endpoint.enrolled",
            "endpoint.lifecycle.v1",
            JsonSerializer.Serialize(
                new
                {
                    endpointId,
                    agentId,
                    groupId = group,
                    policyId = policy,
                    revision = 1,
                },
                JsonOptions
            ),
            request.IdempotencyKey,
            ct
        );
        await using (
            var finish = new NpgsqlCommand(
                "UPDATE platform.enrollment_attempts SET outcome='success',endpoint_id=$1,agent_id=$2 WHERE tenant_id=$3 AND nonce_hash=$4",
                connection,
                tx
            )
        )
        {
            finish.Parameters.AddWithValue(endpointId);
            finish.Parameters.AddWithValue(agentId);
            finish.Parameters.AddWithValue(tenant);
            finish.Parameters.AddWithValue(nonceHash);
            await finish.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<EndpointView> RecordHeartbeatAsync(
        string tenantId,
        HeartbeatRequest request,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            ct
        );
        string previousStatus;
        await using (
            var current = new NpgsqlCommand(
                "SELECT status FROM platform.endpoints WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                connection,
                tx
            )
        )
        {
            current.Parameters.AddWithValue(tenant);
            current.Parameters.AddWithValue(request.EndpointId);
            previousStatus =
                (string?)await current.ExecuteScalarAsync(ct)
                ?? throw new EnrollmentConflictException(
                    "AGENT_IDENTITY_INVALID",
                    "Endpoint identity is invalid."
                );
        }
        await using (
            var insert = new NpgsqlCommand(
                "INSERT INTO platform.agent_heartbeats(tenant_id,agent_id,endpoint_id,sequence,occurred_at,agent_version,protocol_version,health,queue_depth,inventory,data) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 WHERE EXISTS(SELECT 1 FROM platform.agents WHERE tenant_id=$1 AND id=$2 AND endpoint_id=$3 AND status='active') ON CONFLICT (tenant_id,agent_id,sequence) DO NOTHING",
                connection,
                tx
            )
        )
        {
            insert.Parameters.AddWithValue(tenant);
            insert.Parameters.AddWithValue(request.AgentId);
            insert.Parameters.AddWithValue(request.EndpointId);
            insert.Parameters.AddWithValue(request.Sequence);
            insert.Parameters.AddWithValue(request.Timestamp);
            insert.Parameters.AddWithValue(request.AgentVersion);
            insert.Parameters.AddWithValue(request.ProtocolVersion);
            insert.Parameters.AddWithValue(request.Health);
            insert.Parameters.AddWithValue(request.QueueDepth);
            insert.Parameters.Add(
                new NpgsqlParameter
                {
                    Value =
                        (object?)JsonSerializer.Serialize(request.Inventory, JsonOptions)
                        ?? DBNull.Value,
                    NpgsqlDbType = NpgsqlDbType.Jsonb,
                }
            );
            insert.Parameters.Add(
                new NpgsqlParameter
                {
                    Value = JsonSerializer.Serialize(request, JsonOptions),
                    NpgsqlDbType = NpgsqlDbType.Jsonb,
                }
            );
            var rows = await insert.ExecuteNonQueryAsync(ct);
            if (rows != 1)
            {
                await using var replay = new NpgsqlCommand(
                    "SELECT EXISTS(SELECT 1 FROM platform.agent_heartbeats WHERE tenant_id=$1 AND agent_id=$2 AND endpoint_id=$3 AND sequence=$4)",
                    connection,
                    tx
                );
                replay.Parameters.AddWithValue(tenant);
                replay.Parameters.AddWithValue(request.AgentId);
                replay.Parameters.AddWithValue(request.EndpointId);
                replay.Parameters.AddWithValue(request.Sequence);
                if (await replay.ExecuteScalarAsync(ct) is not true)
                    throw new EnrollmentConflictException(
                        "AGENT_IDENTITY_INVALID",
                        "Agent identity is invalid or revoked."
                    );
                await tx.RollbackAsync(ct);
                return await GetEndpointAsync(tenantId, request.EndpointId, ct)
                    ?? throw new InvalidOperationException("Endpoint disappeared after heartbeat replay.");
            }
        }
        var nextStatus = previousStatus is "stale" or "offline" ? "recovered" : "online";
        await using (
            var update = new NpgsqlCommand(
                "UPDATE platform.endpoints SET status=$9,last_seen_at=now(),agent_version=$1,inventory=$2,hostname=COALESCE($3,hostname),os_version=$4,architecture=COALESCE($5,architecture),health=$6,revision=revision+1 WHERE tenant_id=$7 AND id=$8",
                connection,
                tx
            )
        )
        {
            update.Parameters.AddWithValue(request.AgentVersion);
            update.Parameters.Add(
                new NpgsqlParameter
                {
                    Value =
                        (object?)JsonSerializer.Serialize(request.Inventory, JsonOptions)
                        ?? DBNull.Value,
                    NpgsqlDbType = NpgsqlDbType.Jsonb,
                }
            );
            update.Parameters.AddWithValue((object?)request.Inventory?.Hostname ?? DBNull.Value);
            update.Parameters.AddWithValue(request.OsVersion);
            update.Parameters.AddWithValue(
                (object?)request.Inventory?.Architecture ?? DBNull.Value
            );
            update.Parameters.AddWithValue(request.Health);
            update.Parameters.AddWithValue(tenant);
            update.Parameters.AddWithValue(request.EndpointId);
            update.Parameters.AddWithValue(nextStatus);
            await update.ExecuteNonQueryAsync(ct);
        }
        if (nextStatus != previousStatus)
        {
            await InsertStatusHistory(
                connection,
                tx,
                tenant,
                request.EndpointId,
                previousStatus,
                nextStatus,
                "authenticated-heartbeat",
                ct
            );
            await InsertAudit(
                connection,
                tx,
                tenant,
                $"endpoint.{nextStatus}",
                "success",
                $"agent:{request.AgentId}",
                ActivityTrace(),
                request.EndpointId,
                ct
            );
        }
        await using (
            var agent = new NpgsqlCommand(
                "UPDATE platform.agents SET last_checkin=now(),version=$1,capabilities=$2,protocol_version=$3,status='active',revision=revision+1 WHERE tenant_id=$4 AND id=$5",
                connection,
                tx
            )
        )
        {
            agent.Parameters.AddWithValue(request.AgentVersion);
            agent.Parameters.Add(
                new NpgsqlParameter
                {
                    Value = JsonSerializer.Serialize(request.Capabilities),
                    NpgsqlDbType = NpgsqlDbType.Jsonb,
                }
            );
            agent.Parameters.AddWithValue(request.ProtocolVersion);
            agent.Parameters.AddWithValue(tenant);
            agent.Parameters.AddWithValue(request.AgentId);
            await agent.ExecuteNonQueryAsync(ct);
        }
        await InsertOutbox(
            connection,
            tx,
            tenant,
            "endpoint.heartbeat.received",
            "endpoint.lifecycle.v1",
            JsonSerializer.Serialize(
                new
                {
                    request.EndpointId,
                    request.AgentId,
                    request.Sequence,
                },
                JsonOptions
            ),
            ActivityTrace(),
            ct
        );
        await tx.CommitAsync(ct);
        return await GetEndpointAsync(tenantId, request.EndpointId, ct)
            ?? throw new InvalidOperationException("Endpoint disappeared after heartbeat.");
    }

    public async Task<EndpointPage> ListEndpointsAsync(
        string tenantId,
        int pageSize,
        string? cursor,
        string? search,
        EndpointStatus? status,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        pageSize = Math.Clamp(pageSize, 1, 500);
        Guid? after = Guid.TryParse(cursor, out var parsed) ? parsed : null;
        var list = new List<EndpointView>();
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        const string sql =
            "SELECT e.id,e.device_identity,COALESCE(e.hostname,''),e.os_type,e.os_version,COALESCE(e.architecture,''),e.status,e.last_seen_at,COALESCE(e.agent_version,''),e.revision,e.inventory,COALESCE(a.capabilities,'[]'::jsonb) FROM platform.endpoints e LEFT JOIN LATERAL(SELECT capabilities FROM platform.agents WHERE tenant_id=e.tenant_id AND endpoint_id=e.id ORDER BY last_checkin DESC NULLS LAST LIMIT 1)a ON true WHERE e.tenant_id=$1 AND e.deleted_at IS NULL AND ($2::uuid IS NULL OR e.id>$2) AND ($3::text IS NULL OR e.hostname ILIKE '%'||$3||'%' OR e.device_identity=$3 OR e.id::text=$3) AND ($4::text IS NULL OR e.status=$4) ORDER BY e.id LIMIT $5";
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue((object?)after ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)search ?? DBNull.Value);
        command.Parameters.AddWithValue(
            (object?)status?.ToString().ToLowerInvariant() ?? DBNull.Value
        );
        command.Parameters.AddWithValue(pageSize + 1);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            list.Add(ReadEndpoint(reader, tenantId));
        var next = list.Count > pageSize ? list[pageSize - 1].Id.ToString() : null;
        if (list.Count > pageSize)
            list.RemoveAt(list.Count - 1);
        return new(list, next);
    }

    public async Task<EndpointView?> GetEndpointAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        var page = await ListEndpointsAsync(tenantId, 2, null, endpointId.ToString(), null, ct);
        return page.Items.FirstOrDefault(x => x.Id == endpointId);
    }

    public async Task<LifecycleSweepResult> SweepEndpointLifecycleAsync(
        TimeSpan staleAfter,
        TimeSpan offlineAfter,
        CancellationToken ct
    )
    {
        var stale = 0;
        var offline = 0;
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        async Task Transition(string from, string to, TimeSpan age)
        {
            await using var command = new NpgsqlCommand(
                "UPDATE platform.endpoints SET status=$1,revision=revision+1 WHERE status=$2 AND deleted_at IS NULL AND last_seen_at IS NOT NULL AND last_seen_at<now()-$3::interval RETURNING tenant_id,id",
                connection,
                tx
            );
            command.Parameters.AddWithValue(to);
            command.Parameters.AddWithValue(from);
            command.Parameters.AddWithValue(age);
            await using var reader = await command.ExecuteReaderAsync(ct);
            var changed = new List<(Guid Tenant, Guid Endpoint)>();
            while (await reader.ReadAsync(ct))
                changed.Add((reader.GetGuid(0), reader.GetGuid(1)));
            await reader.DisposeAsync();
            foreach (var item in changed)
            {
                await InsertStatusHistory(
                    connection,
                    tx,
                    item.Tenant,
                    item.Endpoint,
                    from,
                    to,
                    "heartbeat-timeout",
                    ct
                );
                await InsertAudit(
                    connection,
                    tx,
                    item.Tenant,
                    $"endpoint.{to}",
                    "success",
                    "system:lifecycle",
                    ActivityTrace(),
                    item.Endpoint,
                    ct
                );
                await InsertOutbox(
                    connection,
                    tx,
                    item.Tenant,
                    $"endpoint.{to}",
                    "endpoint.lifecycle.v1",
                    JsonSerializer.Serialize(
                        new
                        {
                            endpointId = item.Endpoint,
                            previousStatus = from,
                            status = to,
                        },
                        JsonOptions
                    ),
                    ActivityTrace(),
                    ct
                );
            }
            if (to == "stale")
                stale += changed.Count;
            else
                offline += changed.Count;
        }
        await Transition("online", "stale", staleAfter);
        await Transition("recovered", "stale", staleAfter);
        await Transition("stale", "offline", offlineAfter);
        await tx.CommitAsync(ct);
        return new(stale, offline, 0, DateTimeOffset.UtcNow);
    }

    public async Task<bool> SetEndpointAdministrativeStateAsync(
        string tenantId,
        Guid endpointId,
        EndpointStatus status,
        string actor,
        string reason,
        CancellationToken ct
    )
    {
        if (status is not (EndpointStatus.Disabled or EndpointStatus.Revoked))
            throw new EnrollmentConflictException(
                "STATUS_INVALID",
                "Only disabled or revoked administrative states are supported."
            );
        var tenant = ParseTenant(tenantId);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        string? previous;
        await using (
            var read = new NpgsqlCommand(
                "SELECT status FROM platform.endpoints WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE",
                connection,
                tx
            )
        )
        {
            read.Parameters.AddWithValue(tenant);
            read.Parameters.AddWithValue(endpointId);
            previous = (string?)await read.ExecuteScalarAsync(ct);
        }
        if (previous is null)
        {
            await tx.RollbackAsync(ct);
            return false;
        }
        var target = status.ToString().ToLowerInvariant();
        await using (
            var update = new NpgsqlCommand(
                "UPDATE platform.endpoints SET status=$1,revision=revision+1 WHERE tenant_id=$2 AND id=$3",
                connection,
                tx
            )
        )
        {
            update.Parameters.AddWithValue(target);
            update.Parameters.AddWithValue(tenant);
            update.Parameters.AddWithValue(endpointId);
            await update.ExecuteNonQueryAsync(ct);
        }
        if (status == EndpointStatus.Revoked)
        {
            await using var credentials = new NpgsqlCommand(
                "UPDATE platform.agent_credentials SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1 AND agent_id IN(SELECT id FROM platform.agents WHERE tenant_id=$1 AND endpoint_id=$2)",
                connection,
                tx
            );
            credentials.Parameters.AddWithValue(tenant);
            credentials.Parameters.AddWithValue(endpointId);
            await credentials.ExecuteNonQueryAsync(ct);
            await using var agents = new NpgsqlCommand(
                "UPDATE platform.agents SET status='revoked' WHERE tenant_id=$1 AND endpoint_id=$2",
                connection,
                tx
            );
            agents.Parameters.AddWithValue(tenant);
            agents.Parameters.AddWithValue(endpointId);
            await agents.ExecuteNonQueryAsync(ct);
        }
        await InsertStatusHistory(connection, tx, tenant, endpointId, previous, target, reason, ct);
        await InsertAudit(
            connection,
            tx,
            tenant,
            $"endpoint.{target}",
            "success",
            actor,
            ActivityTrace(),
            endpointId,
            ct
        );
        await InsertOutbox(
            connection,
            tx,
            tenant,
            $"endpoint.{target}",
            "endpoint.lifecycle.v1",
            JsonSerializer.Serialize(
                new
                {
                    endpointId,
                    previousStatus = previous,
                    status = target,
                    reason,
                },
                JsonOptions
            ),
            ActivityTrace(),
            ct
        );
        await tx.CommitAsync(ct);
        return true;
    }

    public async Task<IReadOnlyList<EndpointStatusChange>> ListEndpointStatusHistoryAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        var values = new List<EndpointStatusChange>();
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT previous_status,status,reason,occurred_at FROM platform.endpoint_status_history WHERE tenant_id=$1 AND endpoint_id=$2 ORDER BY occurred_at DESC LIMIT 500",
            connection
        );
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(endpointId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            values.Add(
                new(
                    endpointId,
                    Enum.Parse<EndpointStatus>(reader.GetString(0), true),
                    Enum.Parse<EndpointStatus>(reader.GetString(1), true),
                    reader.GetString(2),
                    reader.GetFieldValue<DateTimeOffset>(3)
                )
            );
        return values;
    }

    public async Task<bool> IsCredentialActiveAsync(
        string tenantId,
        string thumbprint,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM platform.agent_credentials WHERE tenant_id=$1 AND certificate_thumbprint=$2 AND revoked_at IS NULL AND certificate_not_before<=now() AND certificate_not_after>now())",
            connection
        );
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(thumbprint);
        return (bool)(await command.ExecuteScalarAsync(ct) ?? false);
    }

    public async Task RotateCredentialAsync(
        string tenantId,
        Guid agentId,
        string currentThumbprint,
        IssuedAgentCertificate issued,
        string certificateSigningRequest,
        CancellationToken ct
    )
    {
        var tenant = ParseTenant(tenantId);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        await using (
            var revoke = new NpgsqlCommand(
                "UPDATE platform.agent_credentials SET revoked_at=now() WHERE tenant_id=$1 AND agent_id=$2 AND certificate_thumbprint=$3 AND revoked_at IS NULL",
                connection,
                tx
            )
        )
        {
            revoke.Parameters.AddWithValue(tenant);
            revoke.Parameters.AddWithValue(agentId);
            revoke.Parameters.AddWithValue(currentThumbprint);
            if (await revoke.ExecuteNonQueryAsync(ct) != 1)
                throw new EnrollmentConflictException(
                    "CREDENTIAL_INVALID",
                    "The active credential could not be rotated."
                );
        }
        await using (
            var insert = new NpgsqlCommand(
                "INSERT INTO platform.agent_credentials(tenant_id,agent_id,credential_type,public_key_sha256,certificate_thumbprint,certificate_not_before,certificate_not_after) VALUES($1,$2,'x509-mtls',$3,$4,now(),$5)",
                connection,
                tx
            )
        )
        {
            insert.Parameters.AddWithValue(tenant);
            insert.Parameters.AddWithValue(agentId);
            insert.Parameters.AddWithValue(Sha256(certificateSigningRequest));
            insert.Parameters.AddWithValue(issued.Thumbprint);
            insert.Parameters.AddWithValue(issued.NotAfter);
            await insert.ExecuteNonQueryAsync(ct);
        }
        await using (
            var agent = new NpgsqlCommand(
                "UPDATE platform.agents SET credential_expires_at=$1,revision=revision+1 WHERE tenant_id=$2 AND id=$3",
                connection,
                tx
            )
        )
        {
            agent.Parameters.AddWithValue(issued.NotAfter);
            agent.Parameters.AddWithValue(tenant);
            agent.Parameters.AddWithValue(agentId);
            await agent.ExecuteNonQueryAsync(ct);
        }
        await InsertAudit(
            connection,
            tx,
            tenant,
            "agent.credential.rotated",
            "success",
            $"agent:{agentId}",
            ActivityTrace(),
            null,
            ct
        );
        await tx.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<EndpointView>> ListAllEndpointsForProjectionAsync(
        CancellationToken ct
    )
    {
        var values = new List<EndpointView>();
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tenants = new NpgsqlCommand(
            "SELECT DISTINCT tenant_id FROM platform.endpoints WHERE deleted_at IS NULL",
            connection
        );
        await using var reader = await tenants.ExecuteReaderAsync(ct);
        var ids = new List<Guid>();
        while (await reader.ReadAsync(ct))
            ids.Add(reader.GetGuid(0));
        await reader.DisposeAsync();
        foreach (var tenant in ids)
        {
            string? cursor = null;
            do
            {
                var page = await ListEndpointsAsync(tenant.ToString(), 500, cursor, null, null, ct);
                values.AddRange(page.Items);
                cursor = page.NextCursor;
            } while (cursor is not null);
        }
        return values;
    }

    public async Task<IReadOnlyList<OutboxMessage>> LeaseOutboxAsync(
        int limit,
        TimeSpan lease,
        CancellationToken ct
    )
    {
        var list = new List<OutboxMessage>();
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        const string sql =
            "WITH picked AS(SELECT id FROM platform.outbox WHERE published_at IS NULL AND failed_at IS NULL AND available_at<=now() AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1) UPDATE platform.outbox o SET lease_until=now()+$2::interval,attempts=attempts+1 FROM picked WHERE o.id=picked.id RETURNING o.id,o.tenant_id,o.topic,o.subject,o.message::text,o.trace_id,o.created_at,o.attempts";
        await using var cmd = new NpgsqlCommand(sql, connection, tx);
        cmd.Parameters.AddWithValue(limit);
        cmd.Parameters.AddWithValue(lease);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(
                new(
                    r.GetGuid(0),
                    r.GetGuid(1).ToString(),
                    r.GetString(2),
                    "1.0",
                    r.GetString(3),
                    r.GetString(4),
                    r.GetString(5),
                    r.GetFieldValue<DateTimeOffset>(6),
                    r.GetInt32(7)
                )
            );
        await r.DisposeAsync();
        await tx.CommitAsync(ct);
        return list;
    }

    public async Task MarkOutboxPublishedAsync(Guid id, CancellationToken ct) =>
        await Execute(
            "UPDATE platform.outbox SET published_at=now(),lease_until=NULL WHERE id=$1",
            id,
            ct
        );

    public async Task MarkOutboxFailedAsync(
        Guid id,
        string safeReason,
        int max,
        CancellationToken ct
    ) =>
        await Execute(
            "UPDATE platform.outbox SET lease_until=NULL,available_at=now()+make_interval(secs=>LEAST(30,power(2,attempts)::int)),failed_at=CASE WHEN attempts>=$2 THEN now() END,safe_failure=$3 WHERE id=$1",
            id,
            ct,
            max,
            safeReason
        );

    public async Task<bool> HealthAsync(CancellationToken ct)
    {
        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(ct);
            await using var command = new NpgsqlCommand(
                "SELECT EXISTS(SELECT 1 FROM platform.schema_migrations WHERE version='0002_endpoint_enrollment')",
                connection
            );
            return (bool)(await command.ExecuteScalarAsync(ct) ?? false);
        }
        catch (NpgsqlException)
        {
            return false;
        }
    }

    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();

    private async Task Execute(string sql, Guid id, CancellationToken ct, params object[] values)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue(id);
        foreach (var value in values)
            cmd.Parameters.AddWithValue(value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<(string Hash, string? Response)?> ReadIdempotency(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string key,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT request_hash,response_json::text FROM platform.idempotency_records WHERE tenant_id=$1 AND scope='agent.enroll' AND idempotency_key=$2 FOR UPDATE",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(key);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct)
            ? (r.GetString(0), r.IsDBNull(1) ? null : r.GetString(1))
            : null;
    }

    private static async Task InsertIdempotency(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string key,
        string hash,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.idempotency_records(tenant_id,scope,idempotency_key,request_hash,state,expires_at) VALUES($1,'agent.enroll',$2,$3,'processing',now()+interval '24 hours')",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(key);
        cmd.Parameters.AddWithValue(hash);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task CompleteIdempotency(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string key,
        string response,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "UPDATE platform.idempotency_records SET state='completed',response_json=$1 WHERE tenant_id=$2 AND scope='agent.enroll' AND idempotency_key=$3",
            c,
            tx
        );
        cmd.Parameters.Add(
            new NpgsqlParameter { Value = response, NpgsqlDbType = NpgsqlDbType.Jsonb }
        );
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(key);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<Guid> ResolveEndpoint(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string identity,
        EnrollmentRequest request,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.endpoints(tenant_id,device_identity,hostname,os_type,os_version,architecture,health,status,agent_version) VALUES($1,$2,$3,$4,$5,$6,'enrolling','pending',$7) ON CONFLICT(tenant_id,device_identity) DO UPDATE SET hostname=EXCLUDED.hostname,os_version=EXCLUDED.os_version,architecture=EXCLUDED.architecture,revision=platform.endpoints.revision+1 RETURNING id",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(identity);
        cmd.Parameters.AddWithValue(request.Hostname);
        cmd.Parameters.AddWithValue(request.Platform);
        cmd.Parameters.AddWithValue(request.OsVersion);
        cmd.Parameters.AddWithValue(request.Architecture);
        cmd.Parameters.AddWithValue(request.AgentVersion);
        return (Guid)(
            await cmd.ExecuteScalarAsync(ct)
            ?? throw new InvalidOperationException("Endpoint creation failed.")
        );
    }

    private static async Task<Guid> ResolveAgent(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        Guid endpoint,
        EnrollmentRequest request,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.agents(tenant_id,endpoint_id,instance_id,version,capabilities,public_key,status,protocol_version,credential_expires_at) VALUES($1,$2,$3,$4,$5,$6,'active',$7,now()+interval '24 hours') ON CONFLICT(tenant_id,instance_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,version=EXCLUDED.version,capabilities=EXCLUDED.capabilities,public_key=EXCLUDED.public_key,status='active',protocol_version=EXCLUDED.protocol_version,credential_expires_at=EXCLUDED.credential_expires_at,revision=platform.agents.revision+1 RETURNING id",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(endpoint);
        cmd.Parameters.AddWithValue(request.InstallationId);
        cmd.Parameters.AddWithValue(request.AgentVersion);
        cmd.Parameters.Add(
            new NpgsqlParameter
            {
                Value = JsonSerializer.Serialize(request.Capabilities),
                NpgsqlDbType = NpgsqlDbType.Jsonb,
            }
        );
        cmd.Parameters.AddWithValue(request.CertificateSigningRequest);
        cmd.Parameters.AddWithValue(request.ProtocolVersion);
        return (Guid)(
            await cmd.ExecuteScalarAsync(ct)
            ?? throw new InvalidOperationException("Agent creation failed.")
        );
    }

    private static async Task InsertAudit(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string action,
        string outcome,
        string actor,
        string correlation,
        Guid? endpoint,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.audit_events(id,tenant_id,occurred_at,actor,action,resource,decision,outcome,request_id,data) VALUES($1,$2,now(),$3,$4,$5,'allow',$6,$7,'{}')",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(Guid.NewGuid());
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.Add(
            new NpgsqlParameter
            {
                Value = JsonSerializer.Serialize(new { type = "principal", id = actor }),
                NpgsqlDbType = NpgsqlDbType.Jsonb,
            }
        );
        cmd.Parameters.AddWithValue(action);
        cmd.Parameters.Add(
            new NpgsqlParameter
            {
                Value = JsonSerializer.Serialize(new { type = "endpoint", id = endpoint }),
                NpgsqlDbType = NpgsqlDbType.Jsonb,
            }
        );
        cmd.Parameters.AddWithValue(outcome);
        cmd.Parameters.AddWithValue(correlation);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task InsertStatusHistory(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        Guid endpoint,
        string previous,
        string status,
        string reason,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.endpoint_status_history(tenant_id,endpoint_id,previous_status,status,reason) VALUES($1,$2,$3,$4,$5)",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(endpoint);
        cmd.Parameters.AddWithValue(previous);
        cmd.Parameters.AddWithValue(status);
        cmd.Parameters.AddWithValue(reason);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task InsertOutbox(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        string topic,
        string subject,
        string payload,
        string trace,
        CancellationToken ct
    )
    {
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO platform.outbox(id,tenant_id,topic,subject,message,trace_id) VALUES($1,$2,$3,$4,$5,$6)",
            c,
            tx
        );
        cmd.Parameters.AddWithValue(Guid.NewGuid());
        cmd.Parameters.AddWithValue(tenant);
        cmd.Parameters.AddWithValue(topic);
        cmd.Parameters.AddWithValue(subject);
        cmd.Parameters.Add(
            new NpgsqlParameter { Value = payload, NpgsqlDbType = NpgsqlDbType.Jsonb }
        );
        cmd.Parameters.AddWithValue(trace);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static EndpointView ReadEndpoint(NpgsqlDataReader r, string tenantId)
    {
        var inv = r.IsDBNull(10)
            ? null
            : JsonSerializer.Deserialize<InventorySummary>(r.GetString(10), JsonOptions);
        var capabilities = JsonSerializer.Deserialize<string[]>(r.GetString(11), JsonOptions) ?? [];
        Enum.TryParse<EndpointStatus>(r.GetString(6), true, out var status);
        return new(
            r.GetGuid(0),
            tenantId,
            r.GetString(1),
            r.GetString(2),
            r.GetString(3),
            r.GetString(4),
            r.GetString(5),
            status,
            r.IsDBNull(7) ? null : r.GetFieldValue<DateTimeOffset>(7),
            r.GetString(8),
            capabilities,
            r.GetInt64(9),
            inv
        );
    }

    private static Guid ParseTenant(string value) =>
        Guid.TryParse(value, out var id)
            ? id
            : throw new EnrollmentConflictException(
                "TENANT_SCOPE_INVALID",
                "Tenant scope is invalid."
            );

    private static Guid? ParseOptional(string? value) =>
        Guid.TryParse(value, out var id) ? id : null;

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string ActivityTrace() =>
        System.Diagnostics.Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N");
}
