using System.Data;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresProcessTelemetryRepository(string connectionString)
    : IProcessTelemetryRepository,
        IAsyncDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly NpgsqlDataSource _dataSource = NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = true,
            MinPoolSize = 1,
            MaxPoolSize = 8,
            ConnectionIdleLifetime = 30,
            ConnectionPruningInterval = 5,
            Timeout = 5,
            CommandTimeout = 20,
        }.ConnectionString
    );

    public async Task<ProcessIngestResult> IngestAsync(
        string tenantId,
        ProcessEventBatch batch,
        ProcessTelemetryHealth health,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            ct
        );
        await using (
            var binding = new NpgsqlCommand(
                "SELECT EXISTS(SELECT 1 FROM platform.agents a JOIN platform.endpoints e ON e.tenant_id=a.tenant_id AND e.id=a.endpoint_id WHERE a.tenant_id=$1 AND a.id=$2 AND a.endpoint_id=$3 AND a.instance_id=$4 AND a.status='active' AND e.status NOT IN('disabled','revoked'))",
                connection,
                tx
            )
        )
        {
            binding.Parameters.AddWithValue(tenant);
            binding.Parameters.AddWithValue(batch.AgentId);
            binding.Parameters.AddWithValue(batch.EndpointId);
            binding.Parameters.AddWithValue(batch.InstallationId);
            if ((bool)(await binding.ExecuteScalarAsync(ct) ?? false) == false)
                throw new EnrollmentConflictException(
                    "PROCESS_IDENTITY_INVALID",
                    "Process telemetry identity is invalid or disabled."
                );
        }
        await using (
            var command = new NpgsqlCommand(
                "INSERT INTO platform.process_batches(tenant_id,batch_id,endpoint_id,agent_id,installation_id,first_sequence,last_sequence,event_count,content_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,batch_id) DO NOTHING",
                connection,
                tx
            )
        )
        {
            command.Parameters.AddWithValue(tenant);
            command.Parameters.AddWithValue(batch.BatchId);
            command.Parameters.AddWithValue(batch.EndpointId);
            command.Parameters.AddWithValue(batch.AgentId);
            command.Parameters.AddWithValue(batch.InstallationId);
            command.Parameters.AddWithValue(batch.FirstSequence);
            command.Parameters.AddWithValue(batch.LastSequence);
            command.Parameters.AddWithValue(batch.Events.Count);
            command.Parameters.AddWithValue(batch.ContentSha256);
            await command.ExecuteNonQueryAsync(ct);
        }
        var accepted = new List<Guid>();
        var duplicates = new List<Guid>();
        var rejected = new Dictionary<Guid, string>();
        var gaps = 0;
        long previousSequence = 0;
        await using (
            var lockHealth = new NpgsqlCommand(
                "SELECT last_sequence FROM platform.process_telemetry_health WHERE tenant_id=$1 AND endpoint_id=$2 FOR UPDATE",
                connection,
                tx
            )
        )
        {
            lockHealth.Parameters.AddWithValue(tenant);
            lockHealth.Parameters.AddWithValue(batch.EndpointId);
            previousSequence = (long?)await lockHealth.ExecuteScalarAsync(ct) ?? 0;
        }
        foreach (var item in batch.Events.OrderBy(x => x.Sequence))
        {
            var late = item.ObservedAt < DateTimeOffset.UtcNow.AddMinutes(-5);
            int inserted;
            await using (
                var command = new NpgsqlCommand(
                    "INSERT INTO platform.process_events(tenant_id,event_id,batch_id,endpoint_id,agent_id,process_entity_id,event_type,sequence,observed_at,schema_version,normalization_version,collector_type,collector_version,source_event_id,raw_sha256,trace_id,data_quality_flags,late,event_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT DO NOTHING",
                    connection,
                    tx
                )
            )
            {
                command.Parameters.AddWithValue(tenant);
                command.Parameters.AddWithValue(item.EventId);
                command.Parameters.AddWithValue(batch.BatchId);
                command.Parameters.AddWithValue(item.EndpointId);
                command.Parameters.AddWithValue(item.AgentId);
                command.Parameters.AddWithValue(item.ProcessEntityId);
                command.Parameters.AddWithValue(
                    item.Kind == ProcessEventKind.Started ? "started" : "exited"
                );
                command.Parameters.AddWithValue(item.Sequence);
                command.Parameters.AddWithValue(item.ObservedAt);
                command.Parameters.AddWithValue(item.SchemaVersion);
                command.Parameters.AddWithValue(item.NormalizationVersion);
                command.Parameters.AddWithValue(item.CollectorType);
                command.Parameters.AddWithValue(item.CollectorVersion);
                command.Parameters.AddWithValue((object?)item.SourceEventId ?? DBNull.Value);
                command.Parameters.AddWithValue((object?)item.RawSha256 ?? DBNull.Value);
                command.Parameters.AddWithValue((object?)item.TraceId ?? DBNull.Value);
                command.Parameters.AddWithValue(item.DataQualityFlags);
                command.Parameters.AddWithValue(late);
                command.Parameters.Add(
                    new NpgsqlParameter
                    {
                        Value = JsonSerializer.Serialize(item, Json),
                        NpgsqlDbType = NpgsqlDbType.Jsonb,
                    }
                );
                inserted = await command.ExecuteNonQueryAsync(ct);
            }
            if (inserted == 0)
            {
                duplicates.Add(item.EventId);
                continue;
            }
            accepted.Add(item.EventId);
            if (previousSequence > 0 && item.Sequence > previousSequence + 1)
                gaps += checked((int)Math.Min(int.MaxValue, item.Sequence - previousSequence - 1));
            previousSequence = Math.Max(previousSequence, item.Sequence);
            await UpsertEntity(connection, tx, tenant, item, late, ct);
            await using var outbox = new NpgsqlCommand(
                "INSERT INTO platform.outbox(id,tenant_id,topic,subject,message,trace_id) VALUES($1,$2,$3,$4,$5,$6)",
                connection,
                tx
            );
            outbox.Parameters.AddWithValue(Guid.NewGuid());
            outbox.Parameters.AddWithValue(tenant);
            outbox.Parameters.AddWithValue(
                item.Kind == ProcessEventKind.Started ? "process.started" : "process.exited"
            );
            outbox.Parameters.AddWithValue("process.telemetry.v1");
            outbox.Parameters.Add(
                new NpgsqlParameter
                {
                    Value = JsonSerializer.Serialize(
                        new
                        {
                            endpointId = item.EndpointId,
                            processEntityId = item.ProcessEntityId,
                            eventId = item.EventId,
                        },
                        Json
                    ),
                    NpgsqlDbType = NpgsqlDbType.Jsonb,
                }
            );
            outbox.Parameters.AddWithValue(item.TraceId ?? item.CorrelationId);
            await outbox.ExecuteNonQueryAsync(ct);
        }
        await using (
            var updateHealth = new NpgsqlCommand(
                "INSERT INTO platform.process_telemetry_health(tenant_id,endpoint_id,enabled,collector_type,collector_version,last_event_at,queue_depth,oldest_queued_age_seconds,dropped_events,drop_reason,last_upload_result,policy_version,last_sequence,sequence_gaps,excluded_events,last_exclusion_rule_id,last_exclusion_category,last_exclusion_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET enabled=EXCLUDED.enabled,collector_type=EXCLUDED.collector_type,collector_version=EXCLUDED.collector_version,last_event_at=EXCLUDED.last_event_at,queue_depth=EXCLUDED.queue_depth,oldest_queued_age_seconds=EXCLUDED.oldest_queued_age_seconds,dropped_events=EXCLUDED.dropped_events,drop_reason=EXCLUDED.drop_reason,last_upload_result=EXCLUDED.last_upload_result,policy_version=EXCLUDED.policy_version,last_sequence=GREATEST(platform.process_telemetry_health.last_sequence,EXCLUDED.last_sequence),sequence_gaps=platform.process_telemetry_health.sequence_gaps+EXCLUDED.sequence_gaps,excluded_events=GREATEST(platform.process_telemetry_health.excluded_events,EXCLUDED.excluded_events),last_exclusion_rule_id=EXCLUDED.last_exclusion_rule_id,last_exclusion_category=EXCLUDED.last_exclusion_category,last_exclusion_at=EXCLUDED.last_exclusion_at,updated_at=now()",
                connection,
                tx
            )
        )
        {
            updateHealth.Parameters.AddWithValue(tenant);
            updateHealth.Parameters.AddWithValue(batch.EndpointId);
            updateHealth.Parameters.AddWithValue(health.Enabled);
            updateHealth.Parameters.AddWithValue(health.CollectorType);
            updateHealth.Parameters.AddWithValue(health.CollectorVersion);
            updateHealth.Parameters.AddWithValue(
                (object?)batch.Events.Max(x => x.ObservedAt) ?? DBNull.Value
            );
            updateHealth.Parameters.AddWithValue(health.QueueDepth);
            updateHealth.Parameters.AddWithValue(health.OldestQueuedAgeSeconds);
            updateHealth.Parameters.AddWithValue(health.DroppedEvents);
            updateHealth.Parameters.AddWithValue((object?)health.DropReason ?? DBNull.Value);
            updateHealth.Parameters.AddWithValue(health.LastUploadResult);
            updateHealth.Parameters.AddWithValue(health.PolicyVersion);
            updateHealth.Parameters.AddWithValue(previousSequence);
            updateHealth.Parameters.AddWithValue(gaps);
            updateHealth.Parameters.AddWithValue(health.ExcludedEvents);
            updateHealth.Parameters.AddWithValue(
                (object?)health.LastExclusionRuleId ?? DBNull.Value
            );
            updateHealth.Parameters.AddWithValue(
                (object?)health.LastExclusionCategory ?? DBNull.Value
            );
            updateHealth.Parameters.AddWithValue((object?)health.LastExclusionAt ?? DBNull.Value);
            await updateHealth.ExecuteNonQueryAsync(ct);
        }
        if (
            health.LastExclusionRuleId is { } ruleId
            && health.LastExclusionCategory is { } category
        )
        {
            await using var exclusion = new NpgsqlCommand(
                "INSERT INTO platform.process_exclusion_metrics(tenant_id,endpoint_id,rule_id,category,events_excluded,last_match_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,endpoint_id,rule_id) DO UPDATE SET events_excluded=GREATEST(platform.process_exclusion_metrics.events_excluded,EXCLUDED.events_excluded),last_match_at=EXCLUDED.last_match_at",
                connection,
                tx
            );
            exclusion.Parameters.AddWithValue(tenant);
            exclusion.Parameters.AddWithValue(batch.EndpointId);
            exclusion.Parameters.AddWithValue(ruleId);
            exclusion.Parameters.AddWithValue(category);
            exclusion.Parameters.AddWithValue(health.ExcludedEvents);
            exclusion.Parameters.AddWithValue((object?)health.LastExclusionAt ?? DBNull.Value);
            await exclusion.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
        return new(
            new(batch.BatchId, accepted, duplicates, rejected, previousSequence, false),
            accepted.Count,
            duplicates.Count,
            rejected.Count,
            gaps
        );
    }

    public async Task<ProcessPage> SearchAsync(
        string tenantId,
        ProcessSearchRequest request,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        var size = Math.Clamp(request.PageSize, 1, 500);
        DateTimeOffset? cursorTime = null;
        string? cursorId = null;
        if (!string.IsNullOrWhiteSpace(request.Cursor))
        {
            try
            {
                var parts = TenantCursor.Unprotect(tenantId, request.Cursor).Split('|', 2);
                cursorTime = DateTimeOffset.Parse(
                    parts[0],
                    System.Globalization.CultureInfo.InvariantCulture
                );
                cursorId = parts[1];
            }
            catch (Exception e) when (e is FormatException or IndexOutOfRangeException)
            {
                throw new EnrollmentConflictException(
                    "CURSOR_INVALID",
                    "Process cursor is invalid."
                );
            }
        }
        const string sql =
            "SELECT tenant_id::text,endpoint_id,process_entity_id,pid,start_time,exit_time,parent_process_entity_id,parent_pid,lineage_state,executable_name,executable_path,command_line,working_directory,user_name,user_id,session_id,integrity_level,elevated,architecture,container_id,executable_metadata,start_event_id,exit_event_id,first_observed_at,last_updated_at,collector_type,collector_version,schema_version,normalization_version,data_quality_flags,late,duration_ms,exit_code FROM platform.process_entities WHERE tenant_id=$1 AND start_time BETWEEN $2 AND $3 AND ($4::uuid IS NULL OR endpoint_id=$4) AND ($5::text IS NULL OR executable_name ILIKE '%'||$5||'%') AND ($6::text IS NULL OR executable_path ILIKE '%'||$6||'%') AND ($7::text IS NULL OR command_line ILIKE '%'||$7||'%') AND ($8::integer IS NULL OR pid=$8) AND ($9::integer IS NULL OR parent_pid=$9) AND ($10::text IS NULL OR user_name ILIKE '%'||$10||'%' OR user_id=$10) AND ($11::text IS NULL OR executable_metadata->>'sha256'=$11) AND ($12::text IS NULL OR executable_metadata->>'signatureState'=$12) AND ($13::text IS NULL OR ($13='running' AND exit_time IS NULL) OR ($13='exited' AND exit_time IS NOT NULL)) AND ($14::timestamptz IS NULL OR (start_time,process_entity_id)<($14,$15)) ORDER BY start_time DESC,process_entity_id DESC LIMIT $16";
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(request.From);
        command.Parameters.AddWithValue(request.To);
        command.Parameters.AddWithValue((object?)request.EndpointId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)Limit(request.ProcessName, 256) ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)Limit(request.Path, 1024) ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)Limit(request.CommandLine, 1024) ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)request.ProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)request.ParentProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)Limit(request.User, 512) ?? DBNull.Value);
        command.Parameters.AddWithValue(
            (object?)request.Sha256?.ToLowerInvariant() ?? DBNull.Value
        );
        command.Parameters.AddWithValue(
            (object?)request.Signature?.ToString().ToLowerInvariant() ?? DBNull.Value
        );
        command.Parameters.AddWithValue((object?)request.State?.ToLowerInvariant() ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)cursorTime ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)cursorId ?? DBNull.Value);
        command.Parameters.AddWithValue(size + 1);
        var list = new List<ProcessEntityView>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            list.Add(Read(reader));
        var next =
            list.Count > size
                ? TenantCursor.Protect(
                    tenantId,
                    $"{list[size - 1].StartTime:O}|{list[size - 1].ProcessEntityId}"
                )
                : null;
        if (list.Count > size)
            list.RemoveAt(list.Count - 1);
        return new(list, next);
    }

    public async Task<ProcessEntityView?> GetAsync(
        string tenantId,
        Guid endpointId,
        string processEntityId,
        CancellationToken ct
    )
    {
        var page = await SearchAsync(
            tenantId,
            new(
                endpointId,
                DateTimeOffset.UtcNow.AddDays(-30),
                DateTimeOffset.UtcNow.AddMinutes(5),
                PageSize: 500
            ),
            ct
        );
        return page.Items.FirstOrDefault(x => x.ProcessEntityId == processEntityId);
    }

    public async Task<IReadOnlyList<ProcessEntityView>> TimelineAsync(
        string tenantId,
        Guid endpointId,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct
    ) =>
        (
            await SearchAsync(
                tenantId,
                new(endpointId, from, to, PageSize: Math.Clamp(limit, 1, 500)),
                ct
            )
        ).Items;

    public async Task<ProcessTreeNode?> TreeAsync(
        string tenantId,
        Guid endpointId,
        string rootProcessEntityId,
        int depth,
        CancellationToken ct
    )
    {
        depth = Math.Clamp(depth, 0, 8);
        var all = (
            await SearchAsync(
                tenantId,
                new(
                    endpointId,
                    DateTimeOffset.UtcNow.AddDays(-7),
                    DateTimeOffset.UtcNow.AddMinutes(5),
                    PageSize: 500
                ),
                ct
            )
        ).Items;
        var root = all.FirstOrDefault(x => x.ProcessEntityId == rootProcessEntityId);
        if (root is null)
            return null;
        ProcessTreeNode Build(ProcessEntityView item, int remaining, HashSet<string> path)
        {
            if (remaining == 0 || !path.Add(item.ProcessEntityId))
                return new(
                    item,
                    [],
                    item.ParentProcessEntityId is not null
                        && all.All(x => x.ProcessEntityId != item.ParentProcessEntityId),
                    item.LineageState != LineageState.Resolved
                );
            var children = all.Where(x => x.ParentProcessEntityId == item.ProcessEntityId)
                .Take(100)
                .Select(x => Build(x, remaining - 1, new(path)))
                .ToArray();
            return new(
                item,
                children,
                item.ParentProcessEntityId is not null
                    && all.All(x => x.ProcessEntityId != item.ParentProcessEntityId),
                item.LineageState != LineageState.Resolved
            );
        }
        return Build(root, depth, []);
    }

    public async Task<ProcessLineageView?> LineageAsync(
        string tenantId,
        Guid endpointId,
        string selectedProcessEntityId,
        int ancestorDepth,
        int descendantDepth,
        CancellationToken ct
    )
    {
        ancestorDepth = Math.Clamp(ancestorDepth, 0, 16);
        descendantDepth = Math.Clamp(descendantDepth, 0, 8);
        var all = (
            await SearchAsync(
                tenantId,
                new(
                    endpointId,
                    DateTimeOffset.UtcNow.AddDays(-30),
                    DateTimeOffset.UtcNow.AddMinutes(5),
                    PageSize: 500
                ),
                ct
            )
        ).Items;
        var byId = all.ToDictionary(x => x.ProcessEntityId, StringComparer.Ordinal);
        if (!byId.TryGetValue(selectedProcessEntityId, out var selected))
            return null;
        bool MissingParent(ProcessEntityView item) =>
            item.ParentProcessId is not null
            && (
                item.ParentProcessEntityId is null
                || !byId.ContainsKey(item.ParentProcessEntityId)
            );

        var descendants = 0;
        ProcessTreeNode BuildDescendants(
            ProcessEntityView item,
            int remaining,
            HashSet<string> path
        )
        {
            if (remaining == 0 || !path.Add(item.ProcessEntityId))
                return new(
                    item,
                    [],
                    MissingParent(item),
                    item.LineageState != LineageState.Resolved
                );
            var children = all.Where(x => x.ParentProcessEntityId == item.ProcessEntityId)
                .OrderBy(x => x.StartTime)
                .Take(100)
                .Select(x =>
                {
                    descendants++;
                    return BuildDescendants(x, remaining - 1, new(path));
                })
                .ToArray();
            return new(
                item,
                children,
                MissingParent(item),
                item.LineageState != LineageState.Resolved
            );
        }

        var tree = BuildDescendants(selected, descendantDepth, []);
        var ancestorCount = 0;
        var current = selected;
        var seen = new HashSet<string>(StringComparer.Ordinal) { selected.ProcessEntityId };
        while (
            ancestorCount < ancestorDepth
            && current.ParentProcessEntityId is { } parentId
            && byId.TryGetValue(parentId, out var parent)
            && seen.Add(parent.ProcessEntityId)
        )
        {
            tree = new(
                parent,
                [tree],
                MissingParent(parent),
                parent.LineageState != LineageState.Resolved
            );
            current = parent;
            ancestorCount++;
        }
        var incomplete = MissingParent(current);
        return new(
            selectedProcessEntityId,
            tree,
            ancestorCount,
            descendants,
            incomplete
        );
    }

    public async Task<ProcessTelemetryHealth?> HealthAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT enabled,collector_type,collector_version,last_event_at,queue_depth,oldest_queued_age_seconds,dropped_events,drop_reason,last_upload_result,policy_version,sequence_gaps FROM platform.process_telemetry_health WHERE tenant_id=$1 AND endpoint_id=$2",
            connection
        );
        command.Parameters.AddWithValue(Guid.Parse(tenantId));
        command.Parameters.AddWithValue(endpointId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct)
            ? new(
                endpointId,
                reader.GetBoolean(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3),
                reader.GetInt64(4),
                reader.GetInt64(5),
                reader.GetInt64(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetInt64(10)
            )
            : null;
    }

    public async Task<IReadOnlyList<ProcessEntityView>> ListAllAsync(CancellationToken ct)
    {
        var all = new List<ProcessEntityView>();
        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT tenant_id::text,endpoint_id,process_entity_id,pid,start_time,exit_time,parent_process_entity_id,parent_pid,lineage_state,executable_name,executable_path,command_line,working_directory,user_name,user_id,session_id,integrity_level,elevated,architecture,container_id,executable_metadata,start_event_id,exit_event_id,first_observed_at,last_updated_at,collector_type,collector_version,schema_version,normalization_version,data_quality_flags,late,duration_ms,exit_code FROM platform.process_entities ORDER BY start_time",
            connection
        );
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            all.Add(Read(reader));
        return all;
    }

    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();

    private static async Task UpsertEntity(
        NpgsqlConnection connection,
        NpgsqlTransaction tx,
        Guid tenant,
        ProcessObservation item,
        bool late,
        CancellationToken ct
    )
    {
        const string sql =
            "INSERT INTO platform.process_entities(tenant_id,endpoint_id,process_entity_id,pid,start_time,exit_time,parent_process_entity_id,parent_pid,lineage_state,executable_name,executable_path,command_line,working_directory,user_name,user_id,session_id,integrity_level,elevated,architecture,container_id,executable_metadata,start_event_id,exit_event_id,first_observed_at,last_updated_at,collector_type,collector_version,schema_version,normalization_version,data_quality_flags,late,duration_ms,exit_code) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$24,$25,$26,$27,$28,$29,$30,$31,$32) ON CONFLICT(tenant_id,endpoint_id,process_entity_id) DO UPDATE SET exit_time=COALESCE(EXCLUDED.exit_time,platform.process_entities.exit_time),exit_event_id=COALESCE(EXCLUDED.exit_event_id,platform.process_entities.exit_event_id),last_updated_at=EXCLUDED.last_updated_at,data_quality_flags=(SELECT ARRAY(SELECT DISTINCT unnest(platform.process_entities.data_quality_flags||EXCLUDED.data_quality_flags))),late=platform.process_entities.late OR EXCLUDED.late,duration_ms=COALESCE(EXCLUDED.duration_ms,platform.process_entities.duration_ms),exit_code=COALESCE(EXCLUDED.exit_code,platform.process_entities.exit_code),parent_process_entity_id=COALESCE(platform.process_entities.parent_process_entity_id,EXCLUDED.parent_process_entity_id),lineage_state=CASE WHEN EXCLUDED.parent_process_entity_id IS NOT NULL THEN EXCLUDED.lineage_state ELSE platform.process_entities.lineage_state END";
        await using var command = new NpgsqlCommand(sql, connection, tx);
        command.Parameters.AddWithValue(tenant);
        command.Parameters.AddWithValue(item.EndpointId);
        command.Parameters.AddWithValue(item.ProcessEntityId);
        command.Parameters.AddWithValue(item.ProcessId);
        command.Parameters.AddWithValue(item.ProcessStartTime);
        command.Parameters.AddWithValue((object?)item.ExitTime ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.ParentProcessEntityId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.ParentProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue(item.LineageState.ToString().ToLowerInvariant());
        command.Parameters.AddWithValue((object?)item.ExecutableName ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.ExecutablePath ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.CommandLine ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.WorkingDirectory ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.UserName ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.UserId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.SessionId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.IntegrityLevel ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.Elevated ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.Architecture ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.ContainerId ?? DBNull.Value);
        command.Parameters.Add(
            new NpgsqlParameter
            {
                Value =
                    (object?)JsonSerializer.Serialize(item.ExecutableMetadata, Json)
                    ?? DBNull.Value,
                NpgsqlDbType = NpgsqlDbType.Jsonb,
            }
        );
        command.Parameters.AddWithValue(
            item.Kind == ProcessEventKind.Started ? item.EventId : Guid.Empty
        );
        command.Parameters.AddWithValue(
            item.Kind == ProcessEventKind.Exited ? item.EventId : DBNull.Value
        );
        command.Parameters.AddWithValue(item.ObservedAt);
        command.Parameters.AddWithValue(item.CollectorType);
        command.Parameters.AddWithValue(item.CollectorVersion);
        command.Parameters.AddWithValue(item.SchemaVersion);
        command.Parameters.AddWithValue(item.NormalizationVersion);
        command.Parameters.AddWithValue(item.DataQualityFlags);
        command.Parameters.AddWithValue(late);
        command.Parameters.AddWithValue((object?)item.DurationMilliseconds ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)item.ExitCode ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(ct);

        if (item.Kind == ProcessEventKind.Started
            && item.DataQualityFlags.Contains("startup-inventory", StringComparer.OrdinalIgnoreCase))
        {
            await using var reconcile = new NpgsqlCommand(
                "UPDATE platform.process_entities SET parent_process_entity_id=$5,lineage_state='resolved',data_quality_flags=array_remove(data_quality_flags,'parent-not-observed'),last_updated_at=GREATEST(last_updated_at,$6) WHERE tenant_id=$1 AND endpoint_id=$2 AND parent_pid=$3 AND parent_process_entity_id IS NULL AND start_time BETWEEN $4 AND $6 AND process_entity_id<>$5",
                connection,
                tx
            );
            reconcile.Parameters.AddWithValue(tenant);
            reconcile.Parameters.AddWithValue(item.EndpointId);
            reconcile.Parameters.AddWithValue(item.ProcessId);
            reconcile.Parameters.AddWithValue(item.ProcessStartTime);
            reconcile.Parameters.AddWithValue(item.ProcessEntityId);
            reconcile.Parameters.AddWithValue(item.ObservedAt);
            await reconcile.ExecuteNonQueryAsync(ct);
        }
    }

    private static ProcessEntityView Read(NpgsqlDataReader r) =>
        new(
            r.GetString(0),
            r.GetGuid(1),
            r.GetString(2),
            r.GetInt32(3),
            r.GetFieldValue<DateTimeOffset>(4),
            r.IsDBNull(5) ? null : r.GetFieldValue<DateTimeOffset>(5),
            r.IsDBNull(6) ? null : r.GetString(6),
            r.IsDBNull(7) ? null : r.GetInt32(7),
            Enum.Parse<LineageState>(r.GetString(8), true),
            r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10),
            r.IsDBNull(11) ? null : r.GetString(11),
            r.IsDBNull(12) ? null : r.GetString(12),
            r.IsDBNull(13) ? null : r.GetString(13),
            r.IsDBNull(14) ? null : r.GetString(14),
            r.IsDBNull(15) ? null : r.GetString(15),
            r.IsDBNull(16) ? null : r.GetString(16),
            r.IsDBNull(17) ? null : r.GetBoolean(17),
            r.IsDBNull(18) ? null : r.GetString(18),
            r.IsDBNull(19) ? null : r.GetString(19),
            r.IsDBNull(20)
                ? null
                : JsonSerializer.Deserialize<ProcessExecutableMetadata>(r.GetString(20), Json),
            r.GetGuid(21),
            r.IsDBNull(22) ? null : r.GetGuid(22),
            r.GetFieldValue<DateTimeOffset>(23),
            r.GetFieldValue<DateTimeOffset>(24),
            r.GetString(25),
            r.GetString(26),
            r.GetString(27),
            r.GetString(28),
            r.GetFieldValue<string[]>(29),
            r.GetBoolean(30),
            r.IsDBNull(31) ? null : r.GetInt64(31),
            r.IsDBNull(32) ? null : r.GetInt32(32)
        );

    private static string? Limit(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? null : value[..Math.Min(value.Length, max)];
}
