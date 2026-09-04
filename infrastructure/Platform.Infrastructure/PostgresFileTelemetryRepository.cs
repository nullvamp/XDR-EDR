using System.Data;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresFileTelemetryRepository(string connectionString)
    : IFileTelemetryRepository,
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

    public async Task<FileIngestResult> IngestAsync(
        string tenantId,
        FileEventBatch batch,
        FileTelemetryHealth health,
        CancellationToken ct
    )
    {
        var tenant = Guid.Parse(tenantId);
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        await using (
            var bind = new NpgsqlCommand(
                "SELECT EXISTS(SELECT 1 FROM platform.agents a JOIN platform.endpoints e ON e.tenant_id=a.tenant_id AND e.id=a.endpoint_id WHERE a.tenant_id=$1 AND a.id=$2 AND a.endpoint_id=$3 AND a.instance_id=$4 AND a.status='active' AND e.status NOT IN('disabled','revoked'))",
                c,
                tx
            )
        )
        {
            bind.Parameters.AddWithValue(tenant);
            bind.Parameters.AddWithValue(batch.AgentId);
            bind.Parameters.AddWithValue(batch.EndpointId);
            bind.Parameters.AddWithValue(batch.InstallationId);
            if ((bool)(await bind.ExecuteScalarAsync(ct) ?? false) == false)
                throw new EnrollmentConflictException(
                    "FILE_IDENTITY_INVALID",
                    "File telemetry identity is invalid or disabled."
                );
        }
        await using (
            var cmd = new NpgsqlCommand(
                "INSERT INTO platform.file_batches(tenant_id,batch_id,endpoint_id,agent_id,installation_id,first_sequence,last_sequence,event_count,content_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
                c,
                tx
            )
        )
        {
            cmd.Parameters.AddWithValue(tenant);
            cmd.Parameters.AddWithValue(batch.BatchId);
            cmd.Parameters.AddWithValue(batch.EndpointId);
            cmd.Parameters.AddWithValue(batch.AgentId);
            cmd.Parameters.AddWithValue(batch.InstallationId);
            cmd.Parameters.AddWithValue(batch.FirstSequence);
            cmd.Parameters.AddWithValue(batch.LastSequence);
            cmd.Parameters.AddWithValue(batch.Events.Count);
            cmd.Parameters.AddWithValue(batch.ContentSha256);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        long previous = 0;
        await using (
            var cmd = new NpgsqlCommand(
                "SELECT last_sequence FROM platform.file_telemetry_health WHERE tenant_id=$1 AND endpoint_id=$2 FOR UPDATE",
                c,
                tx
            )
        )
        {
            cmd.Parameters.AddWithValue(tenant);
            cmd.Parameters.AddWithValue(batch.EndpointId);
            previous = (long?)await cmd.ExecuteScalarAsync(ct) ?? 0;
        }
        var accepted = new List<Guid>();
        var duplicates = new List<Guid>();
        var rejected = new Dictionary<Guid, string>();
        var gaps = 0;
        foreach (var item in batch.Events.OrderBy(x => x.Sequence))
        {
            if (
                item.EndpointId != batch.EndpointId
                || item.AgentId != batch.AgentId
                || item.InstallationId != batch.InstallationId
            )
            {
                rejected[item.EventId] = "identity-mismatch";
                continue;
            }
            var late = item.ObservedAt < DateTimeOffset.UtcNow.AddMinutes(-5);
            int inserted;
            await using (
                var cmd = new NpgsqlCommand(
                    "INSERT INTO platform.file_events(tenant_id,event_id,batch_id,endpoint_id,agent_id,file_entity_id,event_type,sequence,observed_at,schema_version,normalization_version,collector_type,collector_version,source_event_id,raw_sha256,trace_id,data_quality_flags,late,event_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT DO NOTHING",
                    c,
                    tx
                )
            )
            {
                cmd.Parameters.AddWithValue(tenant);
                cmd.Parameters.AddWithValue(item.EventId);
                cmd.Parameters.AddWithValue(batch.BatchId);
                cmd.Parameters.AddWithValue(item.EndpointId);
                cmd.Parameters.AddWithValue(item.AgentId);
                cmd.Parameters.AddWithValue(item.FileEntityId);
                cmd.Parameters.AddWithValue(ToDatabaseEventType(item.Kind));
                cmd.Parameters.AddWithValue(item.Sequence);
                cmd.Parameters.AddWithValue(item.ObservedAt);
                cmd.Parameters.AddWithValue(item.SchemaVersion);
                cmd.Parameters.AddWithValue(item.NormalizationVersion);
                cmd.Parameters.AddWithValue(item.CollectorType);
                cmd.Parameters.AddWithValue(item.CollectorVersion);
                cmd.Parameters.AddWithValue((object?)item.SourceEventId ?? DBNull.Value);
                cmd.Parameters.AddWithValue((object?)item.RawSha256 ?? DBNull.Value);
                cmd.Parameters.AddWithValue((object?)item.TraceId ?? DBNull.Value);
                cmd.Parameters.AddWithValue(item.DataQualityFlags);
                cmd.Parameters.AddWithValue(late);
                cmd.Parameters.Add(
                    new NpgsqlParameter
                    {
                        Value = JsonSerializer.Serialize(item, Json),
                        NpgsqlDbType = NpgsqlDbType.Jsonb,
                    }
                );
                inserted = await cmd.ExecuteNonQueryAsync(ct);
            }
            if (inserted == 0)
            {
                duplicates.Add(item.EventId);
                continue;
            }
            accepted.Add(item.EventId);
            if (previous > 0 && item.Sequence > previous + 1)
                gaps += (int)Math.Min(int.MaxValue, item.Sequence - previous - 1);
            previous = Math.Max(previous, item.Sequence);
            await UpsertEntity(c, tx, tenant, item, late, ct);
            var payload = JsonSerializer.Serialize(
                new
                {
                    tenantId,
                    eventId = item.EventId,
                    endpointId = item.EndpointId,
                    fileEntityId = item.FileEntityId,
                    operation = ToDatabaseEventType(item.Kind),
                    observedAt = item.ObservedAt,
                },
                Json
            );
            await using var outbox = new NpgsqlCommand(
                "INSERT INTO platform.outbox(id,tenant_id,topic,subject,message,trace_id) VALUES($1,$2,'file.changed','file.telemetry.v1',$3,$4)",
                c,
                tx
            );
            outbox.Parameters.AddWithValue(Guid.NewGuid());
            outbox.Parameters.AddWithValue(tenant);
            outbox.Parameters.Add(
                new NpgsqlParameter { Value = payload, NpgsqlDbType = NpgsqlDbType.Jsonb }
            );
            outbox.Parameters.AddWithValue(item.TraceId ?? string.Empty);
            await outbox.ExecuteNonQueryAsync(ct);
        }
        await using (
            var cmd = new NpgsqlCommand(
                "INSERT INTO platform.file_telemetry_health(tenant_id,endpoint_id,enabled,collector_type,collector_version,last_event_at,queue_depth,oldest_queued_seconds,dropped_events,excluded_events,source_gaps,watch_errors,journal_resets,etw_lost_events,falco_lost_events,hash_failures,signature_failures,last_upload_result,policy_version,last_sequence,hash_metrics) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET enabled=EXCLUDED.enabled,collector_type=EXCLUDED.collector_type,collector_version=EXCLUDED.collector_version,last_event_at=EXCLUDED.last_event_at,queue_depth=EXCLUDED.queue_depth,oldest_queued_seconds=EXCLUDED.oldest_queued_seconds,dropped_events=EXCLUDED.dropped_events,excluded_events=EXCLUDED.excluded_events,source_gaps=platform.file_telemetry_health.source_gaps+EXCLUDED.source_gaps,watch_errors=EXCLUDED.watch_errors,journal_resets=EXCLUDED.journal_resets,etw_lost_events=EXCLUDED.etw_lost_events,falco_lost_events=EXCLUDED.falco_lost_events,hash_failures=EXCLUDED.hash_failures,signature_failures=EXCLUDED.signature_failures,last_upload_result=EXCLUDED.last_upload_result,policy_version=EXCLUDED.policy_version,last_sequence=GREATEST(platform.file_telemetry_health.last_sequence,EXCLUDED.last_sequence),hash_metrics=EXCLUDED.hash_metrics,updated_at=now()",
                c,
                tx
            )
        )
        {
            var v = new object?[]
            {
                tenant,
                health.EndpointId,
                health.Enabled,
                health.CollectorType,
                health.CollectorVersion,
                health.LastEventAt,
                health.QueueDepth,
                health.OldestQueuedSeconds,
                health.DroppedEvents,
                health.ExcludedEvents,
                gaps + health.SourceGaps,
                health.WatchErrors,
                health.JournalResets,
                health.EtwLostEvents,
                health.FalcoLostEvents,
                health.HashFailures,
                health.SignatureFailures,
                health.LastUploadResult,
                health.PolicyVersion,
                Math.Max(previous, health.LastSequence),
                health.HashMetrics is null ? null : JsonSerializer.Serialize(health.HashMetrics, Json),
            };
            for (var i = 0; i < v.Length; i++)
                if (i == 20)
                    cmd.Parameters.Add(
                        new NpgsqlParameter
                        {
                            Value = v[i] ?? DBNull.Value,
                            NpgsqlDbType = NpgsqlDbType.Jsonb,
                        }
                    );
                else
                    cmd.Parameters.AddWithValue(v[i] ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
        return new(
            new(batch.BatchId, accepted, duplicates, rejected, previous, gaps > 0),
            accepted.Count,
            duplicates.Count,
            rejected.Count,
            gaps
        );
    }

    private static string ToDatabaseEventType(FileEventKind kind) =>
        kind switch
        {
            FileEventKind.MetadataChanged => "metadata_changed",
            _ => kind.ToString().ToLowerInvariant(),
        };

    private static async Task UpsertEntity(
        NpgsqlConnection c,
        NpgsqlTransaction tx,
        Guid tenant,
        FileObservation x,
        bool late,
        CancellationToken ct
    )
    {
        var state = x.Kind switch
        {
            FileEventKind.Deleted => FileEntityState.Deleted,
            FileEventKind.Renamed => FileEntityState.Renamed,
            FileEventKind.Moved => FileEntityState.Moved,
            _ => FileEntityState.Present,
        };
        const string sql =
            "INSERT INTO platform.file_entities(tenant_id,endpoint_id,file_entity_id,native_identity,current_path,previous_paths,first_observed,last_observed,created_at,deleted_at,state,metadata,hash_metadata,latest_process,user_name,source_confidence,latest_event_id,data_quality_flags,collector_type,collector_version) VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT(tenant_id,endpoint_id,file_entity_id) DO UPDATE SET current_path=EXCLUDED.current_path,previous_paths=CASE WHEN platform.file_entities.current_path<>EXCLUDED.current_path THEN array_append(platform.file_entities.previous_paths,platform.file_entities.current_path) ELSE platform.file_entities.previous_paths END,last_observed=EXCLUDED.last_observed,deleted_at=COALESCE(EXCLUDED.deleted_at,platform.file_entities.deleted_at),state=EXCLUDED.state,metadata=EXCLUDED.metadata,hash_metadata=CASE WHEN EXCLUDED.hash_metadata->>'state'='notRequested' THEN platform.file_entities.hash_metadata ELSE EXCLUDED.hash_metadata END,latest_process=COALESCE(EXCLUDED.latest_process,platform.file_entities.latest_process),user_name=COALESCE(EXCLUDED.user_name,platform.file_entities.user_name),latest_event_id=EXCLUDED.latest_event_id,data_quality_flags=(SELECT ARRAY(SELECT DISTINCT unnest(platform.file_entities.data_quality_flags||EXCLUDED.data_quality_flags))),collector_type=EXCLUDED.collector_type,collector_version=EXCLUDED.collector_version";
        await using var cmd = new NpgsqlCommand(sql, c, tx);
        object?[] v =
        {
            tenant,
            x.EndpointId,
            x.FileEntityId,
            JsonSerializer.Serialize(x.NativeIdentity, Json),
            x.CurrentPath,
            Array.Empty<string>(),
            x.ObservedAt,
            x.Kind == FileEventKind.Created ? x.ObservedAt : x.Metadata.CreatedAt,
            x.Kind == FileEventKind.Deleted ? x.ObservedAt : null,
            state.ToString().ToLowerInvariant(),
            JsonSerializer.Serialize(x.Metadata, Json),
            JsonSerializer.Serialize(x.Hash, Json),
            x.Process is null ? null : JsonSerializer.Serialize(x.Process, Json),
            x.UserName,
            x.SourceConfidence,
            x.EventId,
            x.DataQualityFlags.Append(late ? "late" : "").Where(y => y.Length > 0).ToArray(),
            x.CollectorType,
            x.CollectorVersion,
        };
        for (var i = 0; i < v.Length; i++)
        {
            if (i is 3 or 10 or 11 or 12)
                cmd.Parameters.Add(
                    new NpgsqlParameter
                    {
                        Value = v[i] ?? DBNull.Value,
                        NpgsqlDbType = NpgsqlDbType.Jsonb,
                    }
                );
            else
                cmd.Parameters.AddWithValue(v[i] ?? DBNull.Value);
        }
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<FilePage> SearchAsync(
        string tenantId,
        FileSearchRequest q,
        CancellationToken ct
    )
    {
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        DateTimeOffset? cursorAt = null;
        string? cursorId = null;
        if (!string.IsNullOrWhiteSpace(q.Cursor))
        {
            using var cursor = JsonDocument.Parse(TenantCursor.Unprotect(tenantId, q.Cursor));
            if (cursor.RootElement.ValueKind != JsonValueKind.Array || cursor.RootElement.GetArrayLength() != 2)
                throw new EnrollmentConflictException("CURSOR_INVALID", "File cursor is invalid.");
            cursorAt = DateTimeOffset.FromUnixTimeMilliseconds(cursor.RootElement[0].GetInt64());
            cursorId = cursor.RootElement[1].GetString();
        }
        var sql =
            "SELECT tenant_id::text,endpoint_id,file_entity_id,native_identity,current_path,previous_paths,first_observed,last_observed,created_at,deleted_at,state,metadata,hash_metadata,latest_process,user_name,source_confidence,latest_event_id,data_quality_flags,collector_type,collector_version FROM platform.file_entities WHERE tenant_id=$1 AND ($2::uuid IS NULL OR endpoint_id=$2) AND ($3='' OR current_path ILIKE '%'||$3||'%') AND ($4='' OR current_path ILIKE '%.'||$4) AND ($5='' OR hash_metadata->>'sha256'=$5) AND ($6::timestamptz IS NULL OR last_observed >= $6) AND ($7::timestamptz IS NULL OR last_observed <= $7) AND ($8='' OR EXISTS(SELECT 1 FROM unnest(previous_paths) p WHERE p ILIKE '%'||$8||'%')) AND ($9='' OR native_identity->>'fileId'=$9) AND ($10='' OR native_identity->>'volumeId'=$10) AND ($11::bigint IS NULL OR (native_identity->>'deviceId')::bigint=$11) AND ($12::bigint IS NULL OR (native_identity->>'inode')::bigint=$12) AND ($13::timestamptz IS NULL OR (last_observed,file_entity_id)<($13,$14)) ORDER BY last_observed DESC,file_entity_id DESC LIMIT $15";
        await using var cmd = new NpgsqlCommand(sql, c);
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue((object?)q.EndpointId ?? DBNull.Value);
        cmd.Parameters.AddWithValue(q.Path ?? q.FileName ?? "");
        cmd.Parameters.AddWithValue((q.Extension ?? "").TrimStart('.'));
        cmd.Parameters.AddWithValue(q.Sha256 ?? "");
        cmd.Parameters.AddWithValue((object?)q.From ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)q.To ?? DBNull.Value);
        cmd.Parameters.AddWithValue(q.PreviousPath ?? "");
        cmd.Parameters.AddWithValue(q.NativeFileId ?? "");
        cmd.Parameters.AddWithValue(q.VolumeId ?? "");
        cmd.Parameters.AddWithValue((object?)q.DeviceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)q.Inode ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)cursorAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)cursorId ?? DBNull.Value);
        cmd.Parameters.AddWithValue(Math.Clamp(q.PageSize, 1, 500));
        var list = new List<FileEntityView>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(ReadEntity(r));
        var next = list.Count == 0
            ? null
            : TenantCursor.Protect(
                tenantId,
                JsonSerializer.Serialize(
                    new object[] { list[^1].LastObserved.ToUnixTimeMilliseconds(), list[^1].FileEntityId },
                    Json
                )
            );
        return new(list, next);
    }

    public async Task<FileObservation?> GetEventAsync(
        string tenantId,
        Guid eventId,
        CancellationToken ct
    )
    {
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT event_data FROM platform.file_events WHERE tenant_id=$1 AND event_id=$2",
            c
        );
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue(eventId);
        var value = await cmd.ExecuteScalarAsync(ct);
        return value is string json
            ? JsonSerializer.Deserialize<FileObservation>(json, Json)
            : null;
    }

    public async Task<FileEntityView?> GetAsync(
        string tenantId,
        Guid endpointId,
        string id,
        CancellationToken ct
    )
    {
        var page = await SearchAsync(tenantId, new(endpointId, PageSize: 500), ct);
        return page.Items.FirstOrDefault(x => x.FileEntityId == id);
    }

    public Task<FileEventPage> HistoryAsync(
        string tenantId,
        Guid endpointId,
        string id,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    ) => Events(tenantId, endpointId, from, toInclusive, limit, "file_entity_id=$5", id, ct);

    public Task<FileEventPage> EndpointTimelineAsync(
        string tenantId,
        Guid endpointId,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    ) => Events(tenantId, endpointId, from, toInclusive, limit, "$5::text IS NULL", null, ct);

    public Task<FileEventPage> ProcessFilesAsync(
        string tenantId,
        Guid endpointId,
        string id,
        DateTimeOffset from,
        DateTimeOffset toInclusive,
        int limit,
        CancellationToken ct
    ) =>
        Events(
            tenantId,
            endpointId,
            from,
            toInclusive,
            limit,
            "event_data#>>'{process,processEntityId}'=$5",
            id,
            ct
        );

    private async Task<FileEventPage> Events(
        string tenantId,
        Guid endpointId,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        string predicate,
        string? value,
        CancellationToken ct
    )
    {
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            $"SELECT event_data FROM platform.file_events WHERE tenant_id=$1 AND endpoint_id=$2 AND observed_at BETWEEN $3 AND $4 AND {predicate} ORDER BY observed_at,event_id LIMIT $6",
            c
        );
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue(endpointId);
        cmd.Parameters.AddWithValue(from);
        cmd.Parameters.AddWithValue(to);
        cmd.Parameters.AddWithValue((object?)value ?? DBNull.Value);
        cmd.Parameters.AddWithValue(Math.Clamp(limit, 1, 500));
        var list = new List<FileObservation>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(JsonSerializer.Deserialize<FileObservation>(r.GetString(0), Json)!);
        return new(list, null);
    }

    public async Task<FileTelemetryHealth?> HealthAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT enabled,collector_type,collector_version,last_event_at,queue_depth,oldest_queued_seconds,dropped_events,excluded_events,source_gaps,watch_errors,journal_resets,etw_lost_events,falco_lost_events,hash_failures,signature_failures,last_upload_result,policy_version,last_sequence,hash_metrics::text FROM platform.file_telemetry_health WHERE tenant_id=$1 AND endpoint_id=$2",
            c
        );
        cmd.Parameters.AddWithValue(Guid.Parse(tenantId));
        cmd.Parameters.AddWithValue(endpointId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct)
            ? new(
                endpointId,
                r.GetBoolean(0),
                r.GetString(1),
                r.GetString(2),
                r.IsDBNull(3) ? null : r.GetFieldValue<DateTimeOffset>(3),
                r.GetInt64(4),
                r.GetInt64(5),
                r.GetInt64(6),
                r.GetInt64(7),
                r.GetInt64(8),
                r.GetInt64(9),
                r.GetInt64(10),
                r.GetInt64(11),
                r.GetInt64(12),
                r.GetInt64(13),
                r.GetInt64(14),
                r.GetString(15),
                r.GetString(16),
                r.GetInt64(17),
                r.IsDBNull(18) ? null : JsonSerializer.Deserialize<FileHashMetrics>(r.GetString(18), Json)
            )
            : null;
    }

    public async Task<IReadOnlyList<FileEntityView>> ListAllAsync(CancellationToken ct)
    {
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT tenant_id::text,endpoint_id,file_entity_id,native_identity,current_path,previous_paths,first_observed,last_observed,created_at,deleted_at,state,metadata,hash_metadata,latest_process,user_name,source_confidence,latest_event_id,data_quality_flags,collector_type,collector_version FROM platform.file_entities ORDER BY last_observed",
            c
        );
        var list = new List<FileEntityView>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(ReadEntity(r));
        return list;
    }

    private static FileEntityView ReadEntity(NpgsqlDataReader r) =>
        new(
            r.GetString(0),
            r.GetGuid(1),
            r.GetString(2),
            JsonSerializer.Deserialize<FileNativeIdentity>(r.GetString(3), Json)!,
            r.GetString(4),
            r.GetFieldValue<string[]>(5),
            r.GetFieldValue<DateTimeOffset>(6),
            r.GetFieldValue<DateTimeOffset>(7),
            r.IsDBNull(8) ? null : r.GetFieldValue<DateTimeOffset>(8),
            r.IsDBNull(9) ? null : r.GetFieldValue<DateTimeOffset>(9),
            Enum.Parse<FileEntityState>(r.GetString(10), true),
            JsonSerializer.Deserialize<FileMetadata>(r.GetString(11), Json)!,
            JsonSerializer.Deserialize<FileHashMetadata>(r.GetString(12), Json)!,
            r.IsDBNull(13)
                ? null
                : JsonSerializer.Deserialize<FileProcessRelationship>(r.GetString(13), Json),
            r.IsDBNull(14) ? null : r.GetString(14),
            r.GetString(15),
            r.GetGuid(16),
            r.GetFieldValue<string[]>(17),
            r.GetString(18),
            r.GetString(19)
        );

    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();
}
