using System.Data;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresRegistryTelemetryRepository(string connectionString)
    : IRegistryTelemetryRepository,
        IAsyncDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly NpgsqlDataSource _dataSource = NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(connectionString) { Pooling = true, MinPoolSize = 1, MaxPoolSize = 8, ConnectionIdleLifetime = 30, ConnectionPruningInterval = 5, Timeout = 5, CommandTimeout = 20 }.ConnectionString
    );

    public async Task<RegistryIngestResult> IngestAsync(string tenantId, RegistryEventBatch batch, RegistryTelemetryHealth health, CancellationToken ct)
    {
        var tenant = Guid.Parse(tenantId);
        await using var c = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        await using (var bind = new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM platform.agents a JOIN platform.endpoints e ON e.tenant_id=a.tenant_id AND e.id=a.endpoint_id WHERE a.tenant_id=$1 AND a.id=$2 AND a.endpoint_id=$3 AND a.instance_id=$4 AND a.status='active' AND e.status NOT IN('disabled','revoked'))", c, tx))
        {
            bind.Parameters.AddWithValue(tenant); bind.Parameters.AddWithValue(batch.AgentId); bind.Parameters.AddWithValue(batch.EndpointId); bind.Parameters.AddWithValue(batch.InstallationId);
            if ((bool)(await bind.ExecuteScalarAsync(ct) ?? false) == false) throw new EnrollmentConflictException("REGISTRY_IDENTITY_INVALID", "Registry telemetry identity is invalid or disabled.");
        }
        await using (var command = new NpgsqlCommand("INSERT INTO platform.registry_batches(tenant_id,batch_id,endpoint_id,agent_id,installation_id,first_sequence,last_sequence,event_count,content_sha256,schema_version,compression,uncompressed_bytes,compressed_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING", c, tx))
        {
            object[] v = [tenant, batch.BatchId, batch.EndpointId, batch.AgentId, batch.InstallationId, batch.FirstSequence, batch.LastSequence, batch.Events.Count, batch.ContentSha256, batch.SchemaVersion, batch.Compression, batch.UncompressedBytes, batch.CompressedBytes];
            foreach (var x in v) command.Parameters.AddWithValue(x); await command.ExecuteNonQueryAsync(ct);
        }
        long previous;
        await using (var command = new NpgsqlCommand("SELECT last_sequence FROM platform.registry_telemetry_health WHERE tenant_id=$1 AND endpoint_id=$2 FOR UPDATE", c, tx))
        { command.Parameters.AddWithValue(tenant); command.Parameters.AddWithValue(batch.EndpointId); previous = (long?)await command.ExecuteScalarAsync(ct) ?? 0; }
        var accepted = new List<Guid>(); var duplicates = new List<Guid>(); var rejected = new Dictionary<Guid, string>(); var gaps = 0;
        foreach (var sourceItem in batch.Events.OrderBy(x => x.Sequence))
        {
            var serverTime = DateTimeOffset.UtcNow;
            var item = sourceItem with { ReceivedAt = serverTime, IngestedAt = serverTime };
            if (item.EndpointId != batch.EndpointId || item.AgentId != batch.AgentId || item.InstallationId != batch.InstallationId) { rejected[item.EventId] = "identity-mismatch"; continue; }
            if (!Valid(item, out var error)) { rejected[item.EventId] = error; continue; }
            var late = item.ObservedAt < DateTimeOffset.UtcNow.AddMinutes(-5);
            int inserted;
            await using (var command = new NpgsqlCommand("INSERT INTO platform.registry_events(tenant_id,event_id,batch_id,endpoint_id,agent_id,key_entity_id,value_entity_id,event_type,sequence,observed_at,schema_version,normalization_version,collector_source,collector_version,source_event_id,raw_sha256,trace_id,policy_version,data_quality_flags,late,event_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT DO NOTHING", c, tx))
            {
                object?[] v = [tenant, item.EventId, batch.BatchId, item.EndpointId, item.AgentId, item.RegistryKeyEntityId, item.RegistryValueEntityId, DbKind(item.Kind), item.Sequence, item.ObservedAt, item.SchemaVersion, item.NormalizationVersion, item.CollectorSource, item.CollectorVersion, item.SourceEventId, item.RawSha256, item.TraceId, item.Value.PolicyVersion, item.DataQualityFlags, late, JsonSerializer.Serialize(item, Json)];
                for (var i = 0; i < v.Length; i++) if (i == 20) command.Parameters.Add(new NpgsqlParameter { Value = v[i]!, NpgsqlDbType = NpgsqlDbType.Jsonb }); else command.Parameters.AddWithValue(v[i] ?? DBNull.Value);
                inserted = await command.ExecuteNonQueryAsync(ct);
            }
            if (inserted == 0) { duplicates.Add(item.EventId); continue; }
            accepted.Add(item.EventId);
            if (previous > 0 && item.Sequence > previous + 1) gaps += (int)Math.Min(int.MaxValue, item.Sequence - previous - 1);
            previous = Math.Max(previous, item.Sequence);
            await UpsertKey(c, tx, tenant, item, late, ct);
            if (item.Kind == RegistryEventKind.KeyDeleted)
            {
                await using var deletedValues = new NpgsqlCommand("UPDATE platform.registry_value_entities SET state='deleted',deleted_at=COALESCE(deleted_at,$4),last_observed=GREATEST(last_observed,$4),latest_event_id=$5 WHERE tenant_id=$1 AND endpoint_id=$2 AND key_entity_id=$3", c, tx);
                deletedValues.Parameters.AddWithValue(tenant); deletedValues.Parameters.AddWithValue(item.EndpointId); deletedValues.Parameters.AddWithValue(item.RegistryKeyEntityId); deletedValues.Parameters.AddWithValue(item.ObservedAt); deletedValues.Parameters.AddWithValue(item.EventId); await deletedValues.ExecuteNonQueryAsync(ct);
            }
            if (item.RegistryValueEntityId is not null && item.ValueName is not null) await UpsertValue(c, tx, tenant, item, late, ct);
            await using var outbox = new NpgsqlCommand("INSERT INTO platform.outbox(id,tenant_id,topic,subject,message,trace_id) VALUES($1,$2,'registry.changed','registry.telemetry.v1',$3,$4)", c, tx);
            outbox.Parameters.AddWithValue(Guid.NewGuid()); outbox.Parameters.AddWithValue(tenant);
            outbox.Parameters.Add(new NpgsqlParameter { Value = JsonSerializer.Serialize(new { tenantId, eventId = item.EventId, endpointId = item.EndpointId, keyEntityId = item.RegistryKeyEntityId, valueEntityId = item.RegistryValueEntityId, operation = DbKind(item.Kind), observedAt = item.ObservedAt }, Json), NpgsqlDbType = NpgsqlDbType.Jsonb });
            outbox.Parameters.AddWithValue(item.TraceId ?? string.Empty); await outbox.ExecuteNonQueryAsync(ct);
        }
        var acknowledged = accepted.Count + duplicates.Count;
        var remainingQueue = Math.Max(0, health.QueueDepth - acknowledged);
        var acceptedHealth = health with
        {
            QueueDepth = remainingQueue,
            OldestQueuedSeconds = remainingQueue == 0 ? 0 : health.OldestQueuedSeconds,
        };
        await UpsertHealth(c, tx, tenant, acceptedHealth, gaps, previous, accepted.Count == 0 ? null : batch.Events.Where(x => accepted.Contains(x.EventId)).Max(x => x.ObservedAt), ct);
        await tx.CommitAsync(ct);
        return new(new(batch.BatchId, accepted, duplicates, rejected, previous, gaps > 0), accepted.Count, duplicates.Count, rejected.Count, gaps);
    }

    private static bool Valid(RegistryObservation x, out string error)
    {
        if (x.SchemaVersion != "registry-event.v1") { error = "schema-unsupported"; return false; }
        if (x.KeyPath.Length is 0 or > 2048 || x.ValueName?.Length > 512) { error = "field-limit"; return false; }
        if (x.Hive is not ("HKLM" or "HKCU" or "HKCR" or "HKU" or "HKCC" or "UNRESOLVED")) { error = "hive-invalid"; return false; }
        if (x.Value.CapturedLength > 4096 || x.Value.Preview?.Length > 4096) { error = "capture-limit"; return false; }
        if (RegistryPolicyValidation.IsProtectedPath($"{x.Hive}\\{x.KeyPath}") && (x.Value.Preview is not null || x.Value.CapturedLength > 0)) { error = "protected-content"; return false; }
        if (RegistryPolicyValidation.IsSecretLikeName(x.ValueName) && x.Value.Preview is not null) { error = "secret-preview"; return false; }
        if (x.ObservedAt < DateTimeOffset.UtcNow.AddDays(-30) || x.ObservedAt > DateTimeOffset.UtcNow.AddMinutes(5)) { error = "timestamp-invalid"; return false; }
        error = ""; return true;
    }

    private static string DbKind(RegistryEventKind k) => k switch { RegistryEventKind.KeyCreated => "key_created", RegistryEventKind.KeyDeleted => "key_deleted", RegistryEventKind.KeyRenamed => "key_renamed", RegistryEventKind.ValueSet => "value_set", RegistryEventKind.ValueDeleted => "value_deleted", _ => "key_security_changed" };
    private static string State(RegistryEventKind k) => k switch { RegistryEventKind.KeyDeleted or RegistryEventKind.ValueDeleted => "deleted", RegistryEventKind.KeyRenamed => "renamed", _ => "present" };

    private static async Task UpsertKey(NpgsqlConnection c, NpgsqlTransaction tx, Guid tenant, RegistryObservation x, bool late, CancellationToken ct)
    {
        const string sql = "INSERT INTO platform.registry_key_entities(tenant_id,endpoint_id,key_entity_id,hive,current_key_path,previous_paths,parent_key_path,first_observed,last_observed,created_at,deleted_at,state,latest_event_id,source_confidence,data_quality_flags,latest_process,user_sid) VALUES($1,$2,$3,$4,$5,'{}',$6,$7,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(tenant_id,endpoint_id,key_entity_id) DO UPDATE SET current_key_path=EXCLUDED.current_key_path,previous_paths=CASE WHEN platform.registry_key_entities.current_key_path<>EXCLUDED.current_key_path THEN array_append(platform.registry_key_entities.previous_paths,platform.registry_key_entities.current_key_path) ELSE platform.registry_key_entities.previous_paths END,parent_key_path=EXCLUDED.parent_key_path,last_observed=GREATEST(platform.registry_key_entities.last_observed,EXCLUDED.last_observed),deleted_at=COALESCE(EXCLUDED.deleted_at,platform.registry_key_entities.deleted_at),state=EXCLUDED.state,latest_event_id=EXCLUDED.latest_event_id,data_quality_flags=(SELECT ARRAY(SELECT DISTINCT unnest(platform.registry_key_entities.data_quality_flags||EXCLUDED.data_quality_flags))),latest_process=COALESCE(EXCLUDED.latest_process,platform.registry_key_entities.latest_process),user_sid=COALESCE(EXCLUDED.user_sid,platform.registry_key_entities.user_sid)";
        await using var command = new NpgsqlCommand(sql, c, tx); object?[] v = [tenant, x.EndpointId, x.RegistryKeyEntityId, x.Hive, x.DestinationKeyPath ?? x.KeyPath, x.ParentKeyPath, x.ObservedAt, x.Kind == RegistryEventKind.KeyCreated ? x.ObservedAt : null, x.Kind == RegistryEventKind.KeyDeleted ? x.ObservedAt : null, State(x.Kind), x.EventId, x.SourceConfidence, x.DataQualityFlags.Append(late ? "late" : "").Where(y => y.Length > 0).ToArray(), x.Process is null ? null : JsonSerializer.Serialize(x.Process, Json), x.UserSid];
        for (var i = 0; i < v.Length; i++) if (i == 13) command.Parameters.Add(new NpgsqlParameter { Value = v[i] ?? DBNull.Value, NpgsqlDbType = NpgsqlDbType.Jsonb }); else command.Parameters.AddWithValue(v[i] ?? DBNull.Value); await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task UpsertValue(NpgsqlConnection c, NpgsqlTransaction tx, Guid tenant, RegistryObservation x, bool late, CancellationToken ct)
    {
        const string sql = "INSERT INTO platform.registry_value_entities(tenant_id,endpoint_id,value_entity_id,key_entity_id,hive,key_path,value_name,value_metadata,first_observed,last_observed,created_at,deleted_at,state,latest_event_id,source_confidence,data_quality_flags,latest_process,user_sid) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,NULL,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(tenant_id,endpoint_id,value_entity_id) DO UPDATE SET value_metadata=EXCLUDED.value_metadata,last_observed=GREATEST(platform.registry_value_entities.last_observed,EXCLUDED.last_observed),deleted_at=COALESCE(EXCLUDED.deleted_at,platform.registry_value_entities.deleted_at),state=EXCLUDED.state,latest_event_id=EXCLUDED.latest_event_id,data_quality_flags=(SELECT ARRAY(SELECT DISTINCT unnest(platform.registry_value_entities.data_quality_flags||EXCLUDED.data_quality_flags))),latest_process=COALESCE(EXCLUDED.latest_process,platform.registry_value_entities.latest_process),user_sid=COALESCE(EXCLUDED.user_sid,platform.registry_value_entities.user_sid)";
        await using var command = new NpgsqlCommand(sql, c, tx); object?[] v = [tenant, x.EndpointId, x.RegistryValueEntityId!, x.RegistryKeyEntityId, x.Hive, x.KeyPath, x.ValueName!, JsonSerializer.Serialize(x.Value, Json), x.ObservedAt, x.Kind == RegistryEventKind.ValueDeleted ? x.ObservedAt : null, State(x.Kind), x.EventId, x.SourceConfidence, x.DataQualityFlags.Append(late ? "late" : "").Where(y => y.Length > 0).ToArray(), x.Process is null ? null : JsonSerializer.Serialize(x.Process, Json), x.UserSid];
        for (var i = 0; i < v.Length; i++) if (i is 7 or 14) command.Parameters.Add(new NpgsqlParameter { Value = v[i] ?? DBNull.Value, NpgsqlDbType = NpgsqlDbType.Jsonb }); else command.Parameters.AddWithValue(v[i] ?? DBNull.Value); await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task UpsertHealth(NpgsqlConnection c, NpgsqlTransaction tx, Guid tenant, RegistryTelemetryHealth h, int gaps, long previous, DateTimeOffset? accepted, CancellationToken ct)
    {
        const string sql = "INSERT INTO platform.registry_telemetry_health(tenant_id,endpoint_id,enabled,collector_source,collector_version,last_source_event,last_accepted_event,queue_depth,oldest_queued_seconds,dropped_events,excluded_events,source_losses,sequence_gaps,handle_resolution_failures,path_resolution_failures,capture_attempts,capture_skips,capture_failures,redacted_values,last_upload_result,policy_version,applied_version,drift,last_upload,last_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25) ON CONFLICT(tenant_id,endpoint_id) DO UPDATE SET enabled=EXCLUDED.enabled,collector_source=EXCLUDED.collector_source,collector_version=EXCLUDED.collector_version,last_source_event=EXCLUDED.last_source_event,last_accepted_event=COALESCE(EXCLUDED.last_accepted_event,platform.registry_telemetry_health.last_accepted_event),queue_depth=EXCLUDED.queue_depth,oldest_queued_seconds=EXCLUDED.oldest_queued_seconds,dropped_events=EXCLUDED.dropped_events,excluded_events=EXCLUDED.excluded_events,source_losses=EXCLUDED.source_losses,sequence_gaps=platform.registry_telemetry_health.sequence_gaps+EXCLUDED.sequence_gaps,handle_resolution_failures=EXCLUDED.handle_resolution_failures,path_resolution_failures=EXCLUDED.path_resolution_failures,capture_attempts=EXCLUDED.capture_attempts,capture_skips=EXCLUDED.capture_skips,capture_failures=EXCLUDED.capture_failures,redacted_values=EXCLUDED.redacted_values,last_upload_result=EXCLUDED.last_upload_result,policy_version=EXCLUDED.policy_version,applied_version=EXCLUDED.applied_version,drift=EXCLUDED.drift,last_upload=EXCLUDED.last_upload,last_sequence=GREATEST(platform.registry_telemetry_health.last_sequence,EXCLUDED.last_sequence),updated_at=now()";
        await using var command = new NpgsqlCommand(sql, c, tx); object?[] v = [tenant, h.EndpointId, h.Enabled, h.CollectorSource, h.CollectorVersion, h.LastSourceEvent, accepted ?? h.LastAcceptedEvent, h.QueueDepth, h.OldestQueuedSeconds, h.DroppedEvents, h.ExcludedEvents, h.SourceLosses, gaps + h.SequenceGaps, h.HandleResolutionFailures, h.PathResolutionFailures, h.CaptureAttempts, h.CaptureSkips, h.CaptureFailures, h.RedactedValues, h.LastUploadResult, h.PolicyVersion, h.AppliedVersion, h.Drift, h.LastUpload, Math.Max(previous, h.LastSequence)]; foreach (var x in v) command.Parameters.AddWithValue(x ?? DBNull.Value); await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<RegistryEventPage> SearchAsync(string tenantId, RegistrySearchRequest q, CancellationToken ct)
    {
        DateTimeOffset? cursorAt = null; Guid? cursorId = null;
        if (!string.IsNullOrWhiteSpace(q.Cursor)) { using var d = JsonDocument.Parse(TenantCursor.Unprotect(tenantId, q.Cursor)); if (d.RootElement.ValueKind != JsonValueKind.Array || d.RootElement.GetArrayLength() != 2) throw new EnrollmentConflictException("CURSOR_INVALID", "Registry cursor is invalid."); cursorAt = DateTimeOffset.FromUnixTimeMilliseconds(d.RootElement[0].GetInt64()); cursorId = d.RootElement[1].GetGuid(); }
        const string sql = "SELECT event_data FROM platform.registry_events WHERE tenant_id=$1 AND ($2::uuid IS NULL OR endpoint_id=$2) AND ($3::timestamptz IS NULL OR observed_at >= $3) AND ($4::timestamptz IS NULL OR observed_at <= $4) AND ($5='' OR event_data->>'hive'=$5) AND ($6='' OR event_data->>'keyPath' ILIKE '%'||$6||'%') AND ($7='' OR event_data->>'valueName' ILIKE '%'||$7||'%') AND ($8='' OR event_type=$8) AND ($9='' OR event_data#>>'{process,processEntityId}'=$9 OR event_data#>>'{process,image}' ILIKE '%'||$9||'%') AND ($10='' OR event_data->>'userSid'=$10) AND ($11='' OR event_data#>>'{value,valueType}'=$11) AND ($12='' OR event_data->>'collectorSource'=$12) AND ($13='' OR $13=ANY(data_quality_flags)) AND ($14='' OR event_data#>>'{value,sha256}'=$14) AND ($15::timestamptz IS NULL OR (observed_at,event_id)<($15,$16)) ORDER BY observed_at DESC,event_id DESC LIMIT $17";
        await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand(sql, c); object?[] v = [Guid.Parse(tenantId), q.EndpointId, q.From, q.To, q.Hive ?? "", q.KeyPath ?? "", q.ValueName ?? "", q.Operation is null ? "" : DbKind(q.Operation.Value), q.Process ?? "", q.User ?? "", q.ValueType ?? "", q.Collector ?? "", q.DataQuality ?? "", q.ContentHash ?? "", cursorAt, cursorId, Math.Clamp(q.PageSize, 1, 500)]; foreach (var x in v) command.Parameters.AddWithValue(x ?? DBNull.Value);
        var list = new List<RegistryObservation>(); await using var r = await command.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) list.Add(JsonSerializer.Deserialize<RegistryObservation>(r.GetString(0), Json)!);
        var next = list.Count == 0 ? null : TenantCursor.Protect(tenantId, JsonSerializer.Serialize(new object[] { list[^1].ObservedAt.ToUnixTimeMilliseconds(), list[^1].EventId }, Json)); return new(list, next);
    }

    public async Task<RegistryObservation?> GetEventAsync(string tenantId, Guid id, CancellationToken ct) => await OneEvent("event_id=$2::uuid", tenantId, id.ToString(), ct);
    private async Task<RegistryObservation?> OneEvent(string predicate, string tenant, string value, CancellationToken ct) { await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand($"SELECT event_data FROM platform.registry_events WHERE tenant_id=$1 AND {predicate} LIMIT 1", c); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(value); var result = await command.ExecuteScalarAsync(ct); return result is null ? null : JsonSerializer.Deserialize<RegistryObservation>((string)result, Json); }
    public async Task<RegistryKeyView?> GetKeyAsync(string tenant, Guid endpoint, string id, CancellationToken ct) { await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("SELECT tenant_id::text,endpoint_id,key_entity_id,hive,current_key_path,previous_paths,parent_key_path,first_observed,last_observed,created_at,deleted_at,state,latest_event_id,source_confidence,data_quality_flags,latest_process,user_sid FROM platform.registry_key_entities WHERE tenant_id=$1 AND endpoint_id=$2 AND key_entity_id=$3", c); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(endpoint); command.Parameters.AddWithValue(id); await using var r = await command.ExecuteReaderAsync(ct); return await r.ReadAsync(ct) ? ReadKey(r) : null; }
    public async Task<RegistryValueView?> GetValueAsync(string tenant, Guid endpoint, string id, CancellationToken ct) { await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("SELECT tenant_id::text,endpoint_id,value_entity_id,key_entity_id,hive,key_path,value_name,value_metadata,first_observed,last_observed,created_at,deleted_at,state,latest_event_id,source_confidence,data_quality_flags,latest_process,user_sid FROM platform.registry_value_entities WHERE tenant_id=$1 AND endpoint_id=$2 AND value_entity_id=$3", c); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(endpoint); command.Parameters.AddWithValue(id); await using var r = await command.ExecuteReaderAsync(ct); return await r.ReadAsync(ct) ? ReadValue(r) : null; }
    private static RegistryKeyView ReadKey(NpgsqlDataReader r) => new(r.GetString(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetFieldValue<string[]>(5), r.IsDBNull(6) ? null : r.GetString(6), r.GetFieldValue<DateTimeOffset>(7), r.GetFieldValue<DateTimeOffset>(8), r.IsDBNull(9) ? null : r.GetFieldValue<DateTimeOffset>(9), r.IsDBNull(10) ? null : r.GetFieldValue<DateTimeOffset>(10), Enum.Parse<RegistryEntityState>(r.GetString(11), true), r.GetGuid(12), r.GetString(13), r.GetFieldValue<string[]>(14), r.IsDBNull(15) ? null : JsonSerializer.Deserialize<RegistryProcessRelationship>(r.GetString(15), Json), r.IsDBNull(16) ? null : r.GetString(16));
    private static RegistryValueView ReadValue(NpgsqlDataReader r) => new(r.GetString(0), r.GetGuid(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), JsonSerializer.Deserialize<RegistryValueMetadata>(r.GetString(7), Json)!, r.GetFieldValue<DateTimeOffset>(8), r.GetFieldValue<DateTimeOffset>(9), r.IsDBNull(10) ? null : r.GetFieldValue<DateTimeOffset>(10), r.IsDBNull(11) ? null : r.GetFieldValue<DateTimeOffset>(11), Enum.Parse<RegistryEntityState>(r.GetString(12), true), r.GetGuid(13), r.GetString(14), r.GetFieldValue<string[]>(15), r.IsDBNull(16) ? null : JsonSerializer.Deserialize<RegistryProcessRelationship>(r.GetString(16), Json), r.IsDBNull(17) ? null : r.GetString(17));
    public Task<RegistryEventPage> KeyHistoryAsync(string tenant, Guid endpoint, string id, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, "key_entity_id=$5", id, ct);
    public Task<RegistryEventPage> ValueHistoryAsync(string tenant, Guid endpoint, string id, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, "value_entity_id=$5", id, ct);
    public Task<RegistryEventPage> ProcessRegistryAsync(string tenant, Guid endpoint, string id, DateTimeOffset from, DateTimeOffset to, int limit, CancellationToken ct) => History(tenant, endpoint, from, to, limit, "event_data#>>'{process,processEntityId}'=$5", id, ct);
    private async Task<RegistryEventPage> History(string tenant, Guid endpoint, DateTimeOffset from, DateTimeOffset to, int limit, string predicate, string id, CancellationToken ct) { await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand($"SELECT event_data FROM platform.registry_events WHERE tenant_id=$1 AND endpoint_id=$2 AND observed_at BETWEEN $3 AND $4 AND {predicate} ORDER BY observed_at,event_id LIMIT $6", c); object[] v = [Guid.Parse(tenant), endpoint, from, to, id, Math.Clamp(limit, 1, 500)]; foreach (var x in v) command.Parameters.AddWithValue(x); var list = new List<RegistryObservation>(); await using var r = await command.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) list.Add(JsonSerializer.Deserialize<RegistryObservation>(r.GetString(0), Json)!); return new(list, null); }
    public Task<RegistryEventPage> EndpointTimelineAsync(string tenant, Guid endpoint, RegistrySearchRequest request, CancellationToken ct) => SearchAsync(tenant, request with { EndpointId = endpoint }, ct);
    public async Task<RegistryTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct) { await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("SELECT enabled,collector_source,collector_version,last_source_event,last_accepted_event,queue_depth,oldest_queued_seconds,dropped_events,excluded_events,source_losses,sequence_gaps,handle_resolution_failures,path_resolution_failures,capture_attempts,capture_skips,capture_failures,redacted_values,last_upload_result,policy_version,applied_version,drift,last_upload,last_sequence FROM platform.registry_telemetry_health WHERE tenant_id=$1 AND endpoint_id=$2", c); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(endpoint); await using var r = await command.ExecuteReaderAsync(ct); return await r.ReadAsync(ct) ? new(endpoint, r.GetBoolean(0), r.GetString(1), r.GetString(2), r.IsDBNull(3) ? null : r.GetFieldValue<DateTimeOffset>(3), r.IsDBNull(4) ? null : r.GetFieldValue<DateTimeOffset>(4), r.GetInt64(5), r.GetInt64(6), r.GetInt64(7), r.GetInt64(8), r.GetInt64(9), r.GetInt64(10), r.GetInt64(11), r.GetInt64(12), r.GetInt64(13), r.GetInt64(14), r.GetInt64(15), r.GetInt64(16), r.GetString(17), r.GetString(18), r.IsDBNull(19) ? null : r.GetInt32(19), r.GetBoolean(20), r.IsDBNull(21) ? null : r.GetFieldValue<DateTimeOffset>(21), r.GetInt64(22)) : null; }
    public async Task<IReadOnlyList<RegistryObservation>> ListAllAsync(CancellationToken ct) { await using var c = await _dataSource.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("SELECT tenant_id::text,event_data FROM platform.registry_events ORDER BY observed_at,event_id", c); var list = new List<RegistryObservation>(); await using var r = await command.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) { var value = JsonSerializer.Deserialize<RegistryObservation>(r.GetString(1), Json)!; list.Add(value with { CorrelationId = $"tenant:{r.GetString(0)}" }); } return list; }
    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();
}
