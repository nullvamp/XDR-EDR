using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresThreatIntelligenceRepository(string connectionString) : IThreatIntelligenceRepository, IThreatBackmatchProcessor, IDisposable
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<IntelligenceSource> CreateSourceAsync(string tenant, IntelligenceSource source, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var value = await memory.CreateSourceAsync(tenant, source, actor, ct); await InsertSourceAsync(value, actor, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<IReadOnlyList<IntelligenceSource>> SourcesAsync(string tenant, CancellationToken ct) => await (await LoadAsync(tenant, ct)).SourcesAsync(tenant, ct);
    public async Task<ThreatIndicator> AddAsync(string tenant, ThreatIndicatorInput input, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var value = await memory.AddAsync(tenant, input, actor, ct); await InsertIndicatorAsync(value, actor, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<ThreatImportResult> ImportAsync(string tenant, Guid sourceId, string format, Stream content, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try
        {
            byte[]? stix = null;
            if (format is "stix" or "stix2")
            {
                await using var copy = new MemoryStream(); await content.CopyToAsync(copy, ct);
                stix = copy.ToArray(); content = new MemoryStream(stix, false);
            }
            var memory = await LoadAsync(tenant, ct); var before = memory.SnapshotIndicators(tenant).Select(x => (x.IndicatorId, x.Version)).ToHashSet(); var result = await memory.ImportAsync(tenant, sourceId, format, content, actor, ct);
            var after = memory.SnapshotIndicators(tenant); foreach (var value in after.Where(x => !before.Contains((x.IndicatorId, x.Version)))) await InsertIndicatorAsync(value, actor, ct);
            await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand("INSERT INTO platform.threat_imports(tenant_id,import_id,source_id,format,import_data) VALUES($1,$2,$3,$4,$5)", c); Add(cmd, Guid.Parse(tenant), result.ImportId, sourceId, format); AddJson(cmd, result); await cmd.ExecuteNonQueryAsync(ct);
            if (stix is not null)
                foreach (var relationship in ThreatImportParser.Relationships(tenant, sourceId, System.Text.Encoding.UTF8.GetString(stix)))
                {
                    await using var relationshipCommand = new NpgsqlCommand("INSERT INTO platform.threat_relationships(tenant_id,relationship_id,source_record_id,target_record_id,relationship_type,source_id,relationship_data) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING", c); Add(relationshipCommand, Guid.Parse(tenant), relationship.RelationshipId, relationship.SourceRecordId, relationship.TargetRecordId, relationship.RelationshipType, sourceId); AddJson(relationshipCommand, relationship); await relationshipCommand.ExecuteNonQueryAsync(ct);
                }
            return result;
        }
        finally { _gate.Release(); }
    }
    public async Task<ThreatPage<ThreatIndicator>> SearchAsync(string tenant, ThreatSearchRequest query, CancellationToken ct) => await (await LoadAsync(tenant, ct)).SearchAsync(tenant, query, ct);
    public async Task<ThreatIndicator?> GetAsync(string tenant, Guid id, int? version, CancellationToken ct) => await (await LoadAsync(tenant, ct)).GetAsync(tenant, id, version, ct);
    public async Task<ThreatIndicator> SetStateAsync(string tenant, Guid id, bool? revoked, DateTimeOffset? validUntil, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var value = await memory.SetStateAsync(tenant, id, revoked, validUntil, actor, ct); await InsertIndicatorAsync(value, actor, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<IReadOnlyList<ThreatMatch>> MatchAsync(string tenant, IReadOnlyList<ThreatEvidence> evidence, ThreatMatchMode mode, CancellationToken ct)
    {
        if (evidence.Count > 256) throw new EnrollmentConflictException("INTEL_MATCH_BOUNDS", "At most 256 semantic evidence candidates are accepted per event.");
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var values = await memory.MatchAsync(tenant, evidence, mode, ct); foreach (var value in values) await InsertMatchAsync(value, ct); return values; } finally { _gate.Release(); }
    }
    public async Task<ThreatPage<ThreatMatch>> SearchMatchesAsync(string tenant, ThreatMatchSearchRequest query, CancellationToken ct) => await (await LoadAsync(tenant, ct)).SearchMatchesAsync(tenant, query, ct);
    public async Task<ThreatExclusion> AddExclusionAsync(string tenant, ThreatExclusion exclusion, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var value = await memory.AddExclusionAsync(tenant, exclusion, actor, ct); await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand("INSERT INTO platform.threat_exclusions(tenant_id,exclusion_id,version,exclusion_data) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", c); Add(cmd, Guid.Parse(tenant), value.ExclusionId, value.Version); AddJson(cmd, value); await cmd.ExecuteNonQueryAsync(ct); await AuditAsync(c, tenant, "exclusion", value.ExclusionId.ToString("D"), "created", actor, value, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<IReadOnlyList<ThreatExclusion>> ExclusionsAsync(string tenant, CancellationToken ct) => await (await LoadAsync(tenant, ct)).ExclusionsAsync(tenant, ct);
    public async Task<ThreatBackmatchJob> QueueBackmatchAsync(string tenant, Guid indicatorId, int version, DateTimeOffset from, DateTimeOffset until, ThreatMatchMode mode, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var value = await memory.QueueBackmatchAsync(tenant, indicatorId, version, from, until, mode, actor, ct); await UpsertJobAsync(value, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<ThreatBackmatchJob?> GetJobAsync(string tenant, Guid jobId, CancellationToken ct) => await (await LoadAsync(tenant, ct)).GetJobAsync(tenant, jobId, ct);
    public async Task<ThreatBackmatchJob?> CancelJobAsync(string tenant, Guid jobId, string actor, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); try { var memory = await LoadAsync(tenant, ct); var value = await memory.CancelJobAsync(tenant, jobId, actor, ct); if (value is not null) await UpsertJobAsync(value, ct); return value; } finally { _gate.Release(); }
    }
    public async Task<ThreatHealth> HealthAsync(string tenant, CancellationToken ct)
    {
        await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand("WITH latest AS (SELECT DISTINCT ON(indicator_id) indicator_id,revoked,valid_until FROM platform.threat_indicators WHERE tenant_id=$1 ORDER BY indicator_id,version DESC) SELECT (SELECT count(DISTINCT source_id) FROM platform.intelligence_sources WHERE tenant_id=$1),(SELECT count(*) FROM latest WHERE NOT revoked AND (valid_until IS NULL OR valid_until>now())),(SELECT count(*) FROM latest WHERE NOT revoked AND valid_until<=now()),(SELECT count(*) FROM latest WHERE revoked),(SELECT count(*) FROM platform.threat_imports WHERE tenant_id=$1),(SELECT count(*) FROM platform.threat_matches WHERE tenant_id=$1),(SELECT count(*) FROM platform.threat_matches WHERE tenant_id=$1 AND (match_data->>'excluded')::boolean),(SELECT count(*) FROM platform.threat_match_jobs WHERE tenant_id=$1)", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await cmd.ExecuteReaderAsync(ct); await r.ReadAsync(ct); return new(r.GetInt64(0), r.GetInt64(1), r.GetInt64(2), r.GetInt64(3), r.GetInt64(4), 0, r.GetInt64(5), r.GetInt64(6), r.GetInt64(7), 0, 0, 0, DateTimeOffset.UtcNow);
    }
    public async Task<(long IndicatorVersions, long Matches)> CountsAsync(string tenant, CancellationToken ct) { await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand("SELECT (SELECT count(*) FROM platform.threat_indicators WHERE tenant_id=$1),(SELECT count(*) FROM platform.threat_matches WHERE tenant_id=$1)", c); cmd.Parameters.AddWithValue(Guid.Parse(tenant)); await using var r = await cmd.ExecuteReaderAsync(ct); await r.ReadAsync(ct); return (r.GetInt64(0), r.GetInt64(1)); }

    public async Task<bool> ProcessNextAsync(CancellationToken ct)
    {
        ThreatBackmatchJob? job = null;
        await using (var c = await OpenAsync(ct))
        await using (var tx = await c.BeginTransactionAsync(ct))
        {
            await using var cmd = new NpgsqlCommand("SELECT job_data FROM platform.threat_match_jobs WHERE job_state='Queued' ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT 1", c, tx);
            var raw = await cmd.ExecuteScalarAsync(ct) as string; if (raw is null) { await tx.RollbackAsync(ct); return false; }
            job = JsonSerializer.Deserialize<ThreatBackmatchJob>(raw, Json)!; var running = job with { State = ThreatJobState.Running, ProgressPercent = 1, UpdatedAt = DateTimeOffset.UtcNow }; await UpdateJobAsync(c, tx, running, ct); await tx.CommitAsync(ct); job = running;
        }
        try
        {
            var indicator = await GetAsync(job.TenantId, job.IndicatorId, job.IndicatorVersion, ct) ?? throw new InvalidOperationException("Pinned indicator version is missing.");
            var candidates = await HistoricalEvidenceAsync(job, ct); long scanned = candidates.Count, matched = 0;
            foreach (var evidence in candidates)
            {
                ct.ThrowIfCancellationRequested(); if (!ThreatIntelligenceSafety.Matches(indicator, evidence)) continue;
                var id = ThreatIntelligenceSafety.StableId(job.TenantId, indicator.IndicatorId.ToString("D"), indicator.Version.ToString(System.Globalization.CultureInfo.InvariantCulture), evidence.EventId.ToString("D"), evidence.Field, job.Mode.ToString());
                var value = new ThreatMatch(id, job.TenantId, indicator.IndicatorId, indicator.Version, indicator.SourceId, evidence.EventId, evidence.EntityId, evidence.EndpointId, evidence.ProcessEntityId, evidence.Field, ThreatIntelligenceSafety.Normalize(evidence.Type, evidence.Value), indicator.Type, evidence.ObservedAt, evidence.ObservedAt, indicator.Confidence, evidence.Quality, job.Mode, ThreatIntelligenceSafety.EngineVersion, evidence.EvidenceReference, false, null, DateTimeOffset.UtcNow); await InsertMatchAsync(value, ct); matched++;
            }
            var completed = job with { State = ThreatJobState.Completed, Scanned = scanned, Matched = matched, ProgressPercent = 100, UpdatedAt = DateTimeOffset.UtcNow }; await UpsertJobAsync(completed, ct); return true;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            var failed = job with { State = ThreatJobState.Failed, Error = e.GetType().Name, UpdatedAt = DateTimeOffset.UtcNow }; await UpsertJobAsync(failed, CancellationToken.None); return true;
        }
    }

    async Task<List<ThreatEvidence>> HistoricalEvidenceAsync(ThreatBackmatchJob job, CancellationToken ct)
    {
        const string sql = "SELECT 'file',event_data::text FROM platform.file_events WHERE tenant_id=$1 AND observed_at>=$2 AND observed_at<$3 UNION ALL SELECT 'network',event_data::text FROM platform.network_events WHERE tenant_id=$1 AND observed_at>=$2 AND observed_at<$3 UNION ALL SELECT 'dns',event_data::text FROM platform.dns_events WHERE tenant_id=$1 AND observed_at>=$2 AND observed_at<$3 UNION ALL SELECT 'module',event_data::text FROM platform.module_events WHERE tenant_id=$1 AND observed_at>=$2 AND observed_at<$3 ORDER BY 1 LIMIT 100001";
        await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand(sql, c); Add(cmd, Guid.Parse(job.TenantId), job.From, job.To); await using var r = await cmd.ExecuteReaderAsync(ct); var values = new List<ThreatEvidence>(); while (await r.ReadAsync(ct))
        {
            var kind = r.GetString(0); var raw = r.GetString(1); IReadOnlyList<ThreatEvidence> mapped = kind switch { "file" => ThreatEvidenceMapper.FromFile(JsonSerializer.Deserialize<FileObservation>(raw, Json)!, $"postgresql://platform/file_events/{JsonDocument.Parse(raw).RootElement.GetProperty("eventId").GetGuid():D}"), "network" => ThreatEvidenceMapper.FromNetwork(JsonSerializer.Deserialize<NetworkObservation>(raw, Json)!, $"postgresql://platform/network_events/{JsonDocument.Parse(raw).RootElement.GetProperty("eventId").GetGuid():D}"), "dns" => ThreatEvidenceMapper.FromDns(JsonSerializer.Deserialize<DnsObservation>(raw, Json)!, $"postgresql://platform/dns_events/{JsonDocument.Parse(raw).RootElement.GetProperty("eventId").GetGuid():D}"), "module" => ThreatEvidenceMapper.FromModule(JsonSerializer.Deserialize<ModuleObservation>(raw, Json)!, $"postgresql://platform/module_events/{JsonDocument.Parse(raw).RootElement.GetProperty("eventId").GetGuid():D}"), _ => [] }; values.AddRange(mapped);
        }
        if (values.Count > 100_000) throw new EnrollmentConflictException("INTEL_BACKMATCH_EVENT_LIMIT", "Historical backmatch exceeds the 100,000 evidence-candidate bound; narrow the time range."); return values;
    }

    static async Task UpdateJobAsync(NpgsqlConnection c, NpgsqlTransaction tx, ThreatBackmatchJob value, CancellationToken ct) { await using var cmd = new NpgsqlCommand("UPDATE platform.threat_match_jobs SET job_state=$3,job_data=$4,updated_at=$5 WHERE tenant_id=$1 AND job_id=$2", c, tx); Add(cmd, Guid.Parse(value.TenantId), value.JobId, value.State.ToString()); AddJson(cmd, value); cmd.Parameters.AddWithValue(value.UpdatedAt); await cmd.ExecuteNonQueryAsync(ct); }

    async Task<FileThreatIntelligenceRepository> LoadAsync(string tenant, CancellationToken ct)
    {
        await using var c = await OpenAsync(ct); var id = Guid.Parse(tenant);
        var sources = await ReadAsync<IntelligenceSource>(c, "SELECT source_data FROM platform.intelligence_sources WHERE tenant_id=$1", id, ct);
        var indicators = await ReadAsync<ThreatIndicator>(c, "SELECT indicator_data FROM platform.threat_indicators WHERE tenant_id=$1", id, ct);
        var matches = await ReadAsync<ThreatMatch>(c, "SELECT match_data FROM platform.threat_matches WHERE tenant_id=$1", id, ct);
        var exclusions = await ReadAsync<ThreatExclusion>(c, "SELECT exclusion_data FROM platform.threat_exclusions WHERE tenant_id=$1", id, ct);
        var jobs = await ReadAsync<ThreatBackmatchJob>(c, "SELECT job_data FROM platform.threat_match_jobs WHERE tenant_id=$1", id, ct);
        return new(sources, indicators, matches, exclusions, jobs);
    }
    async Task InsertSourceAsync(IntelligenceSource value, string actor, CancellationToken ct) { await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand("INSERT INTO platform.intelligence_sources(tenant_id,source_id,version,source_data) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", c); Add(cmd, Guid.Parse(value.TenantId), value.SourceId, value.Version); AddJson(cmd, value); await cmd.ExecuteNonQueryAsync(ct); await AuditAsync(c, value.TenantId, "source", value.SourceId.ToString("D"), "created", actor, value, ct); }
    async Task InsertIndicatorAsync(ThreatIndicator value, string actor, CancellationToken ct) { await using var c = await OpenAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); await using (var cmd = new NpgsqlCommand("INSERT INTO platform.threat_indicators(tenant_id,indicator_id,version,source_id,indicator_type,canonical_value,valid_from,valid_until,revoked,indicator_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING", c, tx)) { Add(cmd, Guid.Parse(value.TenantId), value.IndicatorId, value.Version, value.SourceId, value.Type.ToString(), value.CanonicalValue, value.ValidFrom, value.ValidUntil, value.Revoked); AddJson(cmd, value); await cmd.ExecuteNonQueryAsync(ct); } await OutboxAsync(c, tx, value.TenantId, "threat.indicator.changed.v1", new { value.IndicatorId, value.Version }, ct); await AuditAsync(c, value.TenantId, "indicator", value.IndicatorId.ToString("D"), "version-created", actor, value, ct, tx); await tx.CommitAsync(ct); }
    async Task InsertMatchAsync(ThreatMatch value, CancellationToken ct) { await using var c = await OpenAsync(ct); await using var tx = await c.BeginTransactionAsync(ct); int inserted; await using (var cmd = new NpgsqlCommand("INSERT INTO platform.threat_matches(tenant_id,match_id,indicator_id,indicator_version,evidence_event_id,endpoint_id,match_mode,match_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING", c, tx)) { Add(cmd, Guid.Parse(value.TenantId), value.MatchId, value.IndicatorId, value.IndicatorVersion, value.EvidenceEventId, value.EndpointId, value.Mode.ToString()); AddJson(cmd, value); inserted = await cmd.ExecuteNonQueryAsync(ct); } if (inserted > 0) await OutboxAsync(c, tx, value.TenantId, "threat.match.changed.v1", new { value.MatchId }, ct); await tx.CommitAsync(ct); }
    async Task UpsertJobAsync(ThreatBackmatchJob value, CancellationToken ct) { await using var c = await OpenAsync(ct); await using var cmd = new NpgsqlCommand("INSERT INTO platform.threat_match_jobs(tenant_id,job_id,indicator_id,indicator_version,job_state,job_data,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,job_id) DO UPDATE SET job_state=excluded.job_state,job_data=excluded.job_data,updated_at=excluded.updated_at", c); Add(cmd, Guid.Parse(value.TenantId), value.JobId, value.IndicatorId, value.IndicatorVersion, value.State.ToString()); AddJson(cmd, value); cmd.Parameters.AddWithValue(value.UpdatedAt); await cmd.ExecuteNonQueryAsync(ct); }
    async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { var c = new NpgsqlConnection(connectionString); await c.OpenAsync(ct); return c; }
    static async Task<List<T>> ReadAsync<T>(NpgsqlConnection c, string sql, Guid tenant, CancellationToken ct) { await using var cmd = new NpgsqlCommand(sql, c); cmd.Parameters.AddWithValue(tenant); await using var r = await cmd.ExecuteReaderAsync(ct); var values = new List<T>(); while (await r.ReadAsync(ct)) if (JsonSerializer.Deserialize<T>(r.GetString(0), Json) is { } value) values.Add(value); return values; }
    static void Add(NpgsqlCommand cmd, params object?[] values) { foreach (var value in values) cmd.Parameters.AddWithValue(value ?? DBNull.Value); }
    static void AddJson<T>(NpgsqlCommand cmd, T value) => cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(value, Json) });
    static async Task OutboxAsync(NpgsqlConnection c, NpgsqlTransaction tx, string tenant, string type, object data, CancellationToken ct) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.outbox(id,tenant_id,topic,subject,message,trace_id) VALUES($1,$2,$3,$4,$5,'')", c, tx); var id = Guid.NewGuid(); Add(cmd, id, Guid.Parse(tenant), type[..type.LastIndexOf('.')], type); AddJson(cmd, data); await cmd.ExecuteNonQueryAsync(ct); }
    static async Task AuditAsync<T>(NpgsqlConnection c, string tenant, string objectType, string objectId, string action, string actor, T data, CancellationToken ct, NpgsqlTransaction? tx = null) { await using var cmd = new NpgsqlCommand("INSERT INTO platform.threat_audit(tenant_id,audit_id,object_type,object_id,action,actor,audit_data) VALUES($1,$2,$3,$4,$5,$6,$7)", c, tx); Add(cmd, Guid.Parse(tenant), Guid.NewGuid(), objectType, objectId, action, actor); AddJson(cmd, data); await cmd.ExecuteNonQueryAsync(ct); }
    public void Dispose() => _gate.Dispose();
}
