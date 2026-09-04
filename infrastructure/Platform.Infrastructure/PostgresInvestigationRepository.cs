using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresInvestigationRepository : FileInvestigationRepository, IAsyncDisposable
{
    readonly NpgsqlDataSource _data;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public PostgresInvestigationRepository(string connectionString) => _data = NpgsqlDataSource.Create(connectionString);

    protected override async Task PersistAsync(string tenant, IReadOnlyList<InvestigationEntity> nodes, IReadOnlyList<InvestigationRelationship> edges, CancellationToken ct)
    {
        await using var connection = await _data.OpenConnectionAsync(ct); await using var tx = await connection.BeginTransactionAsync(ct);
        foreach (var node in nodes)
        {
            await using var command = new NpgsqlCommand("INSERT INTO platform.investigation_entities(tenant_id,entity_id,entity_type,endpoint_id,first_observed,last_observed,entity_data,evidence_ids,evidence_references,provenance,ambiguous,relationship_version) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12) ON CONFLICT(tenant_id,entity_id,entity_type) DO UPDATE SET first_observed=LEAST(platform.investigation_entities.first_observed,EXCLUDED.first_observed),last_observed=GREATEST(platform.investigation_entities.last_observed,EXCLUDED.last_observed),entity_data=EXCLUDED.entity_data,evidence_ids=(SELECT ARRAY(SELECT DISTINCT unnest(platform.investigation_entities.evidence_ids||EXCLUDED.evidence_ids))),evidence_references=(SELECT ARRAY(SELECT DISTINCT unnest(platform.investigation_entities.evidence_references||EXCLUDED.evidence_references))),ambiguous=platform.investigation_entities.ambiguous OR EXCLUDED.ambiguous", connection, tx);
            command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(node.EntityId); command.Parameters.AddWithValue(node.Type.ToString()); command.Parameters.AddWithValue((object?)node.EndpointId ?? DBNull.Value); command.Parameters.AddWithValue(node.FirstObserved); command.Parameters.AddWithValue(node.LastObserved); command.Parameters.AddWithValue(JsonSerializer.Serialize(node, Json)); command.Parameters.AddWithValue(node.EvidenceIds); command.Parameters.AddWithValue(node.EvidenceReferences); command.Parameters.AddWithValue(node.Provenance); command.Parameters.AddWithValue(node.Ambiguous); command.Parameters.AddWithValue(node.Version); await command.ExecuteNonQueryAsync(ct);
        }
        foreach (var edge in edges)
        {
            await using var command = new NpgsqlCommand("INSERT INTO platform.investigation_relationships(tenant_id,relationship_id,source_entity_id,source_type,destination_entity_id,destination_type,relationship_type,first_observed,last_observed,confidence,provenance,ambiguous,relationship_version,evidence_ids,evidence_references,relationship_data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb) ON CONFLICT(tenant_id,relationship_id) DO UPDATE SET first_observed=LEAST(platform.investigation_relationships.first_observed,EXCLUDED.first_observed),last_observed=GREATEST(platform.investigation_relationships.last_observed,EXCLUDED.last_observed),confidence=GREATEST(platform.investigation_relationships.confidence,EXCLUDED.confidence),ambiguous=platform.investigation_relationships.ambiguous OR EXCLUDED.ambiguous,evidence_ids=(SELECT ARRAY(SELECT DISTINCT unnest(platform.investigation_relationships.evidence_ids||EXCLUDED.evidence_ids))),evidence_references=(SELECT ARRAY(SELECT DISTINCT unnest(platform.investigation_relationships.evidence_references||EXCLUDED.evidence_references))),relationship_data=EXCLUDED.relationship_data", connection, tx);
            command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(edge.RelationshipId); command.Parameters.AddWithValue(edge.SourceEntityId); command.Parameters.AddWithValue(edge.SourceType.ToString()); command.Parameters.AddWithValue(edge.DestinationEntityId); command.Parameters.AddWithValue(edge.DestinationType.ToString()); command.Parameters.AddWithValue(edge.RelationshipType); command.Parameters.AddWithValue(edge.FirstObserved); command.Parameters.AddWithValue(edge.LastObserved); command.Parameters.AddWithValue(edge.Confidence); command.Parameters.AddWithValue(edge.Provenance); command.Parameters.AddWithValue(edge.Ambiguous); command.Parameters.AddWithValue(edge.Version); command.Parameters.AddWithValue(edge.SourceEvidenceIds); command.Parameters.AddWithValue(edge.EvidenceReferences); command.Parameters.AddWithValue(JsonSerializer.Serialize(edge, Json)); await command.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }

    protected override async Task<(InvestigationEntity[] Nodes, InvestigationRelationship[] Edges)> LoadAsync(string tenant, CancellationToken ct)
    {
        var nodes = new List<InvestigationEntity>(); var edges = new List<InvestigationRelationship>(); await using var connection = await _data.OpenConnectionAsync(ct);
        await using (var command = new NpgsqlCommand("SELECT entity_data::text FROM platform.investigation_entities WHERE tenant_id=$1 ORDER BY last_observed DESC,entity_id LIMIT 20000", connection)) { command.Parameters.AddWithValue(Guid.Parse(tenant)); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) if (JsonSerializer.Deserialize<InvestigationEntity>(reader.GetString(0), Json) is { } node) nodes.Add(node); }
        await using (var command = new NpgsqlCommand("SELECT relationship_data::text FROM platform.investigation_relationships WHERE tenant_id=$1 ORDER BY last_observed DESC,relationship_id LIMIT 40000", connection)) { command.Parameters.AddWithValue(Guid.Parse(tenant)); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) if (JsonSerializer.Deserialize<InvestigationRelationship>(reader.GetString(0), Json) is { } edge) edges.Add(edge); }
        return (nodes.ToArray(), edges.ToArray());
    }

    public override async Task<HuntDefinition> SaveHuntAsync(string tenant, string actor, HuntDefinition hunt, bool newVersion, CancellationToken ct)
    {
        if (hunt.TenantId != tenant || hunt.HuntId != Guid.Empty && hunt.Owner != actor) throw new EnrollmentConflictException("HUNT_OWNERSHIP", "Saved hunt owner mismatch.");
        var id = hunt.HuntId == Guid.Empty ? Guid.NewGuid() : hunt.HuntId; await using var connection = await _data.OpenConnectionAsync(ct); var version = Math.Max(1, hunt.Version);
        if (newVersion) { await using var max = new NpgsqlCommand("SELECT COALESCE(MAX(version),0)+1 FROM platform.saved_hunts WHERE tenant_id=$1 AND hunt_id=$2", connection); max.Parameters.AddWithValue(Guid.Parse(tenant)); max.Parameters.AddWithValue(id); version = Convert.ToInt32(await max.ExecuteScalarAsync(ct), System.Globalization.CultureInfo.InvariantCulture); }
        var value = hunt with { HuntId = id, Version = version, TenantId = tenant, Owner = actor, CreatedAt = DateTimeOffset.UtcNow, SharedWith = hunt.SharedWith.Distinct().Take(100).ToArray() }; var valid = InvestigationSafety.Validate(value); if (!valid.Valid) throw new EnrollmentConflictException("HUNT_INVALID", string.Join(' ', valid.Errors.Values.SelectMany(x => x)));
        await using var command = new NpgsqlCommand("INSERT INTO platform.saved_hunts(tenant_id,hunt_id,version,name,owner,enabled,hunt_data,created_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)", connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(id); command.Parameters.AddWithValue(version); command.Parameters.AddWithValue(value.Name); command.Parameters.AddWithValue(actor); command.Parameters.AddWithValue(value.Enabled); command.Parameters.AddWithValue(JsonSerializer.Serialize(value, Json)); command.Parameters.AddWithValue(value.CreatedAt); command.Parameters.AddWithValue(actor); await command.ExecuteNonQueryAsync(ct); return value;
    }
    public override Task<IReadOnlyList<HuntDefinition>> SavedHuntsAsync(string tenant, CancellationToken ct) => ReadHunts(tenant, null, true, ct);
    public override Task<IReadOnlyList<HuntDefinition>> HuntHistoryAsync(string tenant, Guid id, CancellationToken ct) => ReadHunts(tenant, id, false, ct);
    async Task<IReadOnlyList<HuntDefinition>> ReadHunts(string tenant, Guid? id, bool latest, CancellationToken ct)
    {
        var list = new List<HuntDefinition>(); await using var connection = await _data.OpenConnectionAsync(ct); var sql = latest ? "SELECT DISTINCT ON(hunt_id) hunt_data::text FROM platform.saved_hunts WHERE tenant_id=$1 ORDER BY hunt_id,version DESC" : "SELECT hunt_data::text FROM platform.saved_hunts WHERE tenant_id=$1 AND hunt_id=$2 ORDER BY version DESC"; await using var command = new NpgsqlCommand(sql, connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); if (id is not null) command.Parameters.AddWithValue(id.Value); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) if (JsonSerializer.Deserialize<HuntDefinition>(reader.GetString(0), Json) is { } value) list.Add(value); return list.OrderBy(x => x.Name).ThenByDescending(x => x.Version).ToArray();
    }
    public override async Task DeleteHuntAsync(string tenant, string actor, Guid id, CancellationToken ct)
    {
        await using var connection = await _data.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("DELETE FROM platform.saved_hunts WHERE tenant_id=$1 AND hunt_id=$2 AND owner=$3", connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(id); command.Parameters.AddWithValue(actor); if (await command.ExecuteNonQueryAsync(ct) == 0) throw new EnrollmentConflictException("HUNT_OWNERSHIP", "Saved hunt not found or actor is not owner.");
    }
    public override async Task<HuntRun> ExecuteHuntAsync(string tenant, HuntDefinition hunt, CancellationToken ct)
    {
        var run = await base.ExecuteHuntAsync(tenant, hunt, ct); await using var connection = await _data.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("INSERT INTO platform.hunt_runs(tenant_id,run_id,hunt_id,hunt_version,status,cancel_requested,run_data,started_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)", connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(run.RunId); command.Parameters.AddWithValue(run.HuntId); command.Parameters.AddWithValue(run.HuntVersion); command.Parameters.AddWithValue(run.Status); command.Parameters.AddWithValue(run.CancelRequested); command.Parameters.AddWithValue(JsonSerializer.Serialize(run, Json)); command.Parameters.AddWithValue(run.StartedAt); command.Parameters.AddWithValue((object?)run.CompletedAt ?? DBNull.Value); await command.ExecuteNonQueryAsync(ct); return run;
    }
    public override async Task<HuntRun?> GetRunAsync(string tenant, Guid run, CancellationToken ct)
    {
        await using var connection = await _data.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("SELECT run_data::text FROM platform.hunt_runs WHERE tenant_id=$1 AND run_id=$2", connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(run); return await command.ExecuteScalarAsync(ct) is string json ? JsonSerializer.Deserialize<HuntRun>(json, Json) : null;
    }
    public override async Task<HuntRun> CancelRunAsync(string tenant, Guid run, CancellationToken ct)
    {
        var value = await GetRunAsync(tenant, run, ct) ?? throw new KeyNotFoundException(); value = value with { Status = "cancelled", CancelRequested = true, CompletedAt = DateTimeOffset.UtcNow }; await using var connection = await _data.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("UPDATE platform.hunt_runs SET status='cancelled',cancel_requested=true,run_data=$3::jsonb,completed_at=now() WHERE tenant_id=$1 AND run_id=$2", connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); command.Parameters.AddWithValue(run); command.Parameters.AddWithValue(JsonSerializer.Serialize(value, Json)); await command.ExecuteNonQueryAsync(ct); return value;
    }
    public override async Task<InvestigationHealth> HealthAsync(string tenant, CancellationToken ct)
    {
        var health = await base.HealthAsync(tenant, ct); await using var connection = await _data.OpenConnectionAsync(ct); await using var command = new NpgsqlCommand("SELECT COUNT(DISTINCT hunt_id) FROM platform.saved_hunts WHERE tenant_id=$1", connection); command.Parameters.AddWithValue(Guid.Parse(tenant)); var count = Convert.ToInt64(await command.ExecuteScalarAsync(ct), System.Globalization.CultureInfo.InvariantCulture); return health with { SavedHunts = count };
    }
    public async ValueTask DisposeAsync() => await _data.DisposeAsync();
}
