using System.Text.Json;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class PostgresDetectionEventSource(string connectionString) : IDetectionEventSource, IAsyncDisposable
{
    readonly NpgsqlDataSource _data = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(connectionString) { Pooling = true, MaxPoolSize = 3, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
    public async Task<IReadOnlyList<DetectionEvidenceEvent>> LoadAsync(string tenant, DetectionDomain domain, DateTimeOffset fromInclusive, DateTimeOffset toInclusive, int limit, CancellationToken ct)
    {
        if (toInclusive <= fromInclusive || toInclusive - fromInclusive > TimeSpan.FromDays(7) || limit is < 1 or > 10_000) throw new EnrollmentConflictException("DETECTION_REPLAY_BOUNDS", "Authoritative replay is limited to seven days and 10,000 events."); var table = domain switch { DetectionDomain.Process => "process_events", DetectionDomain.File => "file_events", DetectionDomain.Registry => "registry_events", DetectionDomain.Network => "network_events", DetectionDomain.Dns => "dns_events", DetectionDomain.Module => "module_events", DetectionDomain.Persistence => "persistence_events", DetectionDomain.Identity => "identity_events", DetectionDomain.Execution => "execution_events", _ => throw new ArgumentOutOfRangeException(nameof(domain)) }; var sql = $"SELECT event_id,endpoint_id,observed_at,event_data FROM platform.{table} WHERE tenant_id=$1 AND observed_at>=$2 AND observed_at<=$3 ORDER BY observed_at,event_id LIMIT $4"; await using var c = await _data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand(sql, c); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue(fromInclusive); q.Parameters.AddWithValue(toInclusive); q.Parameters.AddWithValue(limit); var list = new List<DetectionEvidenceEvent>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) { var id = r.GetGuid(0); var endpoint = r.GetGuid(1); var at = r.GetFieldValue<DateTimeOffset>(2); using var document = JsonDocument.Parse(r.GetString(3)); list.Add(DetectionEvidenceMapper.FromCanonical(tenant, domain, id, endpoint, at, document.RootElement.Clone(), $"postgresql://platform/{table}/{id:D}")); }
        return list;
    }
    public ValueTask DisposeAsync() => _data.DisposeAsync();
}
