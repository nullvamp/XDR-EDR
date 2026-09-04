using System.Security.Cryptography;
using Npgsql;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class InventoriedObjectStorage(IObjectStorage inner, string connectionString) : IObjectStorage, IAsyncDisposable
{
    readonly NpgsqlDataSource data = NpgsqlDataSource.Create(connectionString);
    public async Task<ObjectMetadata> UploadAsync(string tenant, string id, Stream content, string media, string hash, CancellationToken ct)
    { var value = await inner.UploadAsync(tenant, id, content, media, hash, ct); await Save(tenant, id, "object", value.Size, value.Sha256, value.MediaType, "Available", ct); return value; }
    public async Task<Stream> DownloadAsync(string tenant, string id, CancellationToken ct)
    {
        var stream = await inner.DownloadAsync(tenant, id, ct); var expected = await Inventory(tenant, id, ct) ?? await inner.HeadAsync(tenant, id, ct) ?? throw new FileNotFoundException("Object inventory or object is missing.");
        var actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant(); stream.Position = 0;
        if (stream.Length != expected.Size || !CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(actual), System.Text.Encoding.ASCII.GetBytes(expected.Sha256.ToLowerInvariant()))) { await Save(tenant, id, "object", expected.Size, expected.Sha256, expected.MediaType, "Mismatch", CancellationToken.None); await stream.DisposeAsync(); throw new CryptographicException("Object content differs from its recovery inventory."); }
        return stream;
    }
    public async Task DeleteAsync(string tenant, string id, CancellationToken ct) { await inner.DeleteAsync(tenant, id, ct); var old = await Inventory(tenant, id, ct); if (old is not null) await Save(tenant, id, "object", old.Size, old.Sha256, old.MediaType, "Deleted", ct); }
    public Task<ObjectMetadata?> HeadAsync(string tenant, string id, CancellationToken ct) => inner.HeadAsync(tenant, id, ct);
    public Task<bool> HealthAsync(CancellationToken ct) => inner.HealthAsync(ct);
    async Task<ObjectMetadata?> Inventory(string tenant, string id, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("SELECT expected_size,media_type,expected_sha256,updated_at FROM platform.object_recovery_inventory WHERE tenant_id=$1 AND object_id=$2 AND state='Available'", c); q.Parameters.AddWithValue(Guid.Parse(tenant)); q.Parameters.AddWithValue(Guid.Parse(id)); await using var r = await q.ExecuteReaderAsync(ct); return await r.ReadAsync(ct) ? new(id, r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetFieldValue<DateTimeOffset>(3)) : null; }
    async Task Save(string tenant, string id, string type, long size, string hash, string media, string state, CancellationToken ct) { await using var c = await data.OpenConnectionAsync(ct); await using var q = new NpgsqlCommand("INSERT INTO platform.object_recovery_inventory(tenant_id,object_id,object_type,expected_size,expected_sha256,media_type,state,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()) ON CONFLICT(tenant_id,object_id) DO UPDATE SET expected_size=EXCLUDED.expected_size,expected_sha256=EXCLUDED.expected_sha256,media_type=EXCLUDED.media_type,state=EXCLUDED.state,updated_at=now()", c); object[] v = [Guid.Parse(tenant), Guid.Parse(id), type, size, hash, media, state]; foreach (var x in v) q.Parameters.AddWithValue(x); await q.ExecuteNonQueryAsync(ct); }
    public async ValueTask DisposeAsync() { await data.DisposeAsync(); GC.SuppressFinalize(this); }
}
