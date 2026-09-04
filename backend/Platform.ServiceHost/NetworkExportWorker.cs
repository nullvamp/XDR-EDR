using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;
sealed class NetworkExportWorker(INetworkExportRepository exports, INetworkTelemetryRepository network, IObjectStorage objects, ILogger<NetworkExportWorker> logger) : BackgroundService
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await RunCycleAsync(ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogWarning(e, "Network export work cycle temporarily unavailable");
                await Task.Delay(TimeSpan.FromSeconds(1), ct);
            }
        }
    }

    private async Task RunCycleAsync(CancellationToken ct)
    {
        foreach (var expired in await exports.ExpireDueAsync(ct))
        {
            foreach (var id in new[] { expired.OutputObjectId, expired.ManifestObjectId, expired.MetadataObjectId })
            {
                try
                {
                    await objects.DeleteAsync(expired.TenantId, id.ToString("D"), ct);
                }
                catch (Exception e) when (e is IOException or HttpRequestException)
                {
                    logger.LogWarning(e, "Expired network export cleanup failed for {ExportId}", expired.Id);
                }
            }
        }

        var job = await exports.ClaimAsync(ct);
        if (job is null)
        {
            await Task.Delay(250, ct);
            return;
        }

        try
        {
            var page = await network.SearchAsync(job.TenantId, job.Query with { Cursor = null, PageSize = Math.Clamp(job.MaximumRecords, 1, 10000) }, ct);
            var selected = page.Items.Take(job.MaximumRecords).ToArray();
            var output = job.Format == "csv" ? Csv(selected, job.Fields) : Jsonl(selected, job.Fields);
            var hash = Hash(output);
            var completed = DateTimeOffset.UtcNow;
            var manifest = new NetworkExportManifest("network-export-manifest.v1", job.Id, job.TenantId, job.Format, selected.Length, job.Query, EffectiveFields(job.Fields), job.CreatedAt, completed, output.LongLength, hash, "0.5.0", "network-event.v1", job.OutputObjectId, job.MetadataObjectId);
            var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
            var metadata = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "network-export-metadata.v1", exportId = job.Id, state = "completed", job.Format, recordCount = selected.Length, query = job.Query, fields = EffectiveFields(job.Fields), job.CreatedAt, completedAt = completed, expiresAt = job.ExpiresAt, job.OutputObjectId, job.ManifestObjectId, outputSha256 = hash, noPayloadContent = true }, Json);
            await Upload(job, job.OutputObjectId, output, job.Format == "csv" ? "text/csv" : "application/x-ndjson", ct);
            await Upload(job, job.ManifestObjectId, manifestBytes, "application/json", ct);
            await Upload(job, job.MetadataObjectId, metadata, "application/json", ct);
            await exports.CompleteAsync(job.Id, selected.Length, output.LongLength, hash, completed, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogError(e, "Network export {ExportId} failed", job.Id);
            await exports.FailAsync(job.Id, "EXPORT_FAILED", e.GetType().Name, ct);
        }
    }
    async Task Upload(NetworkExportJob job, Guid id, byte[] bytes, string media, CancellationToken ct) { await using var stream = new MemoryStream(bytes, false); await objects.UploadAsync(job.TenantId, id.ToString("D"), stream, media, Hash(bytes), ct); }
    static byte[] Jsonl(IReadOnlyList<NetworkObservation> values, string[] requested) { var b = new StringBuilder(); foreach (var value in values) b.AppendLine(JsonSerializer.Serialize(Project(value, requested), Json)); return Encoding.UTF8.GetBytes(b.ToString()); }
    static byte[] Csv(IReadOnlyList<NetworkObservation> values, string[] requested) { var fields = EffectiveFields(requested); var b = new StringBuilder(); b.AppendLine(string.Join(',', fields.Select(Cell))); foreach (var value in values) { var p = Project(value, fields); b.AppendLine(string.Join(',', fields.Select(x => Cell(p[x]?.ToString())))); } return Encoding.UTF8.GetBytes(b.ToString()); }
    static Dictionary<string, object?> Project(NetworkObservation x, string[] requested) { var all = new Dictionary<string, object?>(StringComparer.Ordinal) { ["schemaVersion"] = "network-export.v1", ["eventId"] = x.EventId, ["connectionEntityId"] = x.ConnectionEntityId, ["endpointId"] = x.EndpointId, ["observedAt"] = x.ObservedAt, ["operation"] = x.Kind.ToString(), ["localAddress"] = x.Local.Address, ["localPort"] = x.Local.Port, ["remoteAddress"] = x.Remote?.Address, ["remotePort"] = x.Remote?.Port, ["protocol"] = x.Protocol, ["addressFamily"] = x.Local.AddressFamily, ["direction"] = x.Direction.ToString(), ["state"] = x.State.ToString(), ["processEntityId"] = x.Process?.ProcessEntityId, ["user"] = x.User, ["hostname"] = x.Hostname?.Hostname, ["hostnameSource"] = x.Hostname?.Source, ["collector"] = x.CollectorSource, ["nativeProvider"] = x.NativeProvider, ["dataQuality"] = string.Join(';', x.DataQualityFlags) }; return EffectiveFields(requested).ToDictionary(y => y, y => all[y], StringComparer.Ordinal); }
    internal static string[] EffectiveFields(string[] requested) { string[] allowed = ["schemaVersion", "eventId", "connectionEntityId", "endpointId", "observedAt", "operation", "localAddress", "localPort", "remoteAddress", "remotePort", "protocol", "addressFamily", "direction", "state", "processEntityId", "user", "hostname", "hostnameSource", "collector", "nativeProvider", "dataQuality"]; return requested.Length == 0 ? allowed : requested.Where(allowed.Contains).Distinct().ToArray(); }
    static string Cell(string? value) { var safe = value ?? string.Empty; if (safe.Length > 0 && "=+-@\t\r".Contains(safe[0])) safe = "'" + safe; return '"' + safe.Replace("\"", "\"\"") + '"'; }
    static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
