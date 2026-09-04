using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed class IdentityExportWorker(IIdentityExportRepository jobs, IIdentityTelemetryRepository telemetry, IObjectStorage objects, ILogger<IdentityExportWorker> log) : BackgroundService
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var job = await jobs.ClaimAsync(ct); if (job is null) { await Task.Delay(250, ct); continue; }
            try
            {
                var page = await telemetry.SearchAsync(job.TenantId, job.Query with { Cursor = null, PageSize = Math.Clamp(job.MaximumRecords, 1, 10000) }, ct); var values = page.Items.Take(job.MaximumRecords).ToArray();
                var output = job.Format == "csv" ? Csv(values) : Encoding.UTF8.GetBytes(string.Join('\n', values.Select(x => JsonSerializer.Serialize(x, Json))) + '\n');
                var hash = Convert.ToHexString(SHA256.HashData(output)).ToLowerInvariant(); var at = DateTimeOffset.UtcNow;
                var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "identity-export-manifest.v1", exportId = job.Id, tenantBinding = job.TenantId, job.Format, recordCount = values.Length, job.Query, job.Fields, sha256 = hash, eventSchemaVersion = "identity-event.v1", job.OutputObjectId, job.MetadataObjectId, completedAt = at }, Json);
                var metadata = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "identity-export-metadata.v1", exportId = job.Id, job.Query, job.Fields, job.CreatedAt, job.ExpiresAt, outputSha256 = hash }, Json);
                await Put(job, job.OutputObjectId, output, job.Format == "csv" ? "text/csv" : "application/x-ndjson", ct); await Put(job, job.ManifestObjectId, manifest, "application/json", ct); await Put(job, job.MetadataObjectId, metadata, "application/json", ct); await jobs.CompleteAsync(job.Id, values.Length, output.Length, hash, at, ct);
            }
            catch (Exception exception) when (exception is not OperationCanceledException) { log.LogError(exception, "Identity export failed"); await jobs.FailAsync(job.Id, "EXPORT_FAILED", exception.GetType().Name, ct); }
        }
    }
    async Task Put(IdentityExportJob job, Guid id, byte[] bytes, string media, CancellationToken ct) { await using var stream = new MemoryStream(bytes); await objects.UploadAsync(job.TenantId, id.ToString("D"), stream, media, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), ct); }
    static byte[] Csv(IEnumerable<IdentityObservation> values)
    {
        static string Cell(string? value) { var text = value ?? ""; if (text.Length > 0 && "=+-@\t\r".Contains(text[0])) text = "'" + text; return '"' + text.Replace("\"", "\"\"") + '"'; }
        var result = new StringBuilder("schemaVersion,eventId,endpointId,observedAt,eventType,accountSid,accountName,domain,logonId,logonType,result,sourceIp,sessionId,tokenType,integrity,elevated,privileges,processEntityId,provider,channel,nativeEventId,evidenceSha256,quality\n");
        foreach (var v in values) result.AppendLine(string.Join(',', Cell(v.SchemaVersion), Cell(v.EventId.ToString()), Cell(v.EndpointId.ToString()), Cell(v.ObservedAt.ToString("O")), Cell(v.Kind.ToString()), Cell(v.Account?.Sid), Cell(v.Account?.Name), Cell(v.Account?.Domain), Cell(v.Logon?.LogonId), Cell(v.Logon?.NativeLogonType?.ToString(CultureInfo.InvariantCulture)), Cell(v.Logon?.Result), Cell(v.Logon?.SourceIp), Cell((v.Session?.SessionId ?? v.Token?.SessionId)?.ToString(CultureInfo.InvariantCulture)), Cell(v.Token?.TokenType), Cell(v.Token?.IntegrityLevel), Cell(v.Token?.Elevated?.ToString()), Cell(string.Join(';', v.Privileges.Select(x => $"{x.Name}:{x.State}"))), Cell(v.Process?.ProcessEntityId), Cell(v.Native.Provider), Cell(v.Native.Channel), Cell(v.Native.EventId.ToString(CultureInfo.InvariantCulture)), Cell(v.EvidenceSha256), Cell(string.Join(';', v.DataQualityFlags))));
        return Encoding.UTF8.GetBytes(result.ToString());
    }
}
