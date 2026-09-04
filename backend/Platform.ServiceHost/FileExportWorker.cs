using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed class FileExportWorker(
    IFileExportRepository exports,
    IFileTelemetryRepository files,
    IObjectStorage objects,
    ILogger<FileExportWorker> logger
) : BackgroundService
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            foreach (var expired in await exports.ExpireDueAsync(ct))
                foreach (var id in new[]
                {
                    expired.OutputObjectId,
                    expired.ManifestObjectId,
                    expired.MetadataObjectId,
                })
                    try
                    {
                        await objects.DeleteAsync(expired.TenantId, id.ToString("D"), ct);
                    }
                    catch (Exception e) when (e is IOException or HttpRequestException)
                    {
                        logger.LogWarning(e, "Expired export object cleanup failed for {ExportId}", expired.Id);
                    }
            var job = await exports.ClaimAsync(ct);
            if (job is null)
            {
                await Task.Delay(250, ct);
                continue;
            }
            try
            {
                var page = await files.SearchAsync(
                    job.TenantId,
                    job.Query with
                    {
                        Cursor = null,
                        PageSize = Math.Clamp(job.MaximumRecords, 1, 10000),
                    },
                    ct
                );
                var selected = page.Items.Take(job.MaximumRecords).ToArray();
                var output = job.Format == "csv" ? Csv(selected, job.Fields) : Jsonl(selected, job.Fields);
                var outputHash = Hash(output);
                var completed = DateTimeOffset.UtcNow;
                var manifest = new FileExportManifest(
                    "file-export-manifest.v1",
                    job.Id,
                    job.TenantId,
                    job.Format,
                    selected.Length,
                    job.Query,
                    EffectiveFields(job.Fields),
                    job.CreatedAt,
                    completed,
                    output.LongLength,
                    outputHash,
                    ProductRelease.Version,
                    "file-event.v1",
                    job.OutputObjectId,
                    job.MetadataObjectId
                );
                var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
                var metadataBytes = JsonSerializer.SerializeToUtf8Bytes(
                    new
                    {
                        schemaVersion = "file-export-metadata.v1",
                        exportId = job.Id,
                        state = "completed",
                        job.Format,
                        recordCount = selected.Length,
                        query = job.Query,
                        fields = EffectiveFields(job.Fields),
                        job.CreatedAt,
                        completedAt = completed,
                        expiresAt = job.ExpiresAt,
                        outputObjectId = job.OutputObjectId,
                        manifestObjectId = job.ManifestObjectId,
                        outputSha256 = outputHash,
                    },
                    Json
                );
                await Upload(job, job.OutputObjectId, output, job.Format == "csv" ? "text/csv" : "application/x-ndjson", ct);
                await Upload(job, job.ManifestObjectId, manifestBytes, "application/json", ct);
                await Upload(job, job.MetadataObjectId, metadataBytes, "application/json", ct);
                await exports.CompleteAsync(job.Id, selected.Length, output.LongLength, outputHash, completed, ct);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogError(e, "File export {ExportId} failed", job.Id);
                await exports.FailAsync(job.Id, "EXPORT_FAILED", e.GetType().Name, ct);
            }
        }
    }

    async Task Upload(FileExportJob job, Guid objectId, byte[] bytes, string mediaType, CancellationToken ct)
    {
        await using var stream = new MemoryStream(bytes, false);
        await objects.UploadAsync(job.TenantId, objectId.ToString("D"), stream, mediaType, Hash(bytes), ct);
    }

    static byte[] Jsonl(IReadOnlyList<FileEntityView> values, string[] requested)
    {
        var builder = new StringBuilder();
        foreach (var value in values)
            builder.AppendLine(JsonSerializer.Serialize(Project(value, requested), Json));
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    static byte[] Csv(IReadOnlyList<FileEntityView> values, string[] requested)
    {
        var fields = EffectiveFields(requested);
        var builder = new StringBuilder();
        builder.AppendLine(string.Join(',', fields.Select(CsvCell)));
        foreach (var value in values)
        {
            var projected = Project(value, fields);
            builder.AppendLine(string.Join(',', fields.Select(x => CsvCell(projected[x]?.ToString()))));
        }
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    static Dictionary<string, object?> Project(FileEntityView value, string[] requested)
    {
        var all = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = "file-export.v1",
            ["endpointId"] = value.EndpointId,
            ["fileEntityId"] = value.FileEntityId,
            ["lastObserved"] = value.LastObserved,
            ["state"] = value.State.ToString(),
            ["path"] = value.CurrentPath,
            ["sha256"] = value.Hash.Sha256,
            ["collector"] = value.CollectorType,
            ["dataQuality"] = string.Join(';', value.DataQualityFlags),
        };
        return EffectiveFields(requested).ToDictionary(x => x, x => all[x], StringComparer.Ordinal);
    }

    internal static string[] EffectiveFields(string[] requested)
    {
        string[] allowed =
        [
            "schemaVersion",
            "endpointId",
            "fileEntityId",
            "lastObserved",
            "state",
            "path",
            "sha256",
            "collector",
            "dataQuality",
        ];
        return requested.Length == 0 ? allowed : requested.Where(allowed.Contains).Distinct().ToArray();
    }

    static string CsvCell(string? value)
    {
        var safe = value ?? string.Empty;
        if (safe.Length > 0 && "=+-@\t\r".Contains(safe[0]))
            safe = "'" + safe;
        return '"' + safe.Replace("\"", "\"\"") + '"';
    }

    static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
