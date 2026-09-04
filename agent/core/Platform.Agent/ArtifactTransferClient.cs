using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using OpenSecurityPlatform.Foundation;

static class ArtifactTransferClient
{
    public static async Task<(ArtifactTransferStatus Status, string Sha256)> UploadFileAsync(HttpClient client,
        string ownerType, Guid ownerId, Guid artifactId, string path, string name, string mediaType,
        string? nativeIdentity, CancellationToken ct)
    {
        var info = new FileInfo(path); info.Refresh();
        if (!info.Exists || info.Length > ArtifactTransferSafety.MaximumArtifactBytes)
            throw new InvalidOperationException("File is unavailable or exceeds the large-artifact transfer policy.");
        string sha256;
        await using (var verify = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan)) sha256 = await HashAsync(verify, ct);
        var transferId = StableTransfer(ownerType, ownerId, artifactId, sha256);
        var start = new ArtifactTransferStart(transferId, ownerType, ownerId, artifactId, name, mediaType, info.Length,
            sha256, ArtifactTransferSafety.DefaultChunkSize, nativeIdentity);
        using var started = await client.PostAsJsonAsync("/agent/v1/artifact-transfers", start, ct);
        started.EnsureSuccessStatusCode();
        var envelope = await started.Content.ReadFromJsonAsync<ApiEnvelope<ArtifactTransferStatus>>(cancellationToken: ct)
            ?? throw new InvalidDataException("Artifact transfer start acknowledgement is invalid.");
        var status = envelope.Data;
        if (status.State == ArtifactTransferState.Completed) return (status, sha256);
        if (status.State != ArtifactTransferState.Receiving) throw new InvalidOperationException("Artifact transfer is not resumable.");
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        input.Position = (long)status.ReceivedChunks * start.ChunkSize;
        var buffer = new byte[start.ChunkSize];
        for (var index = status.ReceivedChunks; input.Position < input.Length; index++)
        {
            var required = (int)Math.Min(buffer.Length, input.Length - input.Position); var offset = 0;
            while (offset < required) { var read = await input.ReadAsync(buffer.AsMemory(offset, required - offset), ct); if (read == 0) throw new EndOfStreamException(); offset += read; }
            var chunkHash = Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, required))).ToLowerInvariant();
            using var response = await PutWithRetry(client, transferId, index, buffer.AsMemory(0, required), chunkHash, ct); response.EnsureSuccessStatusCode();
            var ack = await response.Content.ReadFromJsonAsync<ApiEnvelope<ArtifactChunkAcknowledgement>>(cancellationToken: ct) ?? throw new InvalidDataException("Artifact chunk acknowledgement is invalid.");
            if (ack.Data.NextChunkIndex != index + 1) throw new InvalidDataException("Artifact chunk acknowledgement cursor is invalid.");
            await ThrottleAsync(required, ct);
        }
        using var completed = await client.PostAsJsonAsync($"/agent/v1/artifact-transfers/{transferId:D}:complete", new ArtifactTransferCompletion(transferId, sha256, info.Length), ct);
        completed.EnsureSuccessStatusCode();
        var final = await completed.Content.ReadFromJsonAsync<ApiEnvelope<ArtifactTransferStatus>>(cancellationToken: ct) ?? throw new InvalidDataException("Artifact transfer completion acknowledgement is invalid.");
        return (final.Data, sha256);
    }

    static async Task<HttpResponseMessage> PutWithRetry(HttpClient client, Guid transferId, int index, ReadOnlyMemory<byte> bytes, string hash, CancellationToken ct)
    {
        Exception? failure = null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                using var content = new ByteArrayContent(bytes.ToArray()); content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream"); content.Headers.ContentLength = bytes.Length; content.Headers.Add("X-Chunk-SHA256", hash);
                var response = await client.PutAsync($"/agent/v1/artifact-transfers/{transferId:D}/chunks/{index}", content, ct);
                if (response.IsSuccessStatusCode || (int)response.StatusCode < 500) return response;
                failure = new HttpRequestException($"Chunk upload returned HTTP {(int)response.StatusCode}."); response.Dispose();
            }
            catch (Exception ex) when ((ex is HttpRequestException or TaskCanceledException) && !ct.IsCancellationRequested) { failure = ex; }
            if (attempt < 3) await Task.Delay(TimeSpan.FromSeconds(attempt + 1), ct);
        }
        throw new HttpRequestException("Artifact chunk upload did not recover within its bounded retry window.", failure);
    }
    static Guid StableTransfer(string ownerType, Guid ownerId, Guid artifactId, string hash) { var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"artifact-transfer.v1\n{ownerType}\n{ownerId:D}\n{artifactId:D}\n{hash}")); return new Guid(bytes.AsSpan(0, 16)); }
    static async Task<string> HashAsync(Stream stream, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = new byte[256 * 1024]; int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0) { hash.AppendData(buffer, 0, read); await ThrottleAsync(read, ct); }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
    public static async Task ThrottleAsync(int bytes, CancellationToken ct)
    {
        var mibps = int.TryParse(Environment.GetEnvironmentVariable("PLATFORM_ARTIFACT_TRANSFER_MIBPS"), out var configured) ? configured : 32;
        if (mibps <= 0) return;
        var delay = TimeSpan.FromSeconds(bytes / (mibps * 1024d * 1024d)); if (delay > TimeSpan.Zero) await Task.Delay(delay, ct);
    }
}
