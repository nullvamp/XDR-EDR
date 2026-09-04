using System.Security.Cryptography;
using Minio;
using Minio.DataModel.Args;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class MinioObjectStorage : IObjectStorage
{
    private readonly IMinioClient _client;
    private readonly string _bucket;
    private readonly long _maximumBytes;

    public MinioObjectStorage(
        string endpoint,
        string accessKey,
        string secretKey,
        string bucket,
        bool useTls,
        long maximumBytes = ArtifactTransferSafety.MaximumArtifactBytes
    )
    {
        if (string.IsNullOrWhiteSpace(secretKey) || secretKey.Length < 16)
            throw new InvalidOperationException("MinIO credentials are missing or unsafe.");
        _client = new MinioClient()
            .WithEndpoint(endpoint)
            .WithCredentials(accessKey, secretKey)
            .WithSSL(useTls)
            .Build();
        _bucket = bucket;
        _maximumBytes = maximumBytes;
    }

    public async Task EnsureBucketAsync(CancellationToken ct)
    {
        if (!await _client.BucketExistsAsync(new BucketExistsArgs().WithBucket(_bucket), ct))
            await _client.MakeBucketAsync(new MakeBucketArgs().WithBucket(_bucket), ct);
    }

    public async Task<ObjectMetadata> UploadAsync(
        string tenantId,
        string objectId,
        Stream content,
        string mediaType,
        string expectedSha256,
        CancellationToken ct
    )
    {
        var key = Key(tenantId, objectId);
        Stream upload = content;
        FileStream? temporary = null;
        if (!content.CanSeek)
        {
            temporary = new FileStream(
                Path.Combine(Path.GetTempPath(), $"osp-{Guid.NewGuid():N}.upload"),
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                81920,
                FileOptions.Asynchronous | FileOptions.DeleteOnClose
            );
            upload = temporary;
        }
        try
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var start = upload.CanSeek ? upload.Position : 0;
            var buffer = new byte[81920];
            long length = 0;
            int read;
            if (temporary is not null)
            {
                while ((read = await content.ReadAsync(buffer, ct)) > 0)
                {
                    length += read;
                    if (length > _maximumBytes)
                        throw new InvalidOperationException("Object size exceeds policy.");
                    hasher.AppendData(buffer, 0, read);
                    await temporary.WriteAsync(buffer.AsMemory(0, read), ct);
                }
                temporary.Position = 0;
            }
            else
            {
                length = upload.Length - upload.Position;
                if (length < 0 || length > _maximumBytes)
                    throw new InvalidOperationException("Object size exceeds policy.");
                while ((read = await upload.ReadAsync(buffer, ct)) > 0)
                    hasher.AppendData(buffer, 0, read);
                upload.Position = start;
            }
            var hash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
            if (
                !CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(hash),
                    System.Text.Encoding.ASCII.GetBytes(expectedSha256.ToLowerInvariant())
                )
            )
                throw new CryptographicException("Object hash verification failed.");
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { "x-amz-meta-sha256", hash },
                { "x-amz-meta-tenant", TenantHash(tenantId) },
            };
            await _client.PutObjectAsync(
                new PutObjectArgs()
                    .WithBucket(_bucket)
                    .WithObject(key)
                    .WithStreamData(upload)
                    .WithObjectSize(length)
                    .WithContentType(mediaType)
                    .WithHeaders(headers),
                ct
            );
            var stat = await _client.StatObjectAsync(
                new StatObjectArgs().WithBucket(_bucket).WithObject(key),
                ct
            );
            return new(objectId, stat.Size, stat.ContentType ?? mediaType, hash, stat.LastModified);
        }
        finally
        {
            if (temporary is not null)
                await temporary.DisposeAsync();
        }
    }

    public async Task<Stream> DownloadAsync(string tenantId, string objectId, CancellationToken ct)
    {
        var output = new FileStream(Path.Combine(Path.GetTempPath(), $"osp-{Guid.NewGuid():N}.download"),
            FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 256 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.DeleteOnClose);
        try
        {
            await _client.GetObjectAsync(new GetObjectArgs().WithBucket(_bucket).WithObject(Key(tenantId, objectId))
                .WithCallbackStream(stream => stream.CopyTo(output)), ct);
            output.Position = 0; return output;
        }
        catch { await output.DisposeAsync(); throw; }
    }

    public async Task DeleteAsync(string tenantId, string objectId, CancellationToken ct) =>
        await _client.RemoveObjectAsync(
            new RemoveObjectArgs().WithBucket(_bucket).WithObject(Key(tenantId, objectId)),
            ct
        );

    public async Task<ObjectMetadata?> HeadAsync(
        string tenantId,
        string objectId,
        CancellationToken ct
    )
    {
        try
        {
            var stat = await _client.StatObjectAsync(
                new StatObjectArgs().WithBucket(_bucket).WithObject(Key(tenantId, objectId)),
                ct
            );
            var hash = stat.MetaData.FirstOrDefault(x =>
                string.Equals(x.Key, "sha256", StringComparison.OrdinalIgnoreCase)
                || string.Equals(x.Key, "x-amz-meta-sha256", StringComparison.OrdinalIgnoreCase)
                || x.Key.EndsWith("-sha256", StringComparison.OrdinalIgnoreCase)).Value ?? "";
            return new(
                objectId,
                stat.Size,
                stat.ContentType ?? "application/octet-stream",
                hash,
                stat.LastModified
            );
        }
        catch (Minio.Exceptions.ObjectNotFoundException)
        {
            return null;
        }
    }

    public async Task<bool> HealthAsync(CancellationToken ct)
    {
        try
        {
            return await _client.BucketExistsAsync(new BucketExistsArgs().WithBucket(_bucket), ct);
        }
        catch (Minio.Exceptions.MinioException)
        {
            return false;
        }
    }

    private static string Key(string tenant, string id)
    {
        if (!Guid.TryParse(tenant, out var tid) || !Guid.TryParse(id, out var oid))
            throw new ArgumentException("Production object identifiers must be UUIDs.");
        return $"tenants/{tid:N}/objects/{oid:N}";
    }

    private static string TenantHash(string tenant) =>
        Convert
            .ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(tenant)))
            .ToLowerInvariant()[..16];
}
