using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OpenSecurityPlatform.Foundation;

public sealed record PlatformOptions
{
    public string ServiceName { get; init; } = "gateway";
    public string Environment { get; init; } = "development";
    public string Region { get; init; } = "local";
    public string InstanceId { get; init; } = System.Environment.MachineName;
    public string DataDirectory { get; init; } = "data";
    public string? RegistryUrl { get; init; }
    public string JwtIssuer { get; init; } = "security-platform";
    public string JwtAudience { get; init; } = "security-platform-api";
    public string JwtSigningKey { get; init; } = "";
    public string AdapterMode { get; init; } = "development";
    public string? DatabaseUrl { get; init; }
    public string? MessageBusUrl { get; init; }
    public string? ObjectStoreUrl { get; init; }
    public string? SearchUrl { get; init; }
    public string EnrollmentPepper { get; init; } = "";
    public string BootstrapTenantId { get; init; } = "00000000-0000-0000-0000-000000000002";
    public string ManagedClients { get; init; } = "";
    public string ObjectStoreAccessKey { get; init; } = "";
    public string ObjectStoreSecretKey { get; init; } = "";
    public string ObjectStoreBucket { get; init; } = "platform-objects";
    public string? SearchUsername { get; init; }
    public string? SearchPassword { get; init; }
    public string? CertificateAuthorityPath { get; init; }
    public string CertificateAuthorityPassword { get; init; } = "";
    public string? ServerCertificatePath { get; init; }
    public string ServerCertificatePassword { get; init; } = "";

    public static PlatformOptions FromEnvironment() =>
        new()
        {
            ServiceName = Get("PLATFORM_SERVICE_NAME", "gateway"),
            Environment = Get("PLATFORM_ENVIRONMENT", "development"),
            Region = Get("PLATFORM_REGION", "local"),
            InstanceId = Get("PLATFORM_INSTANCE_ID", System.Environment.MachineName),
            DataDirectory = Get("PLATFORM_DATA_DIRECTORY", "data"),
            RegistryUrl = System.Environment.GetEnvironmentVariable("PLATFORM_REGISTRY_URL"),
            JwtIssuer = Get("PLATFORM_JWT_ISSUER", "security-platform"),
            JwtAudience = Get("PLATFORM_JWT_AUDIENCE", "security-platform-api"),
            JwtSigningKey = Get("PLATFORM_JWT_SIGNING_KEY", ""),
            AdapterMode = Get("PLATFORM_ADAPTER_MODE", "development"),
            DatabaseUrl = System.Environment.GetEnvironmentVariable("PLATFORM_DATABASE_URL"),
            MessageBusUrl = System.Environment.GetEnvironmentVariable("PLATFORM_MESSAGEBUS_URL"),
            ObjectStoreUrl = System.Environment.GetEnvironmentVariable("PLATFORM_OBJECTSTORE_URL"),
            SearchUrl = System.Environment.GetEnvironmentVariable("PLATFORM_SEARCH_URL"),
            EnrollmentPepper = Get("PLATFORM_ENROLLMENT_PEPPER", ""),
            BootstrapTenantId = Get(
                "PLATFORM_BOOTSTRAP_TENANT_ID",
                "00000000-0000-0000-0000-000000000002"
            ),
            ManagedClients = Get("PLATFORM_MANAGED_CLIENTS", ""),
            ObjectStoreAccessKey = Get("PLATFORM_OBJECTSTORE_ACCESS_KEY", ""),
            ObjectStoreSecretKey = Get("PLATFORM_OBJECTSTORE_SECRET_KEY", ""),
            ObjectStoreBucket = Get("PLATFORM_OBJECTSTORE_BUCKET", "platform-objects"),
            SearchUsername = System.Environment.GetEnvironmentVariable("PLATFORM_SEARCH_USERNAME"),
            SearchPassword = System.Environment.GetEnvironmentVariable("PLATFORM_SEARCH_PASSWORD"),
            CertificateAuthorityPath = System.Environment.GetEnvironmentVariable(
                "PLATFORM_CA_PFX_PATH"
            ),
            CertificateAuthorityPassword = Get("PLATFORM_CA_PFX_PASSWORD", ""),
            ServerCertificatePath = System.Environment.GetEnvironmentVariable(
                "PLATFORM_SERVER_PFX_PATH"
            ),
            ServerCertificatePassword = Get("PLATFORM_SERVER_PFX_PASSWORD", ""),
        };

    public void Validate()
    {
        if (AdapterMode is not ("development" or "production"))
            throw new InvalidOperationException(
                "PLATFORM_ADAPTER_MODE must be development or production."
            );
        if (JwtSigningKey.Length < 32)
            throw new InvalidOperationException(
                "PLATFORM_JWT_SIGNING_KEY must be at least 32 characters."
            );
        if (EnrollmentPepper.Length < 32)
            throw new InvalidOperationException(
                "PLATFORM_ENROLLMENT_PEPPER must be at least 32 characters."
            );
        if (!Guid.TryParse(BootstrapTenantId, out _))
            throw new InvalidOperationException("PLATFORM_BOOTSTRAP_TENANT_ID must be a UUID.");
        if (AdapterMode == "production")
        {
            if (
                string.IsNullOrWhiteSpace(DatabaseUrl)
                || string.IsNullOrWhiteSpace(MessageBusUrl)
                || string.IsNullOrWhiteSpace(ObjectStoreUrl)
                || string.IsNullOrWhiteSpace(SearchUrl)
            )
                throw new InvalidOperationException(
                    "Production adapters require database, message bus, object store, and search URLs."
                );
            if (ObjectStoreAccessKey.Length < 3 || ObjectStoreSecretKey.Length < 16)
                throw new InvalidOperationException(
                    "Production object-store credentials are missing or unsafe."
                );
            if (
                string.IsNullOrWhiteSpace(CertificateAuthorityPath)
                || CertificateAuthorityPassword.Length < 16
            )
                throw new InvalidOperationException(
                    "Production certificate-authority configuration is missing or unsafe."
                );
            if (
                string.IsNullOrWhiteSpace(ServerCertificatePath)
                || ServerCertificatePassword.Length < 16
            )
                throw new InvalidOperationException(
                    "Production server-certificate configuration is missing or unsafe."
                );
        }
    }

    private static string Get(string key, string fallback) =>
        System.Environment.GetEnvironmentVariable(key) is { Length: > 0 } value ? value : fallback;
}

public sealed record ApiError(
    string Code,
    string Title,
    int Status,
    string RequestId,
    bool Retryable = false,
    string? Detail = null
);

public sealed record ApiEnvelope<T>(T Data, ApiMeta Meta);

public sealed record ApiMeta(string RequestId, string SchemaVersion = "1.0");

public sealed record ServiceRegistration(
    string Name,
    string InstanceId,
    string Address,
    string Region,
    DateTimeOffset StartedAt
);

public sealed record TypedMessage<T>(
    string Type,
    string Version,
    string Id,
    string TenantId,
    DateTimeOffset OccurredAt,
    T Data,
    string TraceId
);

public static class PlatformTelemetry
{
    public const string SourceName = "OpenSecurityPlatform";
    public static readonly ActivitySource Activities = new(SourceName, "0.1.0");
}

public interface IMessageBus
{
    ValueTask PublishAsync<T>(TypedMessage<T> message, CancellationToken cancellationToken);
    bool IsHealthy { get; }
    ValueTask<bool> HealthAsync(CancellationToken cancellationToken);
}

public sealed class DurableFileMessageBus : IMessageBus, IDisposable
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DurableFileMessageBus(string dataDirectory)
    {
        _path = Path.Combine(dataDirectory, "bus");
        Directory.CreateDirectory(_path);
    }

    public bool IsHealthy => Directory.Exists(_path);

    public ValueTask<bool> HealthAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(IsHealthy);

    public async ValueTask PublishAsync<T>(
        TypedMessage<T> message,
        CancellationToken cancellationToken
    )
    {
        var safeType = string.Concat(
            message.Type.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' ? c : '_')
        );
        var file = Path.Combine(
            _path,
            $"{message.OccurredAt:yyyyMMddHHmmssfffffff}-{safeType}-{message.Id}.json"
        );
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await File.WriteAllBytesAsync(file, bytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}

public interface IObjectStorage
{
    Task<ObjectMetadata> UploadAsync(
        string tenantId,
        string objectId,
        Stream content,
        string mediaType,
        string expectedSha256,
        CancellationToken cancellationToken
    );
    Task<Stream> DownloadAsync(
        string tenantId,
        string objectId,
        CancellationToken cancellationToken
    );
    Task DeleteAsync(string tenantId, string objectId, CancellationToken cancellationToken);
    Task<ObjectMetadata?> HeadAsync(
        string tenantId,
        string objectId,
        CancellationToken cancellationToken
    );
    Task<bool> HealthAsync(CancellationToken cancellationToken);
}

public sealed record ObjectMetadata(
    string ObjectId,
    long Size,
    string MediaType,
    string Sha256,
    DateTimeOffset CreatedAt
);

public sealed class FileObjectStorage : IObjectStorage
{
    private readonly string _root;

    public FileObjectStorage(string dataDirectory)
    {
        _root = Path.Combine(dataDirectory, "objects");
        Directory.CreateDirectory(_root);
    }

    private string Resolve(string tenant, string id)
    {
        static bool Valid(string value) =>
            value.Length is > 0 and < 129
            && value.All(c => char.IsLetterOrDigit(c) || c is '-' or '_');
        if (!Valid(tenant) || !Valid(id))
            throw new ArgumentException("Object identifiers contain unsupported characters.");
        return Path.Combine(_root, tenant, id);
    }

    public async Task<ObjectMetadata> UploadAsync(
        string tenantId,
        string objectId,
        Stream content,
        string mediaType,
        string expectedSha256,
        CancellationToken cancellationToken
    )
    {
        var path = Resolve(tenantId, objectId);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".upload";
        long size;
        await using (
            var output = new FileStream(
                temp,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                81920,
                FileOptions.Asynchronous | FileOptions.WriteThrough
            )
        )
        {
            await content.CopyToAsync(output, cancellationToken);
            size = output.Length;
        }
        string hash;
        await using (var verify = File.OpenRead(temp))
        {
            hash = Convert
                .ToHexString(await SHA256.HashDataAsync(verify, cancellationToken))
                .ToLowerInvariant();
        }
        if (
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(hash),
                Encoding.ASCII.GetBytes(expectedSha256.ToLowerInvariant())
            )
        )
        {
            File.Delete(temp);
            throw new CryptographicException("Object hash verification failed.");
        }
        File.Move(temp, path, false);
        var metadata = new ObjectMetadata(objectId, size, mediaType, hash, DateTimeOffset.UtcNow);
        await File.WriteAllTextAsync(
            path + ".metadata.json",
            JsonSerializer.Serialize(metadata),
            cancellationToken
        );
        return metadata;
    }

    public Task<Stream> DownloadAsync(
        string tenantId,
        string objectId,
        CancellationToken cancellationToken
    ) =>
        Task.FromResult<Stream>(
            new FileStream(
                Resolve(tenantId, objectId),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                true
            )
        );

    public Task DeleteAsync(string tenantId, string objectId, CancellationToken cancellationToken)
    {
        File.Delete(Resolve(tenantId, objectId));
        File.Delete(Resolve(tenantId, objectId) + ".metadata.json");
        return Task.CompletedTask;
    }

    public async Task<ObjectMetadata?> HeadAsync(
        string tenantId,
        string objectId,
        CancellationToken cancellationToken
    )
    {
        var p = Resolve(tenantId, objectId) + ".metadata.json";
        return File.Exists(p)
            ? JsonSerializer.Deserialize<ObjectMetadata>(
                await File.ReadAllTextAsync(p, cancellationToken)
            )
            : null;
    }

    public Task<bool> HealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Directory.Exists(_root));
}

public interface ISearchIndex
{
    Task EnsureIndexAsync(string tenantId, string name, CancellationToken cancellationToken);
    Task<bool> HealthAsync(CancellationToken cancellationToken);
}

public sealed class FileSearchIndex : ISearchIndex
{
    private readonly string _root;

    public FileSearchIndex(string data)
    {
        _root = Path.Combine(data, "indexes");
        Directory.CreateDirectory(_root);
    }

    public Task EnsureIndexAsync(string tenantId, string name, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.Combine(_root, tenantId, name));
        return Task.CompletedTask;
    }

    public Task<bool> HealthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Directory.Exists(_root));
}
