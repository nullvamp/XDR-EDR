using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OpenSecurityPlatform.Foundation;

public enum EndpointStatus
{
    Unknown,
    Pending,
    Online,
    Stale,
    Offline,
    Recovered,
    Disabled,
    Revoked,
}

public sealed record EndpointStatusChange(
    Guid EndpointId,
    EndpointStatus PreviousStatus,
    EndpointStatus Status,
    string Reason,
    DateTimeOffset OccurredAt
);

public sealed record LifecycleSweepResult(
    int Stale,
    int Offline,
    int Recovered,
    DateTimeOffset CompletedAt
);

public sealed record EnrollmentTokenCreate(
    DateTimeOffset ExpiresAt,
    int MaximumUses,
    string[] AllowedPlatforms,
    string? EndpointGroupId,
    string? PolicyId
);

public sealed record EnrollmentTokenMetadata(
    Guid Id,
    string TenantId,
    DateTimeOffset ExpiresAt,
    int MaximumUses,
    int Uses,
    string[] AllowedPlatforms,
    string? EndpointGroupId,
    string? PolicyId,
    bool Revoked,
    string CreatedBy,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt
);

public sealed record EnrollmentTokenSecret(EnrollmentTokenMetadata Metadata, string Secret);

public sealed record IssuedAgentCertificate(
    string CertificatePem,
    string CaCertificatePem,
    string Thumbprint,
    DateTimeOffset NotAfter
);

public sealed record CertificateRenewalRequest(string CertificateSigningRequest);

public sealed record CertificateRenewalResult(
    string AgentCertificatePem,
    string CaCertificatePem,
    DateTimeOffset CredentialExpiresAt
);

public sealed record EnrollmentRequest(
    Guid TokenId,
    string TokenSecret,
    string InstallationId,
    string IdempotencyKey,
    string Nonce,
    DateTimeOffset Timestamp,
    string ProtocolVersion,
    string AgentVersion,
    string Platform,
    string OsVersion,
    string Architecture,
    string Hostname,
    string CertificateSigningRequest,
    string[] Capabilities
);

public sealed record EnrollmentResult(
    Guid ReceiptId,
    string TenantId,
    Guid EndpointId,
    Guid AgentId,
    string AgentCertificatePem,
    string CaCertificatePem,
    DateTimeOffset CredentialExpiresAt,
    string ProtocolVersion,
    string PolicyVersion,
    int HeartbeatIntervalSeconds,
    int ConfigurationPollSeconds,
    DateTimeOffset ServerTime
);

public sealed record HeartbeatRequest(
    Guid EndpointId,
    Guid AgentId,
    long Sequence,
    DateTimeOffset Timestamp,
    long UptimeSeconds,
    string AgentVersion,
    string ProtocolVersion,
    string Platform,
    string OsVersion,
    string? PolicyVersion,
    string? ConfigurationVersion,
    string[] Capabilities,
    string Health,
    long QueueDepth,
    long? OldestQueueAgeSeconds,
    double? CpuPercent,
    long? WorkingSetBytes,
    InventorySummary? Inventory
);

public sealed record InventorySummary(
    string Hostname,
    string Platform,
    string OsVersion,
    string Architecture,
    string[] Tags,
    string[] Groups
);

public sealed record EndpointView(
    Guid Id,
    string TenantId,
    string DeviceIdentity,
    string Hostname,
    string Platform,
    string OsVersion,
    string Architecture,
    EndpointStatus Status,
    DateTimeOffset? LastSeenAt,
    string AgentVersion,
    string[] Capabilities,
    long Revision,
    InventorySummary? Inventory
);

public sealed record EndpointPage(IReadOnlyList<EndpointView> Items, string? NextCursor);

public sealed record EnrollmentAudit(
    Guid Id,
    string TenantId,
    string Action,
    string Outcome,
    string Actor,
    DateTimeOffset OccurredAt,
    string CorrelationId,
    Guid? EndpointId
);

public sealed record OutboxMessage(
    Guid Id,
    string TenantId,
    string Type,
    string Version,
    string Subject,
    string Payload,
    string TraceId,
    DateTimeOffset CreatedAt,
    int Attempts
);

public static partial class EndpointValidation
{
    private static readonly HashSet<string> SupportedPlatforms = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        "windows",
        "linux",
        "macos",
    };

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeTokenRegex();

    [GeneratedRegex(
        "^(?=.{1,128}$)[A-Za-z0-9][A-Za-z0-9._-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?$",
        RegexOptions.CultureInvariant
    )]
    private static partial Regex CapabilityRegex();

    [GeneratedRegex("^1\\.[01]$", RegexOptions.CultureInvariant)]
    private static partial Regex ProtocolRegex();

    [GeneratedRegex(
        "^[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
        RegexOptions.CultureInvariant
    )]
    private static partial Regex VersionRegex();

    public static Dictionary<string, string[]> Validate(
        EnrollmentRequest request,
        DateTimeOffset now
    )
    {
        var errors = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (!SafeTokenRegex().IsMatch(request.InstallationId))
            errors["installation_id"] = ["Must be 1-128 safe characters."];
        if (!SafeTokenRegex().IsMatch(request.IdempotencyKey))
            errors["idempotency_key"] = ["Must be 1-128 safe characters."];
        if (!SafeTokenRegex().IsMatch(request.Nonce) || request.Nonce.Length < 16)
            errors["nonce"] = ["Must contain at least 16 safe characters."];
        if ((now - request.Timestamp).Duration() > TimeSpan.FromMinutes(5))
            errors["timestamp"] = ["Outside the allowed five-minute clock window."];
        if (!ProtocolRegex().IsMatch(request.ProtocolVersion))
            errors["protocol_version"] = ["Supported versions are 1.0 and 1.1."];
        if (!VersionRegex().IsMatch(request.AgentVersion))
            errors["agent_version"] = ["Must be semantic version format."];
        if (!SupportedPlatforms.Contains(request.Platform))
            errors["platform"] = ["Unsupported platform."];
        if (string.IsNullOrWhiteSpace(request.Hostname) || request.Hostname.Length > 253)
            errors["hostname"] = ["Required and limited to 253 characters."];
        if (
            request.CertificateSigningRequest.Length is < 128 or > 16384
            || !request.CertificateSigningRequest.Contains(
                "BEGIN CERTIFICATE REQUEST",
                StringComparison.Ordinal
            )
        )
            errors["certificate_signing_request"] =
            [
                "A bounded PEM certificate signing request is required.",
            ];
        if (
            request.Capabilities.Length is 0 or > 128
            || request.Capabilities.Any(x => !CapabilityRegex().IsMatch(x))
        )
            errors["capabilities"] = ["One to 128 safe capability identifiers are required."];
        if (request.TokenSecret.Length is < 32 or > 256)
            errors["token_secret"] = ["Invalid enrollment secret."];
        return errors;
    }

    public static Dictionary<string, string[]> Validate(
        HeartbeatRequest request,
        DateTimeOffset now
    )
    {
        var errors = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (request.Sequence < 1)
            errors["sequence"] = ["Must be positive."];
        if ((now - request.Timestamp).Duration() > TimeSpan.FromMinutes(5))
            errors["timestamp"] = ["Outside the allowed clock window."];
        if (!SupportedPlatforms.Contains(request.Platform))
            errors["platform"] = ["Unsupported platform."];
        if (request.Capabilities.Length > 128)
            errors["capabilities"] = ["Too many capabilities."];
        if (request.QueueDepth < 0)
            errors["queue_depth"] = ["Cannot be negative."];
        return errors;
    }
}

public static class EnrollmentSecrets
{
    public static string Generate() => Base64Url(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string secret, byte[] pepper)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var input = Encoding.UTF8.GetBytes(secret);
        var combined = new byte[input.Length + pepper.Length];
        Buffer.BlockCopy(input, 0, combined, 0, input.Length);
        Buffer.BlockCopy(pepper, 0, combined, input.Length, pepper.Length);
        var hash = Rfc2898DeriveBytes.Pbkdf2(combined, salt, 210_000, HashAlgorithmName.SHA512, 32);
        return $"v1$210000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string secret, string encoded, byte[] pepper)
    {
        var p = encoded.Split('$');
        if (p.Length != 4 || p[0] != "v1" || !int.TryParse(p[1], out var iterations))
            return false;
        try
        {
            var input = Encoding.UTF8.GetBytes(secret);
            var combined = new byte[input.Length + pepper.Length];
            Buffer.BlockCopy(input, 0, combined, 0, input.Length);
            Buffer.BlockCopy(pepper, 0, combined, input.Length, pepper.Length);
            var expected = Convert.FromBase64String(p[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                combined,
                Convert.FromBase64String(p[2]),
                iterations,
                HashAlgorithmName.SHA512,
                expected.Length
            );
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string RequestHash(EnrollmentRequest request) =>
        Convert
            .ToHexString(
                SHA256.HashData(
                    JsonSerializer.SerializeToUtf8Bytes(request with { TokenSecret = "[redacted]" })
                )
            )
            .ToLowerInvariant();

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public interface IEndpointRepository
{
    Task<EnrollmentTokenSecret> CreateEnrollmentTokenAsync(
        string tenantId,
        string actor,
        EnrollmentTokenCreate request,
        byte[] pepper,
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<EnrollmentTokenMetadata>> ListEnrollmentTokensAsync(
        string tenantId,
        CancellationToken cancellationToken
    );
    Task<bool> RevokeEnrollmentTokenAsync(
        string tenantId,
        Guid tokenId,
        string actor,
        CancellationToken cancellationToken
    );
    Task<EnrollmentResult> EnrollAsync(
        EnrollmentRequest request,
        string requestHash,
        Func<string, string, string, IssuedAgentCertificate> issueCredential,
        byte[] pepper,
        CancellationToken cancellationToken
    );
    Task<EndpointView> RecordHeartbeatAsync(
        string tenantId,
        HeartbeatRequest request,
        CancellationToken cancellationToken
    );
    Task<EndpointPage> ListEndpointsAsync(
        string tenantId,
        int pageSize,
        string? cursor,
        string? search,
        EndpointStatus? status,
        CancellationToken cancellationToken
    );
    Task<EndpointView?> GetEndpointAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken cancellationToken
    );
    Task<LifecycleSweepResult> SweepEndpointLifecycleAsync(
        TimeSpan staleAfter,
        TimeSpan offlineAfter,
        CancellationToken cancellationToken
    );
    Task<bool> SetEndpointAdministrativeStateAsync(
        string tenantId,
        Guid endpointId,
        EndpointStatus status,
        string actor,
        string reason,
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<EndpointStatusChange>> ListEndpointStatusHistoryAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken cancellationToken
    );
    Task<bool> IsCredentialActiveAsync(
        string tenantId,
        string thumbprint,
        CancellationToken cancellationToken
    );
    Task RotateCredentialAsync(
        string tenantId,
        Guid agentId,
        string currentThumbprint,
        IssuedAgentCertificate issued,
        string certificateSigningRequest,
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<EndpointView>> ListAllEndpointsForProjectionAsync(
        CancellationToken cancellationToken
    );
    Task<IReadOnlyList<OutboxMessage>> LeaseOutboxAsync(
        int limit,
        TimeSpan lease,
        CancellationToken cancellationToken
    );
    Task MarkOutboxPublishedAsync(Guid id, CancellationToken cancellationToken);
    Task MarkOutboxFailedAsync(
        Guid id,
        string safeReason,
        int maximumAttempts,
        CancellationToken cancellationToken
    );
    Task<bool> HealthAsync(CancellationToken cancellationToken);
}

public sealed record ProjectionRebuildResult(
    string IndexName,
    int Documents,
    TimeSpan Duration,
    bool AliasSwitched
);

public sealed record ProjectionRebuildProgress(
    bool Running,
    string? IndexName,
    int TotalDocuments,
    int CompletedDocuments,
    DateTimeOffset? StartedAt,
    DateTimeOffset UpdatedAt,
    string? Error
);

public interface IEndpointProjection
{
    Task UpsertAsync(EndpointView endpoint, string eventId, CancellationToken cancellationToken);
    Task<EndpointPage> SearchAsync(
        string tenantId,
        int pageSize,
        string? cursor,
        string? query,
        EndpointStatus? status,
        CancellationToken cancellationToken
    );
    Task<bool> HealthAsync(CancellationToken cancellationToken);
    Task<ProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<EndpointView> endpoints,
        CancellationToken cancellationToken
    );
    ProjectionRebuildProgress GetRebuildProgress();
}

public sealed class EnrollmentConflictException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
