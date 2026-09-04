using System.Security.Cryptography;
using System.Text.Json;

namespace OpenSecurityPlatform.Foundation;

public sealed class FileEndpointRepository : IEndpointRepository, IDisposable
{
    private sealed record StoredToken(EnrollmentTokenMetadata Metadata, string SecretHash);

    private sealed record StoredAgent(
        Guid Id,
        Guid EndpointId,
        string InstallationId,
        string PublicKeyHash,
        long LastSequence,
        bool Revoked
    );

    private sealed record StoredIdempotency(string Hash, EnrollmentResult Result);

    private sealed class State
    {
        public List<StoredToken> Tokens { get; init; } = [];
        public List<EndpointView> Endpoints { get; init; } = [];
        public List<StoredAgent> Agents { get; init; } = [];
        public Dictionary<string, StoredIdempotency> Idempotency { get; init; } = [];
        public HashSet<string> Nonces { get; init; } = [];
        public List<OutboxMessage> Outbox { get; init; } = [];
        public HashSet<Guid> Published { get; init; } = [];
        public List<EndpointStatusChange> StatusHistory { get; init; } = [];
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private State _state;

    public FileEndpointRepository(string dataDirectory)
    {
        Directory.CreateDirectory(dataDirectory);
        _path = Path.Combine(dataDirectory, "endpoint-state.json");
        _state = File.Exists(_path)
            ? JsonSerializer.Deserialize<State>(File.ReadAllText(_path), JsonOptions) ?? new()
            : new();
    }

    public async Task<EnrollmentTokenSecret> CreateEnrollmentTokenAsync(
        string tenantId,
        string actor,
        EnrollmentTokenCreate request,
        byte[] pepper,
        CancellationToken ct
    )
    {
        if (request.ExpiresAt <= DateTimeOffset.UtcNow || request.MaximumUses < 1)
            throw new EnrollmentConflictException(
                "TOKEN_POLICY_INVALID",
                "Token policy is invalid."
            );
        var secret = EnrollmentSecrets.Generate();
        var meta = new EnrollmentTokenMetadata(
            Guid.NewGuid(),
            tenantId,
            request.ExpiresAt,
            request.MaximumUses,
            0,
            request.AllowedPlatforms,
            request.EndpointGroupId,
            request.PolicyId,
            false,
            actor,
            DateTimeOffset.UtcNow,
            null
        );
        await Locked(
            async () =>
            {
                _state.Tokens.Add(new(meta, EnrollmentSecrets.Hash(secret, pepper)));
                await Save(ct);
            },
            ct
        );
        return new(meta, secret);
    }

    public async Task<IReadOnlyList<EnrollmentTokenMetadata>> ListEnrollmentTokensAsync(
        string tenantId,
        CancellationToken ct
    )
    {
        return await Locked(
            () =>
                Task.FromResult<IReadOnlyList<EnrollmentTokenMetadata>>(
                    _state
                        .Tokens.Where(x => x.Metadata.TenantId == tenantId)
                        .Select(x => x.Metadata)
                        .OrderByDescending(x => x.CreatedAt)
                        .ToArray()
                ),
            ct
        );
    }

    public async Task<bool> RevokeEnrollmentTokenAsync(
        string tenantId,
        Guid tokenId,
        string actor,
        CancellationToken ct
    )
    {
        return await Locked(
            async () =>
            {
                var index = _state.Tokens.FindIndex(x =>
                    x.Metadata.TenantId == tenantId && x.Metadata.Id == tokenId
                );
                if (index < 0)
                    return false;
                var item = _state.Tokens[index];
                _state.Tokens[index] = item with
                {
                    Metadata = item.Metadata with { Revoked = true },
                };
                await Save(ct);
                return true;
            },
            ct
        );
    }

    public async Task<EnrollmentResult> EnrollAsync(
        EnrollmentRequest request,
        string requestHash,
        Func<string, string, string, IssuedAgentCertificate> issueCredential,
        byte[] pepper,
        CancellationToken ct
    )
    {
        return await Locked(
            async () =>
            {
                var token =
                    _state.Tokens.SingleOrDefault(x => x.Metadata.Id == request.TokenId)
                    ?? throw new EnrollmentConflictException(
                        "ENROLLMENT_REJECTED",
                        "Enrollment material is invalid."
                    );
                var key = $"{token.Metadata.TenantId}:agent.enroll:{request.IdempotencyKey}";
                if (_state.Idempotency.TryGetValue(key, out var old))
                {
                    if (old.Hash != requestHash)
                        throw new EnrollmentConflictException(
                            "IDEMPOTENCY_CONFLICT",
                            "The idempotency key was reused with different content."
                        );
                    return old.Result;
                }
                var nonce = Hash(request.Nonce);
                if (!_state.Nonces.Add(nonce))
                    throw new EnrollmentConflictException(
                        "REPLAY_REJECTED",
                        "The nonce was already used."
                    );
                if (
                    token.Metadata.Revoked
                    || token.Metadata.ExpiresAt <= DateTimeOffset.UtcNow
                    || token.Metadata.Uses >= token.Metadata.MaximumUses
                    || !token.Metadata.AllowedPlatforms.Contains(
                        request.Platform,
                        StringComparer.OrdinalIgnoreCase
                    )
                    || !EnrollmentSecrets.Verify(request.TokenSecret, token.SecretHash, pepper)
                )
                    throw new EnrollmentConflictException(
                        "ENROLLMENT_REJECTED",
                        "Enrollment material is invalid or unavailable."
                    );
                var deviceIdentity = Hash(
                    request.InstallationId + "\n" + request.CertificateSigningRequest
                );
                var endpoint = _state.Endpoints.SingleOrDefault(x =>
                    x.TenantId == token.Metadata.TenantId && x.DeviceIdentity == deviceIdentity
                );
                if (endpoint is null)
                {
                    endpoint = new(
                        Guid.NewGuid(),
                        token.Metadata.TenantId,
                        deviceIdentity,
                        request.Hostname,
                        request.Platform,
                        request.OsVersion,
                        request.Architecture,
                        EndpointStatus.Unknown,
                        null,
                        request.AgentVersion,
                        request.Capabilities,
                        1,
                        new(
                            request.Hostname,
                            request.Platform,
                            request.OsVersion,
                            request.Architecture,
                            [],
                            token.Metadata.EndpointGroupId is null
                                ? []
                                : [token.Metadata.EndpointGroupId]
                        )
                    );
                    _state.Endpoints.Add(endpoint);
                }
                var agent = _state.Agents.SingleOrDefault(x =>
                    x.InstallationId == request.InstallationId
                    && _state.Endpoints.Any(e =>
                        e.Id == x.EndpointId && e.TenantId == token.Metadata.TenantId
                    )
                );
                if (agent is null)
                {
                    agent = new(
                        Guid.NewGuid(),
                        endpoint.Id,
                        request.InstallationId,
                        Hash(request.CertificateSigningRequest),
                        0,
                        false
                    );
                    _state.Agents.Add(agent);
                }
                var issued = issueCredential(
                    request.CertificateSigningRequest,
                    token.Metadata.TenantId,
                    $"{endpoint.Id}:{agent.Id}"
                );
                var result = new EnrollmentResult(
                    Guid.NewGuid(),
                    token.Metadata.TenantId,
                    endpoint.Id,
                    agent.Id,
                    issued.CertificatePem,
                    issued.CaCertificatePem,
                    issued.NotAfter,
                    "1.1",
                    token.Metadata.PolicyId ?? "1",
                    30,
                    60,
                    DateTimeOffset.UtcNow
                );
                _state.Idempotency[key] = new(requestHash, result);
                _state.Tokens[_state.Tokens.IndexOf(token)] = token with
                {
                    Metadata = token.Metadata with
                    {
                        Uses = token.Metadata.Uses + 1,
                        LastUsedAt = DateTimeOffset.UtcNow,
                    },
                };
                _state.Outbox.Add(Event(token.Metadata.TenantId, "endpoint.enrolled", endpoint));
                await Save(ct);
                return result;
            },
            ct
        );
    }

    public async Task<EndpointView> RecordHeartbeatAsync(
        string tenantId,
        HeartbeatRequest request,
        CancellationToken ct
    )
    {
        return await Locked(
            async () =>
            {
                var agent =
                    _state.Agents.SingleOrDefault(x =>
                        x.Id == request.AgentId && x.EndpointId == request.EndpointId && !x.Revoked
                    )
                    ?? throw new EnrollmentConflictException(
                        "AGENT_IDENTITY_INVALID",
                        "Agent identity is invalid or revoked."
                    );
                if (request.Sequence <= agent.LastSequence)
                    throw new EnrollmentConflictException(
                        "SEQUENCE_REPLAYED",
                        "Heartbeat sequence was already processed."
                    );
                _state.Agents[_state.Agents.IndexOf(agent)] = agent with
                {
                    LastSequence = request.Sequence,
                };
                var index = _state.Endpoints.FindIndex(x =>
                    x.Id == request.EndpointId && x.TenantId == tenantId
                );
                if (index < 0)
                    throw new EnrollmentConflictException(
                        "AGENT_IDENTITY_INVALID",
                        "Agent tenant binding is invalid."
                    );
                var current = _state.Endpoints[index];
                var next = current.Status is EndpointStatus.Stale or EndpointStatus.Offline
                    ? EndpointStatus.Recovered
                    : EndpointStatus.Online;
                var updated = current with
                {
                    Status = next,
                    LastSeenAt = DateTimeOffset.UtcNow,
                    AgentVersion = request.AgentVersion,
                    Capabilities = request.Capabilities,
                    Revision = current.Revision + 1,
                    Inventory = request.Inventory ?? current.Inventory,
                    Hostname = request.Inventory?.Hostname ?? current.Hostname,
                    OsVersion = request.OsVersion,
                };
                _state.Endpoints[index] = updated;
                if (next != current.Status)
                    _state.StatusHistory.Add(
                        new(
                            current.Id,
                            current.Status,
                            next,
                            "authenticated-heartbeat",
                            DateTimeOffset.UtcNow
                        )
                    );
                _state.Outbox.Add(Event(tenantId, "endpoint.heartbeat.received", updated));
                await Save(ct);
                return updated;
            },
            ct
        );
    }

    public async Task<EndpointPage> ListEndpointsAsync(
        string tenantId,
        int pageSize,
        string? cursor,
        string? search,
        EndpointStatus? status,
        CancellationToken ct
    )
    {
        return await Locked(
            () =>
            {
                var query = _state.Endpoints.Where(x => x.TenantId == tenantId);
                if (Guid.TryParse(cursor, out var after))
                    query = query.Where(x => x.Id.CompareTo(after) > 0);
                if (!string.IsNullOrWhiteSpace(search))
                    query = query.Where(x =>
                        x.Hostname.Contains(search, StringComparison.OrdinalIgnoreCase)
                        || x.DeviceIdentity == search
                    );
                if (status is not null)
                    query = query.Where(x => x.Status == status);
                var values = query
                    .OrderBy(x => x.Id)
                    .Take(Math.Clamp(pageSize, 1, 500) + 1)
                    .ToArray();
                var next = values.Length > pageSize ? values[pageSize - 1].Id.ToString() : null;
                return Task.FromResult(new EndpointPage(values.Take(pageSize).ToArray(), next));
            },
            ct
        );
    }

    public async Task<EndpointView?> GetEndpointAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    ) =>
        await Locked(
            () =>
                Task.FromResult(
                    _state.Endpoints.SingleOrDefault(x =>
                        x.TenantId == tenantId && x.Id == endpointId
                    )
                ),
            ct
        );

    public async Task<LifecycleSweepResult> SweepEndpointLifecycleAsync(
        TimeSpan staleAfter,
        TimeSpan offlineAfter,
        CancellationToken ct
    ) =>
        await Locked<LifecycleSweepResult>(
            async () =>
            {
                var stale = 0;
                var offline = 0;
                var now = DateTimeOffset.UtcNow;
                for (var i = 0; i < _state.Endpoints.Count; i++)
                {
                    var value = _state.Endpoints[i];
                    if (value.LastSeenAt is null)
                        continue;
                    var age = now - value.LastSeenAt.Value;
                    var target =
                        (value.Status is EndpointStatus.Online or EndpointStatus.Recovered)
                        && age >= staleAfter
                            ? EndpointStatus.Stale
                        : value.Status == EndpointStatus.Stale && age >= offlineAfter
                            ? EndpointStatus.Offline
                        : value.Status;
                    if (target == value.Status)
                        continue;
                    _state.Endpoints[i] = value with
                    {
                        Status = target,
                        Revision = value.Revision + 1,
                    };
                    _state.StatusHistory.Add(
                        new(value.Id, value.Status, target, "heartbeat-timeout", now)
                    );
                    if (target == EndpointStatus.Stale)
                        stale++;
                    else
                        offline++;
                }
                await Save(ct);
                return new(stale, offline, 0, now);
            },
            ct
        );

    public async Task<bool> SetEndpointAdministrativeStateAsync(
        string tenantId,
        Guid endpointId,
        EndpointStatus status,
        string actor,
        string reason,
        CancellationToken ct
    ) =>
        await Locked(
            async () =>
            {
                var index = _state.Endpoints.FindIndex(x =>
                    x.TenantId == tenantId && x.Id == endpointId
                );
                if (index < 0)
                    return false;
                var current = _state.Endpoints[index];
                _state.Endpoints[index] = current with
                {
                    Status = status,
                    Revision = current.Revision + 1,
                };
                _state.StatusHistory.Add(
                    new(endpointId, current.Status, status, reason, DateTimeOffset.UtcNow)
                );
                if (status == EndpointStatus.Revoked)
                    for (var i = 0; i < _state.Agents.Count; i++)
                        if (_state.Agents[i].EndpointId == endpointId)
                            _state.Agents[i] = _state.Agents[i] with { Revoked = true };
                await Save(ct);
                return true;
            },
            ct
        );

    public async Task<IReadOnlyList<EndpointStatusChange>> ListEndpointStatusHistoryAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    ) =>
        await Locked(
            () =>
                Task.FromResult<IReadOnlyList<EndpointStatusChange>>(
                    _state
                        .StatusHistory.Where(x =>
                            x.EndpointId == endpointId
                            && _state.Endpoints.Any(e =>
                                e.Id == endpointId && e.TenantId == tenantId
                            )
                        )
                        .OrderByDescending(x => x.OccurredAt)
                        .ToArray()
                ),
            ct
        );

    public Task<bool> IsCredentialActiveAsync(
        string tenantId,
        string thumbprint,
        CancellationToken ct
    ) => Task.FromResult(true);

    public Task RotateCredentialAsync(
        string tenantId,
        Guid agentId,
        string currentThumbprint,
        IssuedAgentCertificate issued,
        string certificateSigningRequest,
        CancellationToken ct
    ) => Task.CompletedTask;

    public async Task<IReadOnlyList<EndpointView>> ListAllEndpointsForProjectionAsync(
        CancellationToken ct
    ) =>
        await Locked(
            () => Task.FromResult<IReadOnlyList<EndpointView>>(_state.Endpoints.ToArray()),
            ct
        );

    public async Task<IReadOnlyList<OutboxMessage>> LeaseOutboxAsync(
        int limit,
        TimeSpan lease,
        CancellationToken ct
    ) =>
        await Locked(
            () =>
                Task.FromResult<IReadOnlyList<OutboxMessage>>(
                    _state.Outbox.Where(x => !_state.Published.Contains(x.Id)).Take(limit).ToArray()
                ),
            ct
        );

    public async Task MarkOutboxPublishedAsync(Guid id, CancellationToken ct) =>
        await Locked(
            async () =>
            {
                _state.Published.Add(id);
                await Save(ct);
            },
            ct
        );

    public Task MarkOutboxFailedAsync(
        Guid id,
        string safeReason,
        int maximumAttempts,
        CancellationToken ct
    ) => Task.CompletedTask;

    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);

    public void Dispose() => _gate.Dispose();

    private async Task Save(CancellationToken ct)
    {
        var temp = _path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(_state, JsonOptions), ct);
        File.Move(temp, _path, true);
    }

    private async Task Locked(Func<Task> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await action();
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<T> Locked<T>(Func<Task<T>> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            return await action();
        }
        finally
        {
            _gate.Release();
        }
    }

    private static OutboxMessage Event(string tenant, string type, EndpointView endpoint) =>
        new(
            Guid.NewGuid(),
            tenant,
            type,
            "1.0",
            "endpoint.lifecycle.v1",
            JsonSerializer.Serialize(endpoint, JsonOptions),
            System.Diagnostics.Activity.Current?.TraceId.ToString() ?? "",
            DateTimeOffset.UtcNow,
            0
        );

    private static string Hash(string value) =>
        Convert
            .ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant();
}
