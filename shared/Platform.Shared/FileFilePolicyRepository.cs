namespace OpenSecurityPlatform.Foundation;

public sealed class FileFilePolicyRepository : IFilePolicyRepository
{
    readonly object _gate = new();
    readonly List<FilePolicyVersion> _versions = [];
    readonly Dictionary<(string, Guid?), Guid> _assignments = [];
    readonly Dictionary<(string, Guid), FilePolicyAcknowledgement> _acks = [];

    public Task<IReadOnlyList<FilePolicyVersion>> ListAsync(string tenant, CancellationToken ct)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<FilePolicyVersion>>(
                _versions
                    .Where(x => x.TenantId == tenant)
                    .OrderBy(x => x.Name)
                    .ThenByDescending(x => x.Version)
                    .ToArray()
            );
    }

    public Task<FilePolicyVersion> CreateAsync(
        string tenant,
        string actor,
        string name,
        FileTelemetryPolicy policy,
        CancellationToken ct
    )
    {
        if (FilePolicyValidation.Validate(policy).Count > 0)
            throw new EnrollmentConflictException("FILE_POLICY_INVALID", "File policy invalid.");
        lock (_gate)
        {
            var version =
                _versions
                    .Where(x => x.TenantId == tenant && x.Name == name)
                    .Select(x => x.Version)
                    .DefaultIfEmpty()
                    .Max() + 1;
            var value = new FilePolicyVersion(
                Guid.NewGuid(),
                tenant,
                name,
                version,
                policy with
                {
                    Version = $"file-policy.v{version}",
                },
                new string('0', 64),
                "active",
                DateTimeOffset.UtcNow,
                actor
            );
            _versions.Add(value);
            return Task.FromResult(value);
        }
    }

    public Task AssignAsync(
        string tenant,
        Guid policyId,
        Guid? endpoint,
        string actor,
        CancellationToken ct
    )
    {
        lock (_gate)
            _assignments[(tenant, endpoint)] = policyId;
        return Task.CompletedTask;
    }

    public Task<EffectiveFilePolicy> EffectiveAsync(
        string tenant,
        Guid endpoint,
        CancellationToken ct
    )
    {
        lock (_gate)
        {
            var key = _assignments.ContainsKey((tenant, endpoint))
                ? (tenant, (Guid?)endpoint)
                : (tenant, (Guid?)null);
            if (
                _assignments.TryGetValue(key, out var id)
                && _versions.FirstOrDefault(x => x.Id == id && x.TenantId == tenant) is { } v
            )
            {
                _acks.TryGetValue((tenant, endpoint), out var ack);
                return Task.FromResult(
                    new EffectiveFilePolicy(
                        v,
                        key.Item2 is null ? "tenant-default" : "endpoint",
                        endpoint,
                        ack?.PolicyId == v.Id ? ack.AcknowledgedAt : null,
                        ack?.PolicyId == v.Id && ack.Applied ? ack.Version : null,
                        ack?.PolicyId == v.Id && !ack.Applied ? ack.Version : null,
                        ack?.PolicyId == v.Id ? ack.ValidationError : null,
                        ack?.PolicyId != v.Id || ack.Applied != true || ack.Version != v.Version
                    )
                );
            }
            var fallback = new FilePolicyVersion(
                Guid.Empty,
                tenant,
                "safe-default",
                1,
                new(),
                new string('0', 64),
                "implicit",
                DateTimeOffset.UnixEpoch,
                "system"
            );
            return Task.FromResult(
                new EffectiveFilePolicy(
                    fallback,
                    "implicit-default",
                    endpoint,
                    null,
                    null,
                    null,
                    null,
                    true
                )
            );
        }
    }

    public Task AcknowledgeAsync(
        string tenant,
        Guid endpoint,
        FilePolicyAcknowledgement a,
        CancellationToken ct
    )
    {
        lock (_gate)
            _acks[(tenant, endpoint)] = a;
        return Task.CompletedTask;
    }

    public async Task<FilePolicyVersion> RollbackAsync(
        string tenant,
        Guid id,
        int version,
        string actor,
        CancellationToken ct
    )
    {
        var source = (await ListAsync(tenant, ct)).Single(x => x.Id == id && x.Version == version);
        return await CreateAsync(tenant, actor, source.Name, source.Policy, ct);
    }
}
