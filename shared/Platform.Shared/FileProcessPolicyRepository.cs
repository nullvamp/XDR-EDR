namespace OpenSecurityPlatform.Foundation;

public sealed class FileProcessPolicyRepository : IProcessPolicyRepository
{
    private readonly object _gate = new();
    private readonly List<ProcessPolicyVersion> _versions = [];
    private readonly Dictionary<(string Tenant, Guid? Endpoint), Guid> _assignments = [];
    private readonly Dictionary<
        (string Tenant, Guid Endpoint),
        ProcessPolicyAcknowledgement
    > _acks = [];

    public Task<IReadOnlyList<ProcessPolicyVersion>> ListAsync(
        string tenantId,
        CancellationToken ct
    )
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<ProcessPolicyVersion>>(
                _versions
                    .Where(x => x.TenantId == tenantId)
                    .OrderBy(x => x.Name)
                    .ThenByDescending(x => x.Version)
                    .ToArray()
            );
    }

    public Task<ProcessPolicyVersion> CreateAsync(
        string tenantId,
        string actor,
        string name,
        ProcessTelemetryPolicy policy,
        CancellationToken ct
    )
    {
        if (ProcessPolicyValidation.Validate(policy).Count != 0)
            throw new EnrollmentConflictException(
                "PROCESS_POLICY_INVALID",
                "Policy validation failed."
            );
        lock (_gate)
        {
            var version =
                _versions
                    .Where(x => x.TenantId == tenantId && x.Name == name)
                    .Select(x => x.Version)
                    .DefaultIfEmpty()
                    .Max() + 1;
            var value = new ProcessPolicyVersion(
                Guid.NewGuid(),
                tenantId,
                name,
                version,
                policy with
                {
                    Version = $"process-policy.v{version}",
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
        string tenantId,
        Guid policyId,
        Guid? endpointId,
        string actor,
        CancellationToken ct
    )
    {
        lock (_gate)
            _assignments[(tenantId, endpointId)] = policyId;
        return Task.CompletedTask;
    }

    public Task<EffectiveProcessPolicy> EffectiveAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    )
    {
        lock (_gate)
        {
            var key = _assignments.ContainsKey((tenantId, endpointId))
                ? (tenantId, (Guid?)endpointId)
                : (tenantId, (Guid?)null);
            if (
                _assignments.TryGetValue(key, out var id)
                && _versions.FirstOrDefault(x => x.Id == id && x.TenantId == tenantId) is { } value
            )
            {
                _acks.TryGetValue((tenantId, endpointId), out var ack);
                return Task.FromResult(
                    new EffectiveProcessPolicy(
                        value,
                        key.Item2 is null ? "tenant-default" : "endpoint",
                        endpointId,
                        ack?.AcknowledgedAt,
                        ack?.Applied == true ? ack.Version : null,
                        ack?.Applied == false ? ack.Version : null,
                        ack?.ValidationError,
                        ack?.Applied != true || ack.Version != value.Version
                    )
                );
            }
            var policy = new ProcessPolicyVersion(
                Guid.Empty,
                tenantId,
                "safe-default",
                1,
                new(),
                new string('0', 64),
                "implicit",
                DateTimeOffset.UnixEpoch,
                "system"
            );
            return Task.FromResult(
                new EffectiveProcessPolicy(
                    policy,
                    "implicit-default",
                    endpointId,
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
        string tenantId,
        Guid endpointId,
        ProcessPolicyAcknowledgement acknowledgement,
        CancellationToken ct
    )
    {
        lock (_gate)
            _acks[(tenantId, endpointId)] = acknowledgement;
        return Task.CompletedTask;
    }

    public async Task<ProcessPolicyVersion> RollbackAsync(
        string tenantId,
        Guid policyId,
        int version,
        string actor,
        CancellationToken ct
    )
    {
        ProcessPolicyVersion source;
        lock (_gate)
            source = _versions.Single(x =>
                x.TenantId == tenantId && x.Id == policyId && x.Version == version
            );
        return await CreateAsync(tenantId, actor, source.Name, source.Policy, ct);
    }

    public Task<IReadOnlyList<ProcessExclusionMetric>> ExclusionMetricsAsync(
        string tenantId,
        Guid endpointId,
        CancellationToken ct
    ) => Task.FromResult<IReadOnlyList<ProcessExclusionMetric>>([]);
}
