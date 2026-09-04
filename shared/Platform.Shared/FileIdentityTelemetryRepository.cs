namespace OpenSecurityPlatform.Foundation;

public sealed class FileIdentityTelemetryRepository : IIdentityTelemetryRepository, IIdentityProjection
{
    readonly object _gate = new(); readonly Dictionary<string, IdentityObservation> _events = [];
    readonly Dictionary<string, IdentityTelemetryHealth> _health = [];
    public Task<IdentityIngestResult> IngestAsync(string tenant, IdentityEventBatch batch, IdentityTelemetryHealth health, CancellationToken ct)
    {
        lock (_gate)
        {
            var accepted = new List<Guid>(); var duplicates = new List<Guid>(); var rejected = new Dictionary<Guid, string>();
            foreach (var value in batch.Events)
            {
                if (!IdentitySafety.ValidObservation(value, batch.EndpointId, batch.AgentId, batch.InstallationId)) { rejected[value.EventId] = "invalid-event"; continue; }
                var key = $"{tenant}:{value.EventId}";
                if (_events.ContainsKey(key)) duplicates.Add(value.EventId);
                else { _events[key] = value with { ReceivedAt = DateTimeOffset.UtcNow, IngestedAt = DateTimeOffset.UtcNow }; accepted.Add(value.EventId); }
            }
            _health[$"{tenant}:{health.EndpointId}"] = health;
            var ack = new IdentityBatchAcknowledgement(batch.BatchId, accepted, duplicates, rejected, batch.LastSequence, false);
            return Task.FromResult(new IdentityIngestResult(ack, accepted.Count, duplicates.Count, rejected.Count, 0));
        }
    }
    public Task<IdentityEventPage> SearchAsync(string tenant, IdentitySearchRequest request, CancellationToken ct)
    {
        lock (_gate)
        {
            IEnumerable<IdentityObservation> values = _events.Where(x => x.Key.StartsWith(tenant + ':', StringComparison.Ordinal)).Select(x => x.Value);
            if (request.EndpointId is { } endpoint) values = values.Where(x => x.EndpointId == endpoint);
            if (request.Account is { } account) values = values.Where(x => (x.Account?.CanonicalName ?? x.Account?.Name ?? "").Contains(account, StringComparison.OrdinalIgnoreCase));
            if (request.Sid is { } sid) values = values.Where(x => x.Account?.Sid == sid);
            if (request.Domain is { } domain) values = values.Where(x => (x.Account?.Domain ?? "").Contains(domain, StringComparison.OrdinalIgnoreCase));
            if (request.LogonType is { } logonType) values = values.Where(x => x.Logon?.NativeLogonType == logonType);
            if (request.Result is { } result) values = values.Where(x => x.Logon?.Result?.Equals(result, StringComparison.OrdinalIgnoreCase) == true);
            if (request.SourceIp is { } sourceIp) values = values.Where(x => x.Logon?.SourceIp == sourceIp);
            if (request.RemoteSession is { } remote) values = values.Where(x => x.Session?.Remote == remote);
            if (request.SessionId is { } session) values = values.Where(x => x.Session?.SessionId == session || x.Token?.SessionId == session);
            if (request.IntegrityLevel is { } integrity) values = values.Where(x => x.Token?.IntegrityLevel?.Equals(integrity, StringComparison.OrdinalIgnoreCase) == true);
            if (request.ElevatedToken is { } elevated) values = values.Where(x => x.Token?.Elevated == elevated);
            if (request.Privilege is { } privilege) values = values.Where(x => x.Privileges.Any(p => p.Name.Equals(privilege, StringComparison.Ordinal)));
            if (request.Process is { } process) values = values.Where(x => x.Process?.ProcessEntityId == process || (x.Process?.ImagePath ?? "").Contains(process, StringComparison.OrdinalIgnoreCase));
            if (request.Quality is { } quality) values = values.Where(x => x.QualityState.Equals(quality, StringComparison.OrdinalIgnoreCase));
            if (request.Kind is { } kind) values = values.Where(x => x.Kind == kind);
            if (request.From is { } from) values = values.Where(x => x.ObservedAt >= from);
            if (request.To is { } to) values = values.Where(x => x.ObservedAt <= to);
            return Task.FromResult(new IdentityEventPage(values.OrderByDescending(x => x.ObservedAt).Take(Math.Clamp(request.PageSize, 1, 500)).ToArray(), null));
        }
    }
    public Task<IdentityObservation?> GetAsync(string tenant, Guid eventId, CancellationToken ct) { lock (_gate) return Task.FromResult(_events.GetValueOrDefault($"{tenant}:{eventId}")); }
    public Task<IdentityEventPage> EntityHistoryAsync(string tenant, Guid endpoint, string entityId, int limit, CancellationToken ct) { lock (_gate) return Task.FromResult(new IdentityEventPage(_events.Where(x => x.Key.StartsWith(tenant + ':', StringComparison.Ordinal)).Select(x => x.Value).Where(x => x.EndpointId == endpoint && (x.Logon?.EntityId == entityId || x.Session?.EntityId == entityId || x.Token?.EntityId == entityId || x.Process?.ProcessEntityId == entityId)).OrderByDescending(x => x.ObservedAt).Take(Math.Clamp(limit, 1, 500)).ToArray(), null)); }
    public Task<IdentityTelemetryHealth?> HealthAsync(string tenant, Guid endpoint, CancellationToken ct) { lock (_gate) return Task.FromResult(_health.GetValueOrDefault($"{tenant}:{endpoint}")); }
    public Task<IReadOnlyList<IdentityObservation>> ListAllAsync(CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<IdentityObservation>>(_events.Values.ToArray()); }
    public Task EnsureAsync(CancellationToken ct) => Task.CompletedTask;
    public Task UpsertAsync(string tenant, IdentityObservation value, CancellationToken ct) { lock (_gate) _events[$"{tenant}:{value.EventId}"] = value; return Task.CompletedTask; }
    public Task<bool> HealthAsync(CancellationToken ct) => Task.FromResult(true);
}

public sealed class FileIdentityPolicyRepository : IIdentityPolicyRepository
{
    readonly object _gate = new(); readonly List<IdentityPolicyVersion> _versions = [];
    readonly Dictionary<string, Guid> _assignments = []; readonly Dictionary<string, IdentityPolicyAcknowledgement> _acks = [];
    public Task<IReadOnlyList<IdentityPolicyVersion>> ListAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<IdentityPolicyVersion>>(_versions.Where(x => x.TenantId == tenant).ToArray()); }
    public Task<IdentityPolicyVersion> CreateAsync(string tenant, string actor, string name, IdentityTelemetryPolicy policy, CancellationToken ct) { var errors = IdentitySafety.Validate(policy); if (errors.Count > 0) throw new EnrollmentConflictException("IDENTITY_POLICY_INVALID", string.Join(' ', errors.SelectMany(x => x.Value))); lock (_gate) { var value = new IdentityPolicyVersion(Guid.NewGuid(), tenant, name, _versions.Where(x => x.TenantId == tenant && x.Name == name).Select(x => x.Version).DefaultIfEmpty().Max() + 1, policy, IdentitySafety.EvidenceHash(policy), "active", DateTimeOffset.UtcNow, actor); _versions.Add(value); return Task.FromResult(value); } }
    public Task AssignAsync(string tenant, Guid policyId, Guid? endpoint, string actor, CancellationToken ct) { lock (_gate) { if (!_versions.Any(x => x.TenantId == tenant && x.Id == policyId)) throw new EnrollmentConflictException("IDENTITY_POLICY_NOT_FOUND", "Policy unavailable."); _assignments[$"{tenant}:{endpoint?.ToString() ?? "default"}"] = policyId; return Task.CompletedTask; } }
    public async Task<EffectiveIdentityPolicy> EffectiveAsync(string tenant, Guid endpoint, CancellationToken ct) { var all = await ListAsync(tenant, ct); lock (_gate) { var id = _assignments.GetValueOrDefault($"{tenant}:{endpoint}", _assignments.GetValueOrDefault($"{tenant}:default")); var value = all.FirstOrDefault(x => x.Id == id) ?? new(Guid.Empty, tenant, "safe-default", 0, new(), IdentitySafety.EvidenceHash(new IdentityTelemetryPolicy()), "default", DateTimeOffset.UnixEpoch, "system"); var ack = _acks.GetValueOrDefault($"{tenant}:{endpoint}"); return new(value, id == Guid.Empty ? "default" : "assigned", endpoint, ack?.AcknowledgedAt, ack?.Applied == true ? ack.Version : null, ack?.Applied == false ? ack.Version : null, ack?.ValidationError, ack is null || ack.Version != value.Version); } }
    public Task AcknowledgeAsync(string tenant, Guid endpoint, IdentityPolicyAcknowledgement acknowledgement, CancellationToken ct) { lock (_gate) { _acks[$"{tenant}:{endpoint}"] = acknowledgement; return Task.CompletedTask; } }
}

public sealed class FileIdentityExportRepository : IIdentityExportRepository
{
    readonly object _gate = new(); readonly Dictionary<Guid, IdentityExportJob> _jobs = [];
    public Task<IdentityExportJob> CreateAsync(string tenant, string actor, IdentityExportCreateRequest request, CancellationToken ct) { lock (_gate) { var now = DateTimeOffset.UtcNow; var job = new IdentityExportJob(Guid.NewGuid(), tenant, actor, FileExportState.Pending, request.Format, request.Query with { Cursor = null }, request.Fields ?? [], request.MaximumRecords, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), now, now, now.AddMinutes(15)); _jobs[job.Id] = job; return Task.FromResult(job); } }
    public Task<IdentityExportJob?> GetAsync(string tenant, Guid id, CancellationToken ct) { lock (_gate) return Task.FromResult(_jobs.GetValueOrDefault(id) is { } x && x.TenantId == tenant ? x : null); }
    public Task<IdentityExportJob?> ClaimAsync(CancellationToken ct) { lock (_gate) { var value = _jobs.Values.FirstOrDefault(x => x.State == FileExportState.Pending); if (value is null) return Task.FromResult<IdentityExportJob?>(null); var changed = value with { State = FileExportState.Running, StartedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow }; _jobs[value.Id] = changed; return Task.FromResult<IdentityExportJob?>(changed); } }
    public Task CompleteAsync(Guid id, int count, long size, string sha256, DateTimeOffset at, CancellationToken ct) { lock (_gate) _jobs[id] = _jobs[id] with { State = FileExportState.Completed, RecordCount = count, OutputSize = size, OutputSha256 = sha256, CompletedAt = at, UpdatedAt = at }; return Task.CompletedTask; }
    public Task FailAsync(Guid id, string code, string summary, CancellationToken ct) { lock (_gate) _jobs[id] = _jobs[id] with { State = FileExportState.Failed, ErrorCode = code, ErrorSummary = summary[..Math.Min(512, summary.Length)], UpdatedAt = DateTimeOffset.UtcNow }; return Task.CompletedTask; }
}
