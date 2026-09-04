using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<ProtectionState>))]
public enum ProtectionState { Protected, Degraded, TamperDetected, RepairPending, Repairing, MaintenanceMode, DisabledByAuthorizedPolicy, Unknown }
[JsonConverter(typeof(JsonStringEnumConverter<ProtectedResourceType>))]
public enum ProtectedResourceType { AgentBinary, RequiredLibrary, AgentService, Configuration, PolicyCache, Certificate, PrivateKey, TelemetryQueue, ResponseReplayState, OrchestrationState, QuarantineStore, ForensicState, IsolationControl, UpdateManifest, InstallationIdentity, CollectorConfiguration }
[JsonConverter(typeof(JsonStringEnumConverter<IntegrityState>))]
public enum IntegrityState { Healthy, Missing, Modified, Replaced, PermissionDrift, InvalidIdentity, Corrupt, RolledBack, Disabled, Stopped, Unknown, MaintenanceSuppressed }
[JsonConverter(typeof(JsonStringEnumConverter<TamperPreventionResult>))]
public enum TamperPreventionResult { Prevented, DetectedOnly, NotObservable, NotPreventableAtPrivilegeBoundary, AuthorizedMaintenance }
[JsonConverter(typeof(JsonStringEnumConverter<RepairState>))]
public enum RepairState { NotSupported, NotRequested, Pending, Repairing, Succeeded, Failed }
[JsonConverter(typeof(JsonStringEnumConverter<MaintenanceState>))]
public enum MaintenanceState { PendingApproval, Approved, Active, Expired, Rejected, Cancelled }

public sealed record ProtectedResourceDefinition(string ResourceId, ProtectedResourceType Type, string ObjectName,
    string ExpectedOwner, string? ExpectedSecurityDescriptor, string? ExpectedSha256, string? ExpectedNativeIdentity,
    string? ExpectedSigner, string? ExpectedVersion, string VerificationMethod, string? RepairMethod,
    bool Required = true, bool Sensitive = false);
public sealed record AgentProtectionPolicy(string SchemaVersion, int Version, string TenantId, Guid EndpointId,
    string InstallationId, bool Enabled, int VerificationIntervalSeconds, int MaximumHashBytesPerCycle,
    int MaximumEventsPerReport, bool RepairServiceConfiguration, bool RepairOwnedAcls, bool RepairIsolationControls,
    ProtectedResourceDefinition[] Resources, DateTimeOffset CreatedAt, string Author, string PreviousPolicyHash,
    string PolicyHash, string Compatibility = "agent-self-protection.v1");
public sealed record SignedProtectionPolicyEnvelope(AgentProtectionPolicy Policy, DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt, string Nonce, string SignatureAlgorithm, string SignatureKeyId, string Signature);
public sealed record ResourceIntegrityResult(string ResourceId, ProtectedResourceType Type, IntegrityState State,
    string ObjectName, string ExpectedState, string ObservedState, string VerificationMethod, string EvidenceHash,
    DateTimeOffset VerifiedAt, TamperPreventionResult Prevention, RepairState Repair, string? ActorProcess,
    string[] Quality, string Provenance = "agent-self-protection.v1");
public sealed record TamperEvent(string SchemaVersion, Guid EventId, string TenantId, Guid EndpointId,
    string InstallationId, string EventType, string ResourceId, ProtectedResourceType ResourceType,
    string ExpectedState, string ObservedState, string EvidenceHash, TamperPreventionResult Prevention,
    RepairState Repair, string? ActorProcess, DateTimeOffset OccurredAt, int PolicyVersion, string[] Evidence,
    string Provenance, string EventHash);
public sealed record ProtectionSnapshot(string SchemaVersion, string TenantId, Guid EndpointId,
    string InstallationId, int PolicyVersion, ProtectionState State, DateTimeOffset VerifiedAt,
    ResourceIntegrityResult[] Resources, long TamperCount, int UnresolvedDrift, RepairState Repair,
    bool MaintenanceMode, DateTimeOffset? MaintenanceExpiresAt, string AgentVersion, string SnapshotHash);
public sealed record ProtectionReport(ProtectionSnapshot Snapshot, TamperEvent[] Events);
public sealed record MaintenanceRequest(Guid EndpointId, string InstallationId, string Reason,
    string[] Capabilities, DateTimeOffset StartsAt, DateTimeOffset ExpiresAt);
public sealed record MaintenanceAuthorization(string SchemaVersion, Guid MaintenanceId, string TenantId,
    Guid EndpointId, string InstallationId, string Requester, string? Approver, string Reason,
    string[] Capabilities, DateTimeOffset StartsAt, DateTimeOffset ExpiresAt, MaintenanceState State,
    string RequestHash, string Nonce, DateTimeOffset CreatedAt, DateTimeOffset? ApprovedAt,
    string SignatureAlgorithm, string SignatureKeyId, string Signature);
public sealed record MaintenanceApproval(string RequestHash, string Reason);
public sealed record RepairRequest(Guid EndpointId, string InstallationId, string ResourceId, string Reason);
public sealed record RepairRecord(Guid RepairId, string TenantId, Guid EndpointId, string InstallationId,
    string ResourceId, string Requester, string Reason, RepairState State, DateTimeOffset RequestedAt,
    DateTimeOffset? CompletedAt, string Result, string AuditHash);
public sealed record ProtectionHealth(long ProtectedEndpoints, long DegradedEndpoints, long TamperEvents,
    long PreventedTamper, long DetectedOnlyTamper, long RepairAttempts, long RepairSucceeded, long RepairFailed,
    long PolicyFailures, long IdentityFailures, long ServiceDrift, long FileDrift, long IsolationDrift,
    long MaintenanceSessions, DateTimeOffset UpdatedAt);

public interface IAgentProtectionRepository
{
    Task<AgentProtectionPolicy> PutPolicyAsync(string tenant, string actor, AgentProtectionPolicy policy, CancellationToken ct);
    Task<AgentProtectionPolicy?> PolicyAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task<ProtectionSnapshot> ReportAsync(string tenant, Guid endpoint, string installation, ProtectionReport report, CancellationToken ct);
    Task<ProtectionSnapshot?> SnapshotAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task<IReadOnlyList<TamperEvent>> EventsAsync(string tenant, Guid? endpoint, int limit, CancellationToken ct);
    Task<MaintenanceAuthorization> RequestMaintenanceAsync(string tenant, string actor, MaintenanceRequest request, CancellationToken ct);
    Task<MaintenanceAuthorization> ApproveMaintenanceAsync(string tenant, Guid id, string actor, MaintenanceApproval approval, CancellationToken ct);
    Task<MaintenanceAuthorization> FinalizeMaintenanceAsync(string tenant, Guid id, string algorithm, string keyId, string signature, CancellationToken ct);
    Task<MaintenanceAuthorization?> MaintenanceAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<MaintenanceAuthorization>> ActiveMaintenanceAsync(string tenant, Guid endpoint, string installation, CancellationToken ct);
    Task<RepairRecord> RequestRepairAsync(string tenant, string actor, RepairRequest request, CancellationToken ct);
    Task<RepairRecord?> RepairAsync(string tenant, Guid id, CancellationToken ct);
    Task<ProtectionHealth> HealthAsync(string tenant, CancellationToken ct);
}

public static class AgentProtectionSafety
{
    public const int MaximumResources = 64, MaximumEvents = 128, MaximumCapabilities = 16,
        MaximumObjectName = 1024, MinimumVerificationSeconds = 30, MaximumVerificationSeconds = 3600,
        MaximumMaintenanceSeconds = 3600, MaximumHashBytes = 256 * 1024 * 1024;
    public static readonly HashSet<string> MaintenanceCapabilities = new(StringComparer.Ordinal)
    { "upgrade", "uninstall", "repair", "certificate-rotation", "controlled-troubleshooting" };
    public static readonly HashSet<string> RepairMethods = new(StringComparer.Ordinal)
    { "service-startup", "owned-acl", "isolation-rules", "signed-policy-cache", "service-restart" };
    public static readonly IReadOnlyDictionary<string, string> TamperPack = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["agent.file.replaced"] = "Agent binary replacement",
        ["agent.service.disabled"] = "Agent service disabled",
        ["agent.service.deleted"] = "Agent service deleted",
        ["agent.policy.tampered"] = "Agent policy signature failure",
        ["agent.identity.invalid"] = "Agent certificate identity mismatch",
        ["agent.isolation.drift"] = "Isolation control drift",
        ["agent.replay_state.tampered"] = "Response replay-state tamper",
        ["agent.maintenance.unauthorized"] = "Unauthorized maintenance attempt"
    };
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))).AsSpan(0, 16));
    public static string PolicyHash(AgentProtectionPolicy policy) => Hash(policy with { PolicyHash = "", CreatedAt = default });
    public static string SnapshotHash(ProtectionSnapshot snapshot) => Hash(snapshot with { SnapshotHash = "" });
    public static string EventHash(TamperEvent value) => Hash(value with { EventHash = "" });
    public static string MaintenanceHash(string tenant, string actor, MaintenanceRequest value) => Hash(new { tenant, actor, value.EndpointId, value.InstallationId, value.Reason, capabilities = value.Capabilities.Order(), value.StartsAt, value.ExpiresAt });
    public static string PolicyPayload(SignedProtectionPolicyEnvelope value) => string.Join('\n', value.Policy.PolicyHash, value.Policy.TenantId, value.Policy.EndpointId.ToString("D"), value.Policy.InstallationId, value.Policy.Version, value.IssuedAt.ToUniversalTime().ToString("O"), value.ExpiresAt.ToUniversalTime().ToString("O"), value.Nonce);
    public static string MaintenancePayload(MaintenanceAuthorization value) => string.Join('\n', value.MaintenanceId.ToString("D"), value.TenantId, value.EndpointId.ToString("D"), value.InstallationId, value.RequestHash, value.StartsAt.ToUniversalTime().ToString("O"), value.ExpiresAt.ToUniversalTime().ToString("O"), value.Nonce);
    public static bool VerifyPolicy(SignedProtectionPolicyEnvelope value, string authorityPem, string tenant, Guid endpoint, string installation, int currentVersion)
    {
        if (value.ExpiresAt <= DateTimeOffset.UtcNow || value.IssuedAt > DateTimeOffset.UtcNow.AddMinutes(2) || value.Policy.TenantId != tenant || value.Policy.EndpointId != endpoint || value.Policy.InstallationId != installation || value.Policy.Version < currentVersion || value.Policy.PolicyHash != PolicyHash(value.Policy)) return false;
        return Verify(authorityPem, PolicyPayload(value), value.Signature, value.SignatureAlgorithm);
    }
    public static bool VerifyMaintenance(MaintenanceAuthorization value, string authorityPem, string tenant, Guid endpoint, string installation)
    {
        if (value.State != MaintenanceState.Approved || value.Approver is null || value.Approver == value.Requester || value.StartsAt > DateTimeOffset.UtcNow || value.ExpiresAt <= DateTimeOffset.UtcNow || value.ExpiresAt - value.StartsAt > TimeSpan.FromSeconds(MaximumMaintenanceSeconds) || value.TenantId != tenant || value.EndpointId != endpoint || value.InstallationId != installation || value.Capabilities.Length is < 1 or > MaximumCapabilities || value.Capabilities.Any(x => !MaintenanceCapabilities.Contains(x)) || value.RequestHash != MaintenanceHash(value.TenantId, value.Requester, new(value.EndpointId, value.InstallationId, value.Reason, value.Capabilities, value.StartsAt, value.ExpiresAt))) return false;
        return Verify(authorityPem, MaintenancePayload(value), value.Signature, value.SignatureAlgorithm);
    }
    static bool Verify(string pem, string payload, string signature, string algorithm)
    {
        try { using var certificate = X509Certificate2.CreateFromPem(pem); using var rsa = certificate.GetRSAPublicKey(); return algorithm == "rsa-sha256-ca-v1" && rsa is not null && rsa.VerifyData(Encoding.UTF8.GetBytes(payload), Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); }
        catch (Exception e) when (e is CryptographicException or FormatException) { return false; }
    }
    public static IReadOnlyDictionary<string, string[]> ValidatePolicy(AgentProtectionPolicy p)
    {
        var errors = new Dictionary<string, string[]>();
        if (p.Version < 1 || p.VerificationIntervalSeconds is < MinimumVerificationSeconds or > MaximumVerificationSeconds || p.MaximumHashBytesPerCycle is < 1 or > MaximumHashBytes || p.MaximumEventsPerReport is < 1 or > MaximumEvents) errors["bounds"] = ["Policy verification bounds are invalid."];
        if (p.EndpointId == Guid.Empty || string.IsNullOrWhiteSpace(p.InstallationId) || p.InstallationId.Length > 128) errors["binding"] = ["Endpoint and installation binding are required."];
        if (p.Resources.Length is < 1 or > MaximumResources || p.Resources.Select(x => x.ResourceId).Distinct(StringComparer.Ordinal).Count() != p.Resources.Length) errors["resources"] = ["Resource inventory is empty, excessive, or duplicated."];
        foreach (var r in p.Resources) { if (string.IsNullOrWhiteSpace(r.ResourceId) || r.ResourceId.Length > 128 || string.IsNullOrWhiteSpace(r.ObjectName) || r.ObjectName.Length > MaximumObjectName || r.RepairMethod is not null && !RepairMethods.Contains(r.RepairMethod)) errors[$"resource.{r.ResourceId}"] = ["Protected resource definition is invalid."]; }
        if (p.PolicyHash.Length > 0 && p.PolicyHash != PolicyHash(p)) errors["hash"] = ["Policy hash is invalid."];
        return errors;
    }
    public static ProtectionState State(ResourceIntegrityResult[] resources, bool maintenance, bool enabled)
    {
        if (!enabled) return ProtectionState.DisabledByAuthorizedPolicy;
        if (maintenance) return ProtectionState.MaintenanceMode;
        if (resources.Length == 0) return ProtectionState.Unknown;
        if (resources.Any(x => x.State is IntegrityState.Modified or IntegrityState.Replaced or IntegrityState.InvalidIdentity or IntegrityState.Corrupt or IntegrityState.RolledBack or IntegrityState.Disabled)) return ProtectionState.TamperDetected;
        if (resources.Any(x => x.State is not IntegrityState.Healthy)) return ProtectionState.Degraded;
        return ProtectionState.Protected;
    }
    public static string EventType(ResourceIntegrityResult r) => r.Type switch
    {
        ProtectedResourceType.AgentBinary or ProtectedResourceType.RequiredLibrary => r.State == IntegrityState.Replaced ? "agent.file.replaced" : "agent.file.modified",
        ProtectedResourceType.AgentService => r.State == IntegrityState.Missing ? "agent.service.deleted" : r.State == IntegrityState.Disabled ? "agent.service.disabled" : r.State == IntegrityState.Stopped ? "agent.service.stopped" : "agent.service.configuration_changed",
        ProtectedResourceType.Certificate or ProtectedResourceType.PrivateKey or ProtectedResourceType.InstallationIdentity => "agent.identity.invalid",
        ProtectedResourceType.PolicyCache or ProtectedResourceType.Configuration or ProtectedResourceType.CollectorConfiguration => "agent.policy.tampered",
        ProtectedResourceType.TelemetryQueue => "agent.queue.tampered",
        ProtectedResourceType.ResponseReplayState => "agent.replay_state.tampered",
        ProtectedResourceType.QuarantineStore => "agent.quarantine.tampered",
        ProtectedResourceType.IsolationControl => "agent.isolation.drift",
        _ => "agent.local_state.tampered"
    };
}

public class FileAgentProtectionRepository : IAgentProtectionRepository, IDisposable
{
    readonly SemaphoreSlim gate = new(1, 1); readonly ConcurrentDictionary<(string, Guid), AgentProtectionPolicy> policies = new(); readonly ConcurrentDictionary<(string, Guid), ProtectionSnapshot> snapshots = new(); readonly ConcurrentDictionary<(string, Guid), TamperEvent> events = new(); readonly ConcurrentDictionary<(string, Guid), MaintenanceAuthorization> maintenance = new(); readonly ConcurrentDictionary<(string, Guid), RepairRecord> repairs = new();
    protected virtual Task PersistPolicyAsync(AgentProtectionPolicy p, CancellationToken ct) { policies[(p.TenantId, p.EndpointId)] = p; return Task.CompletedTask; }
    protected virtual Task PersistReportAsync(ProtectionSnapshot s, TamperEvent[] e, CancellationToken ct) { snapshots[(s.TenantId, s.EndpointId)] = s; foreach (var x in e) events.TryAdd((x.TenantId, x.EventId), x); return Task.CompletedTask; }
    protected virtual Task PersistMaintenanceAsync(MaintenanceAuthorization value, CancellationToken ct) { maintenance[(value.TenantId, value.MaintenanceId)] = value; return Task.CompletedTask; }
    protected virtual Task PersistRepairAsync(RepairRecord value, CancellationToken ct) { repairs[(value.TenantId, value.RepairId)] = value; return Task.CompletedTask; }
    protected virtual Task<IReadOnlyList<AgentProtectionPolicy>> LoadPoliciesAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<AgentProtectionPolicy>>(policies.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<ProtectionSnapshot>> LoadSnapshotsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<ProtectionSnapshot>>(snapshots.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<TamperEvent>> LoadEventsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<TamperEvent>>(events.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<MaintenanceAuthorization>> LoadMaintenanceAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<MaintenanceAuthorization>>(maintenance.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<RepairRecord>> LoadRepairsAsync(string tenant, CancellationToken ct) => Task.FromResult<IReadOnlyList<RepairRecord>>(repairs.Where(x => x.Key.Item1 == tenant).Select(x => x.Value).ToArray());
    public async Task<AgentProtectionPolicy> PutPolicyAsync(string tenant, string actor, AgentProtectionPolicy input, CancellationToken ct)
    {
        if (input.TenantId != tenant) throw new EnrollmentConflictException("PROTECTION_TENANT", "Policy tenant binding is invalid."); var errors = AgentProtectionSafety.ValidatePolicy(input); if (errors.Count > 0) throw new EnrollmentConflictException("PROTECTION_POLICY_INVALID", string.Join("; ", errors.SelectMany(x => x.Value)));
        await gate.WaitAsync(ct); try { var prior = await PolicyAsync(tenant, input.EndpointId, ct); if (prior is not null && (input.Version <= prior.Version || input.PreviousPolicyHash != prior.PolicyHash)) throw new EnrollmentConflictException("PROTECTION_POLICY_DOWNGRADE", "Policy version must increase and bind the prior hash."); var value = input with { Author = actor, CreatedAt = DateTimeOffset.UtcNow, PolicyHash = "" }; value = value with { PolicyHash = AgentProtectionSafety.PolicyHash(value) }; await PersistPolicyAsync(value, ct); return value; } finally { gate.Release(); }
    }
    public async Task<AgentProtectionPolicy?> PolicyAsync(string tenant, Guid endpoint, CancellationToken ct) => (await LoadPoliciesAsync(tenant, ct)).Where(x => x.EndpointId == endpoint).OrderByDescending(x => x.Version).FirstOrDefault();
    public async Task<ProtectionSnapshot> ReportAsync(string tenant, Guid endpoint, string installation, ProtectionReport report, CancellationToken ct)
    {
        var policy = await PolicyAsync(tenant, endpoint, ct) ?? throw new KeyNotFoundException(); var s = report.Snapshot; if (s.TenantId != tenant || s.EndpointId != endpoint || s.InstallationId != installation || s.InstallationId != policy.InstallationId || s.PolicyVersion != policy.Version || s.SnapshotHash != AgentProtectionSafety.SnapshotHash(s)) throw new EnrollmentConflictException("PROTECTION_REPORT_BINDING", "Protection report binding or hash is invalid."); if (report.Events.Length > policy.MaximumEventsPerReport || report.Events.Any(e => e.TenantId != tenant || e.EndpointId != endpoint || e.InstallationId != installation || e.PolicyVersion != policy.Version || e.EventHash != AgentProtectionSafety.EventHash(e) || !policy.Resources.Any(r => r.ResourceId == e.ResourceId))) throw new EnrollmentConflictException("TAMPER_EVENT_FORGED", "Tamper event binding, resource, hash, or bounds are invalid."); var required = policy.Resources.Where(x => x.Required).Select(x => x.ResourceId).ToHashSet(StringComparer.Ordinal); if (!required.IsSubsetOf(s.Resources.Select(x => x.ResourceId).ToHashSet(StringComparer.Ordinal)) || s.State != AgentProtectionSafety.State(s.Resources, s.MaintenanceMode, policy.Enabled)) throw new EnrollmentConflictException("PROTECTION_FALSE_HEALTH", "Protection status omits required resources or falsely reports health."); await PersistReportAsync(s, report.Events, ct); return s;
    }
    public async Task<ProtectionSnapshot?> SnapshotAsync(string tenant, Guid endpoint, CancellationToken ct) => (await LoadSnapshotsAsync(tenant, ct)).Where(x => x.EndpointId == endpoint).OrderByDescending(x => x.VerifiedAt).FirstOrDefault();
    public async Task<IReadOnlyList<TamperEvent>> EventsAsync(string tenant, Guid? endpoint, int limit, CancellationToken ct) { if (limit is < 1 or > 500) throw new EnrollmentConflictException("TAMPER_PAGE_BOUNDS", "Tamper event limit must be 1-500."); return (await LoadEventsAsync(tenant, ct)).Where(x => endpoint is null || x.EndpointId == endpoint).OrderByDescending(x => x.OccurredAt).Take(limit).ToArray(); }
    public async Task<MaintenanceAuthorization> RequestMaintenanceAsync(string tenant, string actor, MaintenanceRequest request, CancellationToken ct)
    {
        if (request.EndpointId == Guid.Empty || string.IsNullOrWhiteSpace(request.InstallationId) || request.Capabilities.Length is < 1 or > AgentProtectionSafety.MaximumCapabilities || request.Capabilities.Any(x => !AgentProtectionSafety.MaintenanceCapabilities.Contains(x)) || request.StartsAt < DateTimeOffset.UtcNow.AddMinutes(-1) || request.ExpiresAt <= request.StartsAt || request.ExpiresAt - request.StartsAt > TimeSpan.FromSeconds(AgentProtectionSafety.MaximumMaintenanceSeconds) || string.IsNullOrWhiteSpace(request.Reason) || request.Reason.Length > 2048) throw new EnrollmentConflictException("MAINTENANCE_INVALID", "Maintenance request binding, scope, duration, or reason is invalid."); var policy = await PolicyAsync(tenant, request.EndpointId, ct) ?? throw new KeyNotFoundException(); if (policy.InstallationId != request.InstallationId) throw new EnrollmentConflictException("MAINTENANCE_INSTALLATION", "Maintenance request targets a stale installation."); var value = new MaintenanceAuthorization("maintenance-authorization.v1", Guid.NewGuid(), tenant, request.EndpointId, request.InstallationId, actor, null, request.Reason, request.Capabilities.Distinct(StringComparer.Ordinal).Order().ToArray(), request.StartsAt, request.ExpiresAt, MaintenanceState.PendingApproval, AgentProtectionSafety.MaintenanceHash(tenant, actor, request), Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, null, "rsa-sha256-ca-v1", "pending", ""); await PersistMaintenanceAsync(value, ct); return value;
    }
    public async Task<MaintenanceAuthorization> ApproveMaintenanceAsync(string tenant, Guid id, string actor, MaintenanceApproval approval, CancellationToken ct)
    {
        var value = await MaintenanceAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); if (value.State != MaintenanceState.PendingApproval || value.Requester == actor || value.RequestHash != approval.RequestHash || value.ExpiresAt <= DateTimeOffset.UtcNow || string.IsNullOrWhiteSpace(approval.Reason)) throw new EnrollmentConflictException("MAINTENANCE_APPROVAL_INVALID", "Maintenance approval is forged, replayed, stale, or lacks separation."); value = value with { State = MaintenanceState.Approved, Approver = actor, ApprovedAt = DateTimeOffset.UtcNow }; await PersistMaintenanceAsync(value, ct); return value;
    }
    public async Task<MaintenanceAuthorization> FinalizeMaintenanceAsync(string tenant, Guid id, string algorithm, string keyId, string signature, CancellationToken ct) { var value = await MaintenanceAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); if (value.State != MaintenanceState.Approved || value.Approver is null || value.Signature.Length > 0 || algorithm != "rsa-sha256-ca-v1" || string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(signature)) throw new EnrollmentConflictException("MAINTENANCE_SIGNING_INVALID", "Only a newly approved maintenance authorization may be signed."); value = value with { SignatureAlgorithm = algorithm, SignatureKeyId = keyId, Signature = signature }; await PersistMaintenanceAsync(value, ct); return value; }
    public async Task<MaintenanceAuthorization?> MaintenanceAsync(string tenant, Guid id, CancellationToken ct) => (await LoadMaintenanceAsync(tenant, ct)).FirstOrDefault(x => x.MaintenanceId == id);
    public async Task<IReadOnlyList<MaintenanceAuthorization>> ActiveMaintenanceAsync(string tenant, Guid endpoint, string installation, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow; var values = await LoadMaintenanceAsync(tenant, ct);
        foreach (var expired in values.Where(x => x.EndpointId == endpoint && x.InstallationId == installation && x.State == MaintenanceState.Approved && x.ExpiresAt <= now)) await PersistMaintenanceAsync(expired with { State = MaintenanceState.Expired }, ct);
        return values.Where(x => x.EndpointId == endpoint && x.InstallationId == installation && x.State == MaintenanceState.Approved && x.StartsAt <= now && x.ExpiresAt > now).ToArray();
    }
    public async Task<RepairRecord> RequestRepairAsync(string tenant, string actor, RepairRequest request, CancellationToken ct)
    {
        var policy = await PolicyAsync(tenant, request.EndpointId, ct) ?? throw new KeyNotFoundException(); var resource = policy.Resources.SingleOrDefault(x => x.ResourceId == request.ResourceId) ?? throw new KeyNotFoundException(); if (policy.InstallationId != request.InstallationId || resource.RepairMethod is null || !AgentProtectionSafety.RepairMethods.Contains(resource.RepairMethod) || string.IsNullOrWhiteSpace(request.Reason)) throw new EnrollmentConflictException("REPAIR_NOT_SUPPORTED", "Repair is unsupported or targets a stale installation."); var value = new RepairRecord(Guid.NewGuid(), tenant, request.EndpointId, request.InstallationId, request.ResourceId, actor, request.Reason, RepairState.Pending, DateTimeOffset.UtcNow, null, "pending-agent-verification", AgentProtectionSafety.Hash(new { tenant, actor, request })); await PersistRepairAsync(value, ct); return value;
    }
    public async Task<RepairRecord?> RepairAsync(string tenant, Guid id, CancellationToken ct) => (await LoadRepairsAsync(tenant, ct)).FirstOrDefault(x => x.RepairId == id);
    public async Task<ProtectionHealth> HealthAsync(string tenant, CancellationToken ct)
    {
        var s = await LoadSnapshotsAsync(tenant, ct); var e = await LoadEventsAsync(tenant, ct); var r = await LoadRepairsAsync(tenant, ct); var m = await LoadMaintenanceAsync(tenant, ct); return new(s.LongCount(x => x.State == ProtectionState.Protected), s.LongCount(x => x.State is ProtectionState.Degraded or ProtectionState.TamperDetected), e.Count, e.LongCount(x => x.Prevention == TamperPreventionResult.Prevented), e.LongCount(x => x.Prevention is TamperPreventionResult.DetectedOnly or TamperPreventionResult.NotPreventableAtPrivilegeBoundary), r.Count, r.LongCount(x => x.State == RepairState.Succeeded), r.LongCount(x => x.State == RepairState.Failed), e.LongCount(x => x.EventType == "agent.policy.tampered"), e.LongCount(x => x.EventType == "agent.identity.invalid"), e.LongCount(x => x.ResourceType == ProtectedResourceType.AgentService), e.LongCount(x => x.ResourceType is ProtectedResourceType.AgentBinary or ProtectedResourceType.RequiredLibrary), e.LongCount(x => x.ResourceType == ProtectedResourceType.IsolationControl), m.LongCount(x => x.State is MaintenanceState.Approved or MaintenanceState.Active), DateTimeOffset.UtcNow);
    }
    public void Dispose() { gate.Dispose(); GC.SuppressFinalize(this); }
}
