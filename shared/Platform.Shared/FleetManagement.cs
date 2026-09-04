using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<UpdateState>))]
public enum UpdateState { NotEligible, Eligible, Assigned, WaitingForRing, WaitingForWindow, Downloading, Downloaded, Verifying, Staged, Installing, Restarting, VerifyingInstall, Succeeded, Failed, RollbackPending, RollingBack, RolledBack, Paused, Cancelled, Expired, Unknown }
[JsonConverter(typeof(JsonStringEnumConverter<RolloutState>))]
public enum RolloutState { Draft, Ready, Running, Paused, Cancelling, Cancelled, Succeeded, Failed }
[JsonConverter(typeof(JsonStringEnumConverter<UpdateEligibility>))]
public enum UpdateEligibility { Eligible, UnsupportedPlatform, UnsupportedArchitecture, VersionTooOld, AlreadyCurrent, Unhealthy, InsufficientDisk, Busy, Isolated, PackageUnavailable, PolicyDisabled }

public sealed record FleetEndpointMetadata(string TenantId, Guid EndpointId, string InstallationId,
    string SchemaVersion, string EnrollmentStatus, DateTimeOffset? LastPolicyAcknowledgment,
    UpdateState LastUpdateStatus, UpdateEligibility Eligibility, string RingId, string[] GroupIds,
    string[] Tags, string MaintenanceState, string ProtectionState, string TelemetryHealth,
    string ResponseHealth, string OnlineState, DateTimeOffset UpdatedAt);
public sealed record FleetEndpointView(Guid EndpointId, string TenantId, string InstallationId, string Hostname,
    string Platform, string OsVersion, string Architecture, string AgentVersion, string CapabilityVersion,
    string EnrollmentStatus, DateTimeOffset? LastHeartbeat, DateTimeOffset? LastPolicyAcknowledgment,
    UpdateState LastUpdateStatus, UpdateEligibility Eligibility, string RingId, string[] GroupIds,
    string[] Tags, string MaintenanceState, string ProtectionState, string TelemetryHealth,
    string ResponseHealth, string OnlineState);

public sealed record FleetGroupRule(string Field, string Operator, string Value);
public sealed record FleetGroup(Guid GroupId, string TenantId, string Name, string Description,
    FleetGroupRule[] Rules, Guid[] ExplicitMembers, int Version, DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt, string Actor, string GroupHash);
public sealed record FleetGroupRequest(string Name, string Description, FleetGroupRule[] Rules,
    Guid[] ExplicitMembers, int Version, string PreviousHash = "");
public sealed record FleetTagRequest(Guid[] EndpointIds, string[] Add, string[] Remove, string Reason);

public sealed record DeploymentRing(string RingId, string Name, int Order, int MaxConcurrency,
    int DelaySeconds, int MinimumHealthySeconds, double SuccessThresholdPercent,
    double FailureThresholdPercent, int MinimumSampleSize);
public sealed record DeploymentRingPolicy(Guid PolicyId, string TenantId, int Version, bool Enabled,
    DeploymentRing[] Rings, DateTimeOffset CreatedAt, string Actor, string PreviousHash, string PolicyHash);

public sealed record AgentUpdateManifest(string SchemaVersion, Guid PackageId, string Version,
    string Platform, string Architecture, string MinimumCurrentVersion, string TargetVersion,
    string PackageType, long PackageSize, string PackageSha256, string ManifestSha256,
    string[] RequiredCapabilities, string ReleaseChannel, DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt, bool RollbackCompatible, string? RollbackFromVersion,
    string ReleaseNotes, string Provenance, string ObjectId);
public sealed record SignedAgentUpdatePackage(AgentUpdateManifest Manifest, string SigningCertificatePem,
    string SigningCertificateIdentity, string SignatureAlgorithm, string Signature, bool Revoked,
    DateTimeOffset? RevokedAt, string? RevokedBy, string? RevocationReason);
public sealed record PackageRegistrationRequest(AgentUpdateManifest Manifest, string SigningCertificatePem,
    string SignatureAlgorithm, string Signature);

public sealed record AgentUpdatePolicy(Guid PolicyId, string TenantId, int Version, bool Enabled,
    string TargetVersion, string ReleaseChannel, Guid RingPolicyId, int MaxConcurrentUpdates,
    int MaxConcurrentDownloads, long BandwidthBytesPerSecond, int RetryLimit, int RetryBackoffSeconds,
    long MinimumFreeDiskBytes, bool RequireAcPower, string MaintenanceWindowStartUtc,
    string MaintenanceWindowEndUtc, int CacheMaximumPackages, long CacheMaximumBytes,
    double AutoPauseFailurePercent, int AutoPauseMinimumSampleSize, bool AutoAdvance,
    bool RollbackOnHealthFailure, string OfflineBehavior, DateTimeOffset CreatedAt, string Actor,
    string PreviousHash, string PolicyHash);

public sealed record RolloutCreateRequest(Guid PackageId, Guid PolicyId, Guid[] EndpointIds,
    string[] RingIds, string Reason);
public sealed record FleetRollout(Guid RolloutId, string TenantId, Guid PackageId, string TargetVersion,
    Guid PolicyId, int PolicyVersion, string[] TargetRings, string CreatedBy, RolloutState State,
    string CurrentRing, int TotalEndpoints, int Eligible, int Pending, int Running, int Succeeded,
    int Failed, int RolledBack, int Skipped, int Paused, DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt, string Reason, string RolloutHash);
public sealed record EndpointUpdateAssignment(Guid AssignmentId, string TenantId, Guid RolloutId,
    Guid EndpointId, string InstallationId, Guid PackageId, string RingId, UpdateState State,
    int Attempt, DateTimeOffset AssignedAt, DateTimeOffset ExpiresAt, DateTimeOffset UpdatedAt,
    string? FailureCode, string? ResultHash, string AssignmentHash);
public sealed record EndpointUpdateStatus(Guid AssignmentId, Guid EndpointId, string InstallationId,
    UpdateState State, string CurrentVersion, string? InstalledVersion, string? FailureCode,
    bool ServiceRunning, bool MtlsHealthy, bool TelemetryHealthy, bool PolicyAcknowledged,
    bool QueuesHealthy, bool SelfProtectionHealthy, bool ResponseHealthy, bool LocalIntegrityHealthy,
    long FreeDiskBytes, DateTimeOffset OccurredAt, string EvidenceHash);
public sealed record RolloutPreview(int Total, int Eligible, int Ineligible, IReadOnlyDictionary<string, int> Rings,
    int MaximumConcurrentUpdates, int MaximumConcurrentDownloads, string[] Warnings);
public sealed record FleetUpdateHealth(IReadOnlyDictionary<string, long> VersionDistribution,
    long Eligible, long Pending, long Active, long Succeeded, long Failed, long RolledBack,
    long PausedRollouts, long VerificationFailures, double? DownloadLatencyMilliseconds,
    double? InstallLatencyMilliseconds, long HealthFailures, DateTimeOffset UpdatedAt);
public sealed record FleetAuditEvent(Guid AuditId, string TenantId, string ObjectType, string ObjectId,
    string Action, string Actor, DateTimeOffset OccurredAt, string Reason, string ObjectHash);

public interface IFleetUpdateRepository
{
    Task<FleetEndpointMetadata> PutMetadataAsync(string tenant, FleetEndpointMetadata value, CancellationToken ct);
    Task<IReadOnlyList<FleetEndpointMetadata>> MetadataAsync(string tenant, CancellationToken ct);
    Task<FleetGroup> PutGroupAsync(string tenant, string actor, Guid? id, FleetGroupRequest request, CancellationToken ct);
    Task<IReadOnlyList<FleetGroup>> GroupsAsync(string tenant, CancellationToken ct);
    Task ApplyTagsAsync(string tenant, string actor, FleetTagRequest request, CancellationToken ct);
    Task<DeploymentRingPolicy> PutRingsAsync(string tenant, string actor, DeploymentRingPolicy value, CancellationToken ct);
    Task<DeploymentRingPolicy?> RingsAsync(string tenant, Guid id, CancellationToken ct);
    Task<SignedAgentUpdatePackage> RegisterPackageAsync(string tenant, string actor, PackageRegistrationRequest value, string trustedAuthorityPem, CancellationToken ct);
    Task<SignedAgentUpdatePackage> RevokePackageAsync(string tenant, string actor, Guid id, string reason, CancellationToken ct);
    Task<SignedAgentUpdatePackage?> PackageAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<SignedAgentUpdatePackage>> PackagesAsync(string tenant, CancellationToken ct);
    Task<AgentUpdatePolicy> PutPolicyAsync(string tenant, string actor, AgentUpdatePolicy value, CancellationToken ct);
    Task<AgentUpdatePolicy?> PolicyAsync(string tenant, Guid id, CancellationToken ct);
    Task<RolloutPreview> PreviewAsync(string tenant, RolloutCreateRequest request, CancellationToken ct);
    Task<FleetRollout> CreateRolloutAsync(string tenant, string actor, RolloutCreateRequest request, IReadOnlyDictionary<Guid, string> installations, CancellationToken ct);
    Task<FleetRollout> TransitionRolloutAsync(string tenant, string actor, Guid id, string transition, string reason, CancellationToken ct);
    Task<FleetRollout?> RolloutAsync(string tenant, Guid id, CancellationToken ct);
    Task<IReadOnlyList<FleetRollout>> RolloutsAsync(string tenant, CancellationToken ct);
    Task<EndpointUpdateAssignment?> AssignmentAsync(string tenant, Guid endpoint, string installation, CancellationToken ct);
    Task<EndpointUpdateAssignment> ReportAsync(string tenant, EndpointUpdateStatus status, CancellationToken ct);
    Task<IReadOnlyList<EndpointUpdateAssignment>> AssignmentsAsync(string tenant, Guid rollout, CancellationToken ct);
    Task<IReadOnlyList<FleetAuditEvent>> AuditAsync(string tenant, int limit, CancellationToken ct);
    Task<FleetUpdateHealth> HealthAsync(string tenant, CancellationToken ct);
}

public static class FleetUpdateSafety
{
    public const int MaximumBulkEndpoints = 500, MaximumGroups = 500, MaximumRules = 8,
        MaximumRings = 8, MaximumConcurrentUpdates = 50, MaximumConcurrentDownloads = 100,
        MaximumRetryLimit = 10, MaximumPackageCacheEntries = 5;
    public static readonly HashSet<string> PackageTypes = new(StringComparer.Ordinal) { "platform-bundle-v1", "platform-rollback-bundle-v1" };
    public static readonly HashSet<string> RuleFields = new(StringComparer.Ordinal) { "platform", "architecture", "hostname", "tag" };
    public static readonly HashSet<string> RuleOperators = new(StringComparer.Ordinal) { "equals", "starts-with" };
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))).AsSpan(0, 16));
    public static string ManifestHash(AgentUpdateManifest value) => Hash(value with { ManifestSha256 = "" });
    public static string PackagePayload(AgentUpdateManifest value) => string.Join('\n', value.PackageId.ToString("D"), value.ManifestSha256, value.PackageSha256, value.Version, value.Platform, value.Architecture, value.PackageType, value.PackageSize, value.ExpiresAt.ToUniversalTime().ToString("O"), value.ObjectId);
    public static string PolicyHash(AgentUpdatePolicy value) => Hash(value with { PolicyHash = "", CreatedAt = default, Actor = "" });
    public static string RingHash(DeploymentRingPolicy value) => Hash(value with { PolicyHash = "", CreatedAt = default, Actor = "" });
    public static string GroupHash(FleetGroup value) => Hash(value with { GroupHash = "", CreatedAt = default, UpdatedAt = default, Actor = "" });
    public static bool VersionGreater(string target, string current) => Version.TryParse(target.Split('-')[0], out var t) && Version.TryParse(current.Split('-')[0], out var c) && t > c;
    public static bool VersionEqual(string left, string right) => Version.TryParse(left.Split('-')[0], out var a) && Version.TryParse(right.Split('-')[0], out var b) && a == b;
    public static void ValidateManifest(AgentUpdateManifest m, DateTimeOffset now)
    {
        if (m.SchemaVersion != "agent-update-manifest.v1" || m.PackageId == Guid.Empty || !PackageTypes.Contains(m.PackageType) || m.PackageSize is < 1 or > 536870912 || m.PackageSha256.Length != 64 || m.ManifestSha256 != ManifestHash(m) || m.ExpiresAt <= now || m.CreatedAt > now.AddMinutes(2) || m.ExpiresAt - m.CreatedAt > TimeSpan.FromDays(90) || m.Platform is not ("windows" or "linux" or "macos") || string.IsNullOrWhiteSpace(m.Architecture) || string.IsNullOrWhiteSpace(m.ObjectId) || m.ObjectId.Contains("..", StringComparison.Ordinal) || m.ObjectId.Contains('/') || m.ObjectId.Contains('\\') || !Version.TryParse(m.TargetVersion.Split('-')[0], out _) || !Version.TryParse(m.MinimumCurrentVersion.Split('-')[0], out _))
            throw new EnrollmentConflictException("UPDATE_MANIFEST_INVALID", "Update manifest identity, bounds, hash, expiry, platform, version, or object identity is invalid.");
        if (m.PackageType == "platform-rollback-bundle-v1" && (!m.RollbackCompatible || string.IsNullOrWhiteSpace(m.RollbackFromVersion))) throw new EnrollmentConflictException("ROLLBACK_MANIFEST_INVALID", "Rollback requires an explicit compatible from-version.");
    }
    public static bool VerifyPackage(SignedAgentUpdatePackage value, string trustedAuthorityPem, byte[]? bytes = null, DateTimeOffset? now = null)
    {
        try
        {
            ValidateManifest(value.Manifest, now ?? DateTimeOffset.UtcNow);
            if (value.Revoked || value.SignatureAlgorithm != "rsa-sha256-ca-v1" || bytes is not null && (bytes.LongLength != value.Manifest.PackageSize || !string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), value.Manifest.PackageSha256, StringComparison.OrdinalIgnoreCase))) return false;
            using var trusted = X509Certificate2.CreateFromPem(trustedAuthorityPem); using var signer = X509Certificate2.CreateFromPem(value.SigningCertificatePem);
            using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(trusted); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(signer) || !string.Equals(signer.Thumbprint, value.SigningCertificateIdentity, StringComparison.OrdinalIgnoreCase)) return false;
            using var rsa = signer.GetRSAPublicKey(); return rsa is not null && rsa.VerifyData(Encoding.UTF8.GetBytes(PackagePayload(value.Manifest)), Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception e) when (e is CryptographicException or FormatException or EnrollmentConflictException) { return false; }
    }
    public static void ValidatePolicy(AgentUpdatePolicy p)
    {
        if (p.Version < 1 || p.PolicyId == Guid.Empty || p.RingPolicyId == Guid.Empty || p.MaxConcurrentUpdates is < 1 or > MaximumConcurrentUpdates || p.MaxConcurrentDownloads is < 1 or > MaximumConcurrentDownloads || p.BandwidthBytesPerSecond is < 65536 or > 1073741824 || p.RetryLimit is < 0 or > MaximumRetryLimit || p.RetryBackoffSeconds is < 5 or > 86400 || p.MinimumFreeDiskBytes < 104857600 || p.CacheMaximumPackages is < 1 or > MaximumPackageCacheEntries || p.CacheMaximumBytes < 104857600 || p.AutoPauseFailurePercent is < 1 or > 100 || p.AutoPauseMinimumSampleSize is < 1 or > MaximumBulkEndpoints || p.OfflineBehavior is not ("retain-until-expiry" or "skip")) throw new EnrollmentConflictException("UPDATE_POLICY_INVALID", "Update policy violates safe rollout, resource, retry, or offline bounds.");
    }
    public static void ValidateRings(DeploymentRingPolicy p)
    {
        if (p.Version < 1 || p.Rings.Length is < 1 or > MaximumRings || p.Rings.Select(x => x.RingId).Distinct(StringComparer.Ordinal).Count() != p.Rings.Length || p.Rings.Select(x => x.Order).Distinct().Count() != p.Rings.Length || p.Rings.Any(x => string.IsNullOrWhiteSpace(x.RingId) || x.MaxConcurrency is < 1 or > MaximumConcurrentUpdates || x.DelaySeconds is < 0 or > 604800 || x.MinimumHealthySeconds is < 0 or > 604800 || x.SuccessThresholdPercent is < 1 or > 100 || x.FailureThresholdPercent is < 1 or > 100 || x.MinimumSampleSize is < 1 or > MaximumBulkEndpoints)) throw new EnrollmentConflictException("RING_POLICY_INVALID", "Ring policy order, identity, concurrency, delay, health, or threshold bounds are invalid.");
    }
    public static bool PostInstallHealthy(EndpointUpdateStatus s) => s.State == UpdateState.Succeeded && s.ServiceRunning && s.MtlsHealthy && s.TelemetryHealthy && s.PolicyAcknowledged && s.QueuesHealthy && s.SelfProtectionHealthy && s.ResponseHealthy && s.LocalIntegrityHealthy && s.InstalledVersion is not null;
}

public class FileFleetUpdateRepository : IFleetUpdateRepository, IDisposable
{
    readonly SemaphoreSlim gate = new(1, 1);
    readonly ConcurrentDictionary<(string, Guid), FleetEndpointMetadata> metadata = new();
    readonly ConcurrentDictionary<(string, Guid), FleetGroup> groups = new();
    readonly ConcurrentDictionary<(string, Guid, int), DeploymentRingPolicy> rings = new();
    readonly ConcurrentDictionary<(string, Guid), SignedAgentUpdatePackage> packages = new();
    readonly ConcurrentDictionary<(string, Guid, int), AgentUpdatePolicy> policies = new();
    readonly ConcurrentDictionary<(string, Guid), FleetRollout> rollouts = new();
    readonly ConcurrentDictionary<(string, Guid), EndpointUpdateAssignment> assignments = new();
    readonly ConcurrentDictionary<(string, Guid), FleetAuditEvent> audits = new();
    protected virtual Task PersistMetadataAsync(FleetEndpointMetadata x, CancellationToken ct) { metadata[(x.TenantId, x.EndpointId)] = x; return Task.CompletedTask; }
    protected virtual Task PersistGroupAsync(FleetGroup x, CancellationToken ct) { groups[(x.TenantId, x.GroupId)] = x; return Task.CompletedTask; }
    protected virtual Task PersistRingsAsync(DeploymentRingPolicy x, CancellationToken ct) { rings[(x.TenantId, x.PolicyId, x.Version)] = x; return Task.CompletedTask; }
    protected virtual Task PersistPackageAsync(string tenant, SignedAgentUpdatePackage x, CancellationToken ct) { packages[(tenant, x.Manifest.PackageId)] = x; return Task.CompletedTask; }
    protected virtual Task PersistPolicyAsync(AgentUpdatePolicy x, CancellationToken ct) { policies[(x.TenantId, x.PolicyId, x.Version)] = x; return Task.CompletedTask; }
    protected virtual Task PersistRolloutAsync(FleetRollout x, CancellationToken ct) { rollouts[(x.TenantId, x.RolloutId)] = x; return Task.CompletedTask; }
    protected virtual Task PersistAssignmentAsync(EndpointUpdateAssignment x, CancellationToken ct) { assignments[(x.TenantId, x.AssignmentId)] = x; return Task.CompletedTask; }
    protected virtual Task PersistAuditAsync(FleetAuditEvent x, CancellationToken ct) { audits[(x.TenantId, x.AuditId)] = x; return Task.CompletedTask; }
    protected virtual Task<IReadOnlyList<FleetEndpointMetadata>> LoadMetadataAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<FleetEndpointMetadata>>(metadata.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<FleetGroup>> LoadGroupsAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<FleetGroup>>(groups.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<DeploymentRingPolicy>> LoadRingsAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<DeploymentRingPolicy>>(rings.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<SignedAgentUpdatePackage>> LoadPackagesAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<SignedAgentUpdatePackage>>(packages.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<AgentUpdatePolicy>> LoadPoliciesAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<AgentUpdatePolicy>>(policies.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<FleetRollout>> LoadRolloutsAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<FleetRollout>>(rollouts.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<EndpointUpdateAssignment>> LoadAssignmentsAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<EndpointUpdateAssignment>>(assignments.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    protected virtual Task<IReadOnlyList<FleetAuditEvent>> LoadAuditsAsync(string t, CancellationToken ct) => Task.FromResult<IReadOnlyList<FleetAuditEvent>>(audits.Where(x => x.Key.Item1 == t).Select(x => x.Value).ToArray());
    async Task Audit(string tenant, string actor, string type, string id, string action, string reason, string hash, CancellationToken ct) => await PersistAuditAsync(new(Guid.NewGuid(), tenant, type, id, action, actor, DateTimeOffset.UtcNow, reason, hash), ct);
    public async Task<FleetEndpointMetadata> PutMetadataAsync(string tenant, FleetEndpointMetadata x, CancellationToken ct) { if (x.TenantId != tenant || x.EndpointId == Guid.Empty || string.IsNullOrWhiteSpace(x.InstallationId) || x.Tags.Length > 64 || x.GroupIds.Length > 64) throw new EnrollmentConflictException("FLEET_METADATA_INVALID", "Fleet metadata is invalid or cross-tenant."); x = x with { Tags = x.Tags.Distinct(StringComparer.Ordinal).Order().ToArray(), GroupIds = x.GroupIds.Distinct(StringComparer.Ordinal).Order().ToArray(), UpdatedAt = DateTimeOffset.UtcNow }; await PersistMetadataAsync(x, ct); return x; }
    public Task<IReadOnlyList<FleetEndpointMetadata>> MetadataAsync(string tenant, CancellationToken ct) => LoadMetadataAsync(tenant, ct);
    public async Task<FleetGroup> PutGroupAsync(string tenant, string actor, Guid? id, FleetGroupRequest r, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(r.Name) || r.Name.Length > 128 || r.Description.Length > 1024 || r.Rules.Length > FleetUpdateSafety.MaximumRules || r.ExplicitMembers.Length > FleetUpdateSafety.MaximumBulkEndpoints || r.Rules.Any(x => !FleetUpdateSafety.RuleFields.Contains(x.Field) || !FleetUpdateSafety.RuleOperators.Contains(x.Operator) || string.IsNullOrWhiteSpace(x.Value) || x.Value.Length > 256)) throw new EnrollmentConflictException("FLEET_GROUP_INVALID", "Group name, membership, or deterministic rule bounds are invalid.");
        var existing = id is null ? null : (await LoadGroupsAsync(tenant, ct)).SingleOrDefault(x => x.GroupId == id); if (existing is not null && (r.Version <= existing.Version || r.PreviousHash != existing.GroupHash)) throw new EnrollmentConflictException("FLEET_GROUP_VERSION", "Group updates must increase version and bind the prior hash.");
        var now = DateTimeOffset.UtcNow; var x = new FleetGroup(id ?? Guid.NewGuid(), tenant, r.Name.Trim(), r.Description.Trim(), r.Rules, r.ExplicitMembers.Distinct().Order().ToArray(), r.Version, existing?.CreatedAt ?? now, now, actor, ""); x = x with { GroupHash = FleetUpdateSafety.GroupHash(x) }; await PersistGroupAsync(x, ct); await Audit(tenant, actor, "group", x.GroupId.ToString("D"), existing is null ? "group.created" : "group.updated", x.Name, x.GroupHash, ct); return x;
    }
    public Task<IReadOnlyList<FleetGroup>> GroupsAsync(string tenant, CancellationToken ct) => LoadGroupsAsync(tenant, ct);
    public async Task ApplyTagsAsync(string tenant, string actor, FleetTagRequest r, CancellationToken ct) { if (r.EndpointIds.Length is < 1 or > FleetUpdateSafety.MaximumBulkEndpoints || r.Add.Length + r.Remove.Length > 64 || r.Add.Concat(r.Remove).Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 64) || string.IsNullOrWhiteSpace(r.Reason)) throw new EnrollmentConflictException("FLEET_TAG_INVALID", "Tag operation is empty, excessive, or invalid."); var all = await LoadMetadataAsync(tenant, ct); foreach (var id in r.EndpointIds.Distinct()) { var x = all.SingleOrDefault(m => m.EndpointId == id) ?? throw new KeyNotFoundException(); var tags = x.Tags.ToHashSet(StringComparer.Ordinal); tags.UnionWith(r.Add); tags.ExceptWith(r.Remove); await PersistMetadataAsync(x with { Tags = tags.Order().ToArray(), UpdatedAt = DateTimeOffset.UtcNow }, ct); } await Audit(tenant, actor, "fleet", "bulk-tags", "tags.changed", r.Reason, FleetUpdateSafety.Hash(r), ct); }
    public async Task<DeploymentRingPolicy> PutRingsAsync(string tenant, string actor, DeploymentRingPolicy x, CancellationToken ct) { if (x.TenantId != tenant) throw new EnrollmentConflictException("RING_TENANT", "Ring policy tenant is invalid."); FleetUpdateSafety.ValidateRings(x); var prior = (await LoadRingsAsync(tenant, ct)).Where(r => r.PolicyId == x.PolicyId).OrderByDescending(r => r.Version).FirstOrDefault(); if (prior is not null && (x.Version <= prior.Version || x.PreviousHash != prior.PolicyHash)) throw new EnrollmentConflictException("RING_POLICY_VERSION", "Ring policy must increase version and bind the prior hash."); x = x with { Actor = actor, CreatedAt = DateTimeOffset.UtcNow, PolicyHash = "" }; x = x with { PolicyHash = FleetUpdateSafety.RingHash(x) }; await PersistRingsAsync(x, ct); await Audit(tenant, actor, "ring-policy", x.PolicyId.ToString("D"), "ring-policy.versioned", $"version {x.Version}", x.PolicyHash, ct); return x; }
    public async Task<DeploymentRingPolicy?> RingsAsync(string tenant, Guid id, CancellationToken ct) => (await LoadRingsAsync(tenant, ct)).Where(x => x.PolicyId == id).OrderByDescending(x => x.Version).FirstOrDefault();
    public async Task<SignedAgentUpdatePackage> RegisterPackageAsync(string tenant, string actor, PackageRegistrationRequest r, string trusted, CancellationToken ct) { FleetUpdateSafety.ValidateManifest(r.Manifest, DateTimeOffset.UtcNow); var candidate = new SignedAgentUpdatePackage(r.Manifest, r.SigningCertificatePem, X509Certificate2.CreateFromPem(r.SigningCertificatePem).Thumbprint, r.SignatureAlgorithm, r.Signature, false, null, null, null); if (!FleetUpdateSafety.VerifyPackage(candidate, trusted)) throw new EnrollmentConflictException("UPDATE_PACKAGE_UNTRUSTED", "Package signature, signer chain, manifest, expiry, or identity is invalid."); if ((await LoadPackagesAsync(tenant, ct)).Any(x => x.Manifest.PackageId == r.Manifest.PackageId)) throw new EnrollmentConflictException("UPDATE_PACKAGE_IMMUTABLE", "Package identity is immutable."); await PersistPackageAsync(tenant, candidate, ct); await Audit(tenant, actor, "package", r.Manifest.PackageId.ToString("D"), "package.registered", r.Manifest.Provenance, r.Manifest.ManifestSha256, ct); return candidate; }
    public async Task<SignedAgentUpdatePackage> RevokePackageAsync(string tenant, string actor, Guid id, string reason, CancellationToken ct) { var x = await PackageAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); if (x.Revoked || string.IsNullOrWhiteSpace(reason)) throw new EnrollmentConflictException("PACKAGE_REVOCATION_INVALID", "Package is already revoked or reason is missing."); x = x with { Revoked = true, RevokedAt = DateTimeOffset.UtcNow, RevokedBy = actor, RevocationReason = reason }; await PersistPackageAsync(tenant, x, ct); await Audit(tenant, actor, "package", id.ToString("D"), "package.revoked", reason, x.Manifest.ManifestSha256, ct); return x; }
    public async Task<SignedAgentUpdatePackage?> PackageAsync(string tenant, Guid id, CancellationToken ct) => (await LoadPackagesAsync(tenant, ct)).SingleOrDefault(x => x.Manifest.PackageId == id);
    public Task<IReadOnlyList<SignedAgentUpdatePackage>> PackagesAsync(string tenant, CancellationToken ct) => LoadPackagesAsync(tenant, ct);
    public async Task<AgentUpdatePolicy> PutPolicyAsync(string tenant, string actor, AgentUpdatePolicy x, CancellationToken ct) { if (x.TenantId != tenant) throw new EnrollmentConflictException("UPDATE_POLICY_TENANT", "Update policy tenant is invalid."); FleetUpdateSafety.ValidatePolicy(x); if (await RingsAsync(tenant, x.RingPolicyId, ct) is null) throw new EnrollmentConflictException("UPDATE_POLICY_RINGS", "Ring policy is unavailable."); var prior = (await LoadPoliciesAsync(tenant, ct)).Where(p => p.PolicyId == x.PolicyId).OrderByDescending(p => p.Version).FirstOrDefault(); if (prior is not null && (x.Version <= prior.Version || x.PreviousHash != prior.PolicyHash)) throw new EnrollmentConflictException("UPDATE_POLICY_VERSION", "Update policy must increase version and bind prior hash."); x = x with { Actor = actor, CreatedAt = DateTimeOffset.UtcNow, PolicyHash = "" }; x = x with { PolicyHash = FleetUpdateSafety.PolicyHash(x) }; await PersistPolicyAsync(x, ct); await Audit(tenant, actor, "update-policy", x.PolicyId.ToString("D"), "update-policy.versioned", $"version {x.Version}", x.PolicyHash, ct); return x; }
    public async Task<AgentUpdatePolicy?> PolicyAsync(string tenant, Guid id, CancellationToken ct) => (await LoadPoliciesAsync(tenant, ct)).Where(x => x.PolicyId == id).OrderByDescending(x => x.Version).FirstOrDefault();
    public async Task<RolloutPreview> PreviewAsync(string tenant, RolloutCreateRequest r, CancellationToken ct) { if (r.EndpointIds.Length is < 1 or > FleetUpdateSafety.MaximumBulkEndpoints || r.EndpointIds.Distinct().Count() != r.EndpointIds.Length) throw new EnrollmentConflictException("ROLLOUT_TARGET_BOUNDS", "Rollout requires one to 500 unique endpoint targets."); var package = await PackageAsync(tenant, r.PackageId, ct) ?? throw new KeyNotFoundException(); var policy = await PolicyAsync(tenant, r.PolicyId, ct) ?? throw new KeyNotFoundException(); var ringPolicy = await RingsAsync(tenant, policy.RingPolicyId, ct) ?? throw new KeyNotFoundException(); if (package.Revoked || !policy.Enabled || package.Manifest.TargetVersion != policy.TargetVersion) throw new EnrollmentConflictException("ROLLOUT_PACKAGE_POLICY", "Rollout package is revoked, disabled, or not bound to policy target."); var selected = ringPolicy.Rings.Where(x => r.RingIds.Contains(x.RingId, StringComparer.Ordinal)).OrderBy(x => x.Order).ToArray(); if (selected.Length != r.RingIds.Distinct(StringComparer.Ordinal).Count()) throw new EnrollmentConflictException("ROLLOUT_RING_INVALID", "Rollout ring selection is invalid."); var m = await LoadMetadataAsync(tenant, ct); var eligible = r.EndpointIds.Count(id => m.Any(x => x.EndpointId == id && x.Eligibility == UpdateEligibility.Eligible)); return new(r.EndpointIds.Length, eligible, r.EndpointIds.Length - eligible, selected.ToDictionary(x => x.RingId, x => m.Count(v => r.EndpointIds.Contains(v.EndpointId) && v.RingId == x.RingId)), policy.MaxConcurrentUpdates, policy.MaxConcurrentDownloads, eligible == 0 ? ["No endpoint currently passes readiness."] : []); }
    public async Task<FleetRollout> CreateRolloutAsync(string tenant, string actor, RolloutCreateRequest r, IReadOnlyDictionary<Guid, string> installations, CancellationToken ct)
    {
        var preview = await PreviewAsync(tenant, r, ct); var package = (await PackageAsync(tenant, r.PackageId, ct))!; var policy = (await PolicyAsync(tenant, r.PolicyId, ct))!; var ringPolicy = (await RingsAsync(tenant, policy.RingPolicyId, ct))!; var metadata = await LoadMetadataAsync(tenant, ct); var selected = ringPolicy.Rings.Where(x => r.RingIds.Contains(x.RingId)).OrderBy(x => x.Order).ToArray(); var id = Guid.NewGuid(); var now = DateTimeOffset.UtcNow;
        foreach (var endpoint in r.EndpointIds) { var meta = metadata.SingleOrDefault(x => x.EndpointId == endpoint); installations.TryGetValue(endpoint, out var installation); var eligible = meta?.Eligibility == UpdateEligibility.Eligible && installation is not null; var state = eligible ? (meta!.RingId == selected[0].RingId ? UpdateState.Assigned : UpdateState.WaitingForRing) : UpdateState.NotEligible; var assignment = new EndpointUpdateAssignment(FleetUpdateSafety.StableId(tenant, id.ToString("D"), endpoint.ToString("D"), package.Manifest.PackageId.ToString("D")), tenant, id, endpoint, eligible ? installation! : "unavailable", package.Manifest.PackageId, meta?.RingId ?? "unassigned", state, 0, now, package.Manifest.ExpiresAt, now, eligible ? null : meta?.Eligibility.ToString() ?? "endpoint-unavailable", null, ""); assignment = assignment with { AssignmentHash = FleetUpdateSafety.Hash(assignment with { AssignmentHash = "" }) }; await PersistAssignmentAsync(assignment, ct); }
        var x = new FleetRollout(id, tenant, r.PackageId, package.Manifest.TargetVersion, r.PolicyId, policy.Version, selected.Select(s => s.RingId).ToArray(), actor, RolloutState.Draft, selected[0].RingId, preview.Total, preview.Eligible, preview.Eligible, 0, 0, 0, 0, preview.Ineligible, 0, now, null, null, r.Reason, ""); x = x with { RolloutHash = FleetUpdateSafety.Hash(x with { RolloutHash = "" }) }; await PersistRolloutAsync(x, ct); await Audit(tenant, actor, "rollout", id.ToString("D"), "rollout.created", r.Reason, x.RolloutHash, ct); return x;
    }
    public async Task<FleetRollout> TransitionRolloutAsync(string tenant, string actor, Guid id, string transition, string reason, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try
        {
            var x = await RolloutAsync(tenant, id, ct) ?? throw new KeyNotFoundException(); var all = (await LoadAssignmentsAsync(tenant, ct)).Where(a => a.RolloutId == id).ToArray(); var policy = await PolicyAsync(tenant, x.PolicyId, ct) ?? throw new KeyNotFoundException(); var rp = await RingsAsync(tenant, policy.RingPolicyId, ct) ?? throw new KeyNotFoundException(); RolloutState next; string ring = x.CurrentRing;
            if (transition == "start" && x.State == RolloutState.Draft) next = RolloutState.Running;
            else if (transition == "pause" && x.State == RolloutState.Running) next = RolloutState.Paused;
            else if (transition == "resume" && x.State == RolloutState.Paused) next = RolloutState.Running;
            else if (transition == "cancel" && x.State is RolloutState.Draft or RolloutState.Ready or RolloutState.Running or RolloutState.Paused) next = RolloutState.Cancelled;
            else if (transition == "advance" && x.State == RolloutState.Running) { var current = rp.Rings.Single(r => r.RingId == x.CurrentRing); var completed = all.Where(a => a.RingId == current.RingId && a.State is UpdateState.Succeeded or UpdateState.Failed or UpdateState.RolledBack).ToArray(); var successes = completed.Count(a => a.State is UpdateState.Succeeded or UpdateState.RolledBack); var failureRate = completed.Length == 0 ? 100 : completed.Count(a => a.State == UpdateState.Failed) * 100d / completed.Length; if (completed.Length < current.MinimumSampleSize || successes * 100d / Math.Max(1, completed.Length) < current.SuccessThresholdPercent || failureRate >= current.FailureThresholdPercent) throw new EnrollmentConflictException("ROLLOUT_HEALTH_GATE", "Current ring has not met minimum sample, success, or failure thresholds."); var nextRing = rp.Rings.Where(r => x.TargetRings.Contains(r.RingId) && r.Order > current.Order).OrderBy(r => r.Order).FirstOrDefault(); if (nextRing is null) next = RolloutState.Succeeded; else { ring = nextRing.RingId; next = RolloutState.Running; foreach (var a in all.Where(a => a.RingId == ring && a.State == UpdateState.WaitingForRing)) await PersistAssignmentAsync(WithState(a, UpdateState.Assigned, null), ct); } }
            else throw new EnrollmentConflictException("ROLLOUT_TRANSITION_INVALID", "Rollout transition is invalid for its current state.");
            if (next == RolloutState.Cancelled) foreach (var a in all.Where(a => a.State is UpdateState.Assigned or UpdateState.WaitingForRing or UpdateState.WaitingForWindow or UpdateState.Paused)) await PersistAssignmentAsync(WithState(a, UpdateState.Cancelled, "rollout-cancelled"), ct);
            all = (await LoadAssignmentsAsync(tenant, ct)).Where(a => a.RolloutId == id).ToArray(); x = Counts(x with { State = next, CurrentRing = ring, StartedAt = x.StartedAt ?? (next == RolloutState.Running ? DateTimeOffset.UtcNow : null), CompletedAt = next is RolloutState.Succeeded or RolloutState.Cancelled or RolloutState.Failed ? DateTimeOffset.UtcNow : null }, all); x = x with { RolloutHash = FleetUpdateSafety.Hash(x with { RolloutHash = "" }) }; await PersistRolloutAsync(x, ct); await Audit(tenant, actor, "rollout", id.ToString("D"), $"rollout.{transition}", reason, x.RolloutHash, ct); return x;
        }
        finally { gate.Release(); }
    }
    public async Task<FleetRollout?> RolloutAsync(string tenant, Guid id, CancellationToken ct) => (await LoadRolloutsAsync(tenant, ct)).SingleOrDefault(x => x.RolloutId == id);
    public Task<IReadOnlyList<FleetRollout>> RolloutsAsync(string tenant, CancellationToken ct) => LoadRolloutsAsync(tenant, ct);
    public async Task<EndpointUpdateAssignment?> AssignmentAsync(string tenant, Guid endpoint, string installation, CancellationToken ct) { var now = DateTimeOffset.UtcNow; var all = (await LoadAssignmentsAsync(tenant, ct)).Where(x => x.EndpointId == endpoint && x.InstallationId == installation).OrderByDescending(x => x.AssignedAt).ToArray(); var x = all.FirstOrDefault(a => a.State is UpdateState.Assigned or UpdateState.WaitingForRing or UpdateState.WaitingForWindow or UpdateState.Downloading or UpdateState.Downloaded or UpdateState.Verifying or UpdateState.Staged or UpdateState.Installing or UpdateState.Restarting or UpdateState.VerifyingInstall or UpdateState.RollbackPending or UpdateState.RollingBack or UpdateState.Paused); if (x is not null && x.ExpiresAt <= now) { x = WithState(x, UpdateState.Expired, "assignment-expired"); await PersistAssignmentAsync(x, ct); } return x; }
    public async Task<EndpointUpdateAssignment> ReportAsync(string tenant, EndpointUpdateStatus s, CancellationToken ct)
    {
        var a = (await LoadAssignmentsAsync(tenant, ct)).SingleOrDefault(x => x.AssignmentId == s.AssignmentId) ?? throw new KeyNotFoundException(); if (a.EndpointId != s.EndpointId || a.InstallationId != s.InstallationId || s.OccurredAt < a.AssignedAt || s.OccurredAt > DateTimeOffset.UtcNow.AddMinutes(2) || s.EvidenceHash != FleetUpdateSafety.Hash(s with { EvidenceHash = "" })) throw new EnrollmentConflictException("UPDATE_STATUS_FORGED", "Update status identity, installation, time, or evidence hash is invalid."); var package = await PackageAsync(tenant, a.PackageId, ct) ?? throw new KeyNotFoundException(); var state = s.State; var failure = s.FailureCode; if (state == UpdateState.Succeeded && (!FleetUpdateSafety.PostInstallHealthy(s) || s.InstalledVersion != package.Manifest.TargetVersion)) { state = UpdateState.Failed; failure = "post-install-health-failed"; }
        a = WithState(a, state, failure, s.EvidenceHash); await PersistAssignmentAsync(a, ct); var rollout = await RolloutAsync(tenant, a.RolloutId, ct) ?? throw new KeyNotFoundException(); var all = (await LoadAssignmentsAsync(tenant, ct)).Where(x => x.RolloutId == rollout.RolloutId).ToArray(); var policy = await PolicyAsync(tenant, rollout.PolicyId, ct) ?? throw new KeyNotFoundException(); var completed = all.Count(x => x.State is UpdateState.Succeeded or UpdateState.Failed or UpdateState.RolledBack); var failed = all.Count(x => x.State == UpdateState.Failed); if (rollout.State == RolloutState.Running && completed >= policy.AutoPauseMinimumSampleSize && failed * 100d / completed >= policy.AutoPauseFailurePercent) rollout = rollout with { State = RolloutState.Paused, Reason = "automatic health/failure threshold" }; rollout = Counts(rollout, all); rollout = rollout with { RolloutHash = FleetUpdateSafety.Hash(rollout with { RolloutHash = "" }) }; await PersistRolloutAsync(rollout, ct); await Audit(tenant, "agent", "assignment", a.AssignmentId.ToString("D"), $"update.{state.ToString().ToLowerInvariant()}", failure ?? "status", a.AssignmentHash, ct); return a;
    }
    public async Task<IReadOnlyList<EndpointUpdateAssignment>> AssignmentsAsync(string tenant, Guid rollout, CancellationToken ct) => (await LoadAssignmentsAsync(tenant, ct)).Where(x => x.RolloutId == rollout).OrderBy(x => x.AssignedAt).ToArray();
    public async Task<IReadOnlyList<FleetAuditEvent>> AuditAsync(string tenant, int limit, CancellationToken ct) { if (limit is < 1 or > 500) throw new EnrollmentConflictException("FLEET_AUDIT_BOUNDS", "Audit limit must be 1-500."); return (await LoadAuditsAsync(tenant, ct)).OrderByDescending(x => x.OccurredAt).Take(limit).ToArray(); }
    public async Task<FleetUpdateHealth> HealthAsync(string tenant, CancellationToken ct) { var m = await LoadMetadataAsync(tenant, ct); var a = await LoadAssignmentsAsync(tenant, ct); var r = await LoadRolloutsAsync(tenant, ct); return new(new Dictionary<string, long> { ["unknown"] = m.Count }, m.LongCount(x => x.Eligibility == UpdateEligibility.Eligible), a.LongCount(x => x.State is UpdateState.Assigned or UpdateState.WaitingForRing or UpdateState.WaitingForWindow), a.LongCount(x => x.State is UpdateState.Downloading or UpdateState.Verifying or UpdateState.Staged or UpdateState.Installing or UpdateState.Restarting or UpdateState.VerifyingInstall), a.LongCount(x => x.State == UpdateState.Succeeded), a.LongCount(x => x.State == UpdateState.Failed), a.LongCount(x => x.State == UpdateState.RolledBack), r.LongCount(x => x.State == RolloutState.Paused), a.LongCount(x => x.FailureCode?.Contains("verif", StringComparison.OrdinalIgnoreCase) == true), null, null, a.LongCount(x => x.FailureCode?.Contains("health", StringComparison.OrdinalIgnoreCase) == true), DateTimeOffset.UtcNow); }
    static EndpointUpdateAssignment WithState(EndpointUpdateAssignment a, UpdateState state, string? failure, string? result = null) { var x = a with { State = state, FailureCode = failure, ResultHash = result ?? a.ResultHash, UpdatedAt = DateTimeOffset.UtcNow, AssignmentHash = "" }; return x with { AssignmentHash = FleetUpdateSafety.Hash(x) }; }
    static FleetRollout Counts(FleetRollout x, EndpointUpdateAssignment[] a) => x with { Pending = a.Count(v => v.State is UpdateState.Assigned or UpdateState.WaitingForRing or UpdateState.WaitingForWindow), Running = a.Count(v => v.State is UpdateState.Downloading or UpdateState.Downloaded or UpdateState.Verifying or UpdateState.Staged or UpdateState.Installing or UpdateState.Restarting or UpdateState.VerifyingInstall or UpdateState.RollingBack), Succeeded = a.Count(v => v.State == UpdateState.Succeeded), Failed = a.Count(v => v.State == UpdateState.Failed), RolledBack = a.Count(v => v.State == UpdateState.RolledBack), Skipped = a.Count(v => v.State is UpdateState.NotEligible or UpdateState.Cancelled or UpdateState.Expired), Paused = a.Count(v => v.State == UpdateState.Paused) };
    public void Dispose() { gate.Dispose(); GC.SuppressFinalize(this); }
}
