using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<AdministrativePrincipalType>))]
public enum AdministrativePrincipalType { HumanUser, ServiceAccount, ApiClient, SystemPrincipal }
[JsonConverter(typeof(JsonStringEnumConverter<AdministrativePrincipalStatus>))]
public enum AdministrativePrincipalStatus { Active, Disabled, Revoked, Expired }
[JsonConverter(typeof(JsonStringEnumConverter<ConfigurationScope>))]
public enum ConfigurationScope { PlatformDefault, Tenant, EndpointGroup, Endpoint }
[JsonConverter(typeof(JsonStringEnumConverter<ConfigurationVersionState>))]
public enum ConfigurationVersionState { Draft, PendingApproval, Active, Disabled }
[JsonConverter(typeof(JsonStringEnumConverter<ConfigurationDriftState>))]
public enum ConfigurationDriftState { InSync, Pending, Stale, Drifted, Unknown }

public sealed record AdministrativePrincipal(Guid PrincipalId, string TenantId, AdministrativePrincipalType Type,
    string DisplayName, AdministrativePrincipalStatus Status, DateTimeOffset CreatedAt, DateTimeOffset? LastActivity,
    string AuthenticationSource, string Purpose, DateTimeOffset? ExpiresAt, int CredentialVersion,
    DateTimeOffset? CredentialsRotatedAt, DateTimeOffset? DisabledAt, string CreatedBy);
public sealed record AdministrativeRole(Guid RoleId, string TenantId, int Version, string Name, string Description,
    bool BuiltIn, string[] Permissions, string DefinitionHash, string Author, string Reason, DateTimeOffset CreatedAt,
    bool Active = true);
public sealed record AdministrativeRoleAssignment(Guid AssignmentId, string TenantId, Guid PrincipalId, Guid RoleId,
    int RoleVersion, DateTimeOffset StartsAt, DateTimeOffset? ExpiresAt, bool TemporaryElevation, string ScopeType,
    string? ScopeId, string Reason, string AssignedBy, DateTimeOffset AssignedAt, DateTimeOffset? RevokedAt = null,
    string? RevokedBy = null);
public sealed record EffectivePermissionEntry(string Permission, string Source, Guid RoleId, int RoleVersion,
    DateTimeOffset? ExpiresAt, string ScopeType, string? ScopeId);
public sealed record EffectivePermissionSet(Guid PrincipalId, string TenantId, AdministrativePrincipalStatus Status,
    EffectivePermissionEntry[] Permissions, string[] Restrictions, DateTimeOffset CalculatedAt);
public sealed record ApiCredentialMetadata(Guid CredentialId, string TenantId, Guid PrincipalId, int Version,
    string Name, string Prefix, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt, string CreatedBy, string Purpose);
public sealed record ApiCredentialSecret(ApiCredentialMetadata Metadata, string Secret);
public sealed record StoredApiCredential(ApiCredentialMetadata Metadata, string SecretHash);

public sealed record ConfigurationDefinition(string Key, string ValueType, ConfigurationScope[] Scopes,
    JsonElement DefaultValue, JsonElement? Minimum, JsonElement? Maximum, string[]? AllowedValues,
    string SecurityClassification, bool RestartRequired, string OwnerSubsystem, bool HighRisk,
    bool NonOverridableSafetyFloor, string Description);
public sealed record ConfigurationVersion(Guid ConfigurationId, string TenantId, string Key, int Version,
    ConfigurationScope Scope, Guid? ScopeId, JsonElement Value, string ValueHash, ConfigurationVersionState State,
    string Author, string Reason, DateTimeOffset CreatedAt, Guid? ApprovalId, string? ApprovedBy,
    DateTimeOffset? ApprovedAt, DateTimeOffset? ActivatedAt, DateTimeOffset? DeactivatedAt, string Diff);
public sealed record ConfigurationAssignment(Guid AssignmentId, string TenantId, Guid ConfigurationId, int Version,
    ConfigurationScope Scope, Guid? ScopeId, DateTimeOffset AssignedAt, string AssignedBy, int RolloutPercent,
    DateTimeOffset? MaintenanceStart, DateTimeOffset? MaintenanceEnd, bool UrgentResponseExempt);
public sealed record PolicyAcknowledgement(Guid EndpointId, string TenantId, string Key, int ExpectedVersion,
    int? ReportedVersion, string? ReportedHash, bool Applied, DateTimeOffset ReportedAt, string? Error);
public sealed record EffectiveConfiguration(string Key, JsonElement EffectiveValue, string EffectiveHash,
    ConfigurationScope SourceScope, Guid? SourceScopeId, int SourceVersion,
    ConfigurationVersion[] OverriddenValues, string? PlatformConstraint, ConfigurationDriftState Drift,
    PolicyAcknowledgement? Acknowledgement);
public sealed record ConfigurationPreview(string Key, ConfigurationScope Scope, Guid? ScopeId, JsonElement PreviousValue,
    JsonElement NewValue, string[] PermissionsAffected, string SecurityImpact, int AffectedEndpoints,
    int RolloutPercent, bool ApprovalRequired, string ConfirmationHash);
public sealed record AdministrativeAuditEvent(Guid AuditId, string TenantId, DateTimeOffset OccurredAt, string Actor,
    string Action, string ResourceType, string ResourceId, string? BeforeHash, string? AfterHash, string Reason,
    string RequestId, Guid? ApprovalId, string Result, IReadOnlyDictionary<string, string?> Metadata);
public sealed record AdministrativeAuditQuery(DateTimeOffset? From = null, DateTimeOffset? To = null,
    string? Principal = null, string? Action = null, string? Resource = null, string? Subsystem = null,
    string? Result = null, Guid? ApprovalId = null, int Limit = 200);
public sealed record AdministrativeHealth(int ActiveUsers, int DisabledUsers, int ServiceAccounts,
    int ApiClients, int ExpiringCredentials, int CustomRoles, int PolicyVersions, int PendingAcknowledgements,
    int DriftedEndpoints, int PendingApprovals, int HighRiskChanges, long AuditEvents, bool AuditHealthy);
public sealed record AdministrationState(long Revision, AdministrativePrincipal[] Principals, AdministrativeRole[] Roles,
    AdministrativeRoleAssignment[] Assignments, ApiCredentialMetadata[] Credentials,
    ConfigurationVersion[] Configurations, ConfigurationAssignment[] ConfigurationAssignments,
    PolicyAcknowledgement[] Acknowledgements);

public static class PermissionRegistry
{
    static readonly ConcurrentDictionary<string, byte> Values = new(StringComparer.Ordinal);
    static readonly string[] Core = ["authenticated", "admin.users", "admin.roles", "admin.policy", "admin.audit",
        "admin.api_clients", "admin.credentials.authenticate", "endpoint.read", "detection.read", "detection.draft",
        "detection.approve", "detection.activate", "hunt.read", "hunt.execute", "hunt.save", "alert.read", "alert.triage",
        "incident.manage", "response.read", "response.safe", "response.destructive", "response.approve",
        "live_response.open", "live_response.command", "live_response.file_get", "forensics.read", "forensics.collect",
        "forensics.sensitive_collect", "forensics.download", "playbook.read", "playbook.edit", "playbook.activate",
        "playbook.approve", "ai.read", "ai.use", "ai.engineering", "ai.policy_manage"];
    static PermissionRegistry() { foreach (var value in Core) Register(value); }
    public static void Register(string permission) { if (!string.IsNullOrWhiteSpace(permission) && permission.Length <= 160) Values.TryAdd(permission, 0); }
    public static bool IsKnown(string permission) => Values.ContainsKey(permission);
    public static string[] All => Values.Keys.Order(StringComparer.Ordinal).ToArray();
    public static string[] HumanAdministrator => All.Where(x => !x.StartsWith("agent:", StringComparison.Ordinal)
        && x is not ("system:admin" or "platform:admin" or "service:register" or "admin.credentials.authenticate")).ToArray();
}

public static class AdministrationSafety
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static readonly ConfigurationDefinition[] ConfigurationRegistry =
    [
        D("session.inactivity_minutes","integer",J(15),J(5),J(60),"security",false,"authentication",false,true,"Bounded human-session inactivity timeout."),
        D("response.high_risk_approval_required","boolean",J(true),null,null,"critical",false,"response",true,true,"High-risk response always requires separated approval."),
        D("forensics.maximum_collection_bytes","integer",J(268435456),J(1048576),J(1073741824),"sensitive",false,"forensics",false,true,"Maximum bounded collection size."),
        D("forensics.sensitive_approval_required","boolean",J(true),null,null,"critical",false,"forensics",true,true,"Sensitive collection requires separated approval."),
        D("ai.external_transmission_enabled","boolean",J(false),null,null,"critical",false,"ai",true,true,"External AI transmission remains disabled without qualified provider."),
        D("audit.retention_days","integer",J(365),J(365),J(3650),"critical",false,"audit",true,true,"Minimum administrative audit retention."),
        D("update.canary_percent","integer",J(5),J(1),J(25),"security",false,"fleet",true,true,"Bounded first rollout ring."),
        D("hunt.maximum_events","integer",J(10000),J(100),J(10000),"operational",false,"hunting",false,false,"Maximum bounded hunt evidence events."),
        D("incident.default_sla_minutes","integer",J(240),J(15),J(10080),"operational",false,"triage",false,false,"Default incident service-level target."),
        D("display.timezone","string",J("UTC"),null,null,"display",false,"frontend",false,false,"IANA or UTC display timezone.", ["UTC","Asia/Riyadh","Europe/London","America/New_York"]),
        D("policy.rollout_percent","integer",J(10),J(1),J(100),"security",false,"fleet",false,false,"Default bounded policy rollout percentage."),
        D("maintenance.maximum_window_minutes","integer",J(240),J(15),J(1440),"security",false,"operations",false,true,"Maximum maintenance-window length; urgent approved response is exempt.")
    ];
    static ConfigurationDefinition D(string key, string type, JsonElement value, JsonElement? min, JsonElement? max, string security, bool restart, string owner, bool high, bool floor, string description, string[]? allowed = null)
        => new(key, type, [ConfigurationScope.PlatformDefault, ConfigurationScope.Tenant, ConfigurationScope.EndpointGroup, ConfigurationScope.Endpoint], value, min, max, allowed, security, restart, owner, high, floor, description);
    public static JsonElement J<T>(T value) => JsonSerializer.SerializeToElement(value, Json);
    public static string Hash<T>(T value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, Json))).ToLowerInvariant();
    public static Guid StableId(params string[] values) => new(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))).AsSpan(0, 16));
    public static ConfigurationDefinition Definition(string key) => ConfigurationRegistry.SingleOrDefault(x => x.Key == key) ?? throw new EnrollmentConflictException("CONFIGURATION_KEY_UNKNOWN", "The configuration key is not registered.");
    public static void ValidateValue(ConfigurationDefinition d, JsonElement value)
    {
        var validType = d.ValueType switch { "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False, "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _), "string" => value.ValueKind == JsonValueKind.String, _ => false };
        if (!validType) throw new EnrollmentConflictException("CONFIGURATION_TYPE_INVALID", $"{d.Key} requires {d.ValueType}.");
        if (d.ValueType == "integer") { var n = value.GetInt64(); if (d.Minimum is { } min && n < min.GetInt64() || d.Maximum is { } max && n > max.GetInt64()) throw new EnrollmentConflictException("CONFIGURATION_BOUNDS_INVALID", $"{d.Key} is outside its safe range."); }
        if (d.AllowedValues is { Length: > 0 } allowed && !allowed.Contains(value.GetString(), StringComparer.Ordinal)) throw new EnrollmentConflictException("CONFIGURATION_VALUE_INVALID", $"{d.Key} is not an allowed value.");
        if (d.NonOverridableSafetyFloor && ((d.Key.EndsWith("approval_required", StringComparison.Ordinal) && value.ValueKind == JsonValueKind.False) || d.Key == "ai.external_transmission_enabled" && value.ValueKind == JsonValueKind.True)) throw new EnrollmentConflictException("PLATFORM_SAFETY_FLOOR", "A lower scope cannot weaken this platform safety constraint.");
    }
    public static void ValidateRole(string name, IEnumerable<string> permissions)
    {
        var p = permissions.Distinct(StringComparer.Ordinal).ToArray(); if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || p.Length is < 1 or > 256) throw new EnrollmentConflictException("ROLE_INVALID", "Role name or permission count is invalid.");
        var unknown = p.Where(x => !PermissionRegistry.IsKnown(x) || x.StartsWith("agent:", StringComparison.Ordinal)
            || x is "system:admin" or "platform:admin" or "service:register" or "admin.credentials.authenticate").ToArray(); if (unknown.Length > 0) throw new EnrollmentConflictException("ROLE_PERMISSION_INVALID", $"Unknown or restricted permissions: {string.Join(',', unknown)}");
    }
    public static AdministrativeRole[] BuiltIns(string tenant)
    {
        var now = DateTimeOffset.UnixEpoch; var all = PermissionRegistry.HumanAdministrator;
        string[] Pick(params string[] prefixes) => all.Where(x => prefixes.Any(p => x.StartsWith(p, StringComparison.Ordinal))).Distinct().Order().ToArray();
        AdministrativeRole R(string name, string desc, string[] p) { var id = StableId("sprint33-role", name); return new(id, tenant, 1, name, desc, true, p, Hash(p), "system:sprint33", "built-in least-privilege role", now); }
        return [
            R("Tenant Administrator","Tenant-scoped administration without platform-global or agent identity privileges.",all),
            R("SOC Manager","Alert, incident, hunt and analyst workflow management.",Pick("endpoint:","alert:","incident:","triage:","hunt:","investigation:")),
            R("SOC Analyst","Read, investigate and triage without response approval.",Pick("endpoint:read","process:read","file:read","registry:read","network:read","dns:read","module:read","identity:read","execution:read","alert:read","alert:acknowledge","alert:assign","alert:status","alert:notes","incident:read","hunt:","investigation:")),
            R("Detection Engineer","Detection, correlation, hunting and advisory AI engineering.",Pick("detection:","correlation:","hunt:","ai:")),
            R("Incident Responder","Bounded response request and investigation; approval remains separate.",Pick("response:read","response:request","response:cancel","isolation:request","isolation:status","process-response:","file-response:","persistence-response:","live:open","live:read","live:execute","live:file:download").Where(x=>!x.Contains(":approve",StringComparison.Ordinal)&&!x.EndsWith(":policy:admin",StringComparison.Ordinal)).ToArray()),
            R("DFIR Analyst","Forensic collection, evidence access and investigation.",Pick("forensics:","investigation:","endpoint:read","process:read","file:read","registry:read","identity:read")),
            R("Threat Hunter","Threat hunting, intelligence and evidence read access.",Pick("hunt:","investigation:","intelligence:","tunnel:","detection:read","correlation:read")),
            R("Read Only / Auditor","Read-only operational and audit visibility.",all.Where(x=>x.EndsWith(":read",StringComparison.Ordinal)||x.EndsWith(".read",StringComparison.Ordinal)||x is "admin.audit" or "authenticated").ToArray())
        ];
    }
}

public interface IAdministrationStateStore
{
    Task<AdministrationState> LoadAsync(string tenant, CancellationToken ct);
    Task SaveAsync(string tenant, long expectedRevision, AdministrationState state, IReadOnlyList<AdministrativeAuditEvent> audit, CancellationToken ct);
    Task<StoredApiCredential?> CredentialAsync(Guid id, CancellationToken ct);
    Task PutCredentialAsync(StoredApiCredential credential, CancellationToken ct);
    Task TouchCredentialAsync(Guid id, DateTimeOffset usedAt, CancellationToken ct);
    Task<IReadOnlyList<AdministrativeAuditEvent>> AuditAsync(string tenant, AdministrativeAuditQuery query, CancellationToken ct);
    Task<long> AuditCountAsync(string tenant, CancellationToken ct);
}

public sealed class FileAdministrationStateStore : IAdministrationStateStore
{
    readonly ConcurrentDictionary<string, AdministrationState> states = new(); readonly ConcurrentDictionary<Guid, StoredApiCredential> credentials = new(); readonly ConcurrentDictionary<string, List<AdministrativeAuditEvent>> audits = new(); readonly object gate = new();
    public Task<AdministrationState> LoadAsync(string t, CancellationToken ct) => Task.FromResult(states.GetValueOrDefault(t, new(0, [], [], [], [], [], [], [])));
    public Task SaveAsync(string t, long expected, AdministrationState s, IReadOnlyList<AdministrativeAuditEvent> a, CancellationToken ct) { lock (gate) { var current = states.GetValueOrDefault(t, new(0, [], [], [], [], [], [], [])); if (current.Revision != expected) throw new EnrollmentConflictException("ADMINISTRATION_STALE_VERSION", "Administrative state changed; reload and retry."); states[t] = s with { Revision = expected + 1 }; var list = audits.GetOrAdd(t, _ => []); list.AddRange(a); } return Task.CompletedTask; }
    public Task<StoredApiCredential?> CredentialAsync(Guid id, CancellationToken ct) => Task.FromResult(credentials.GetValueOrDefault(id));
    public Task PutCredentialAsync(StoredApiCredential c, CancellationToken ct) { credentials[c.Metadata.CredentialId] = c; return Task.CompletedTask; }
    public Task TouchCredentialAsync(Guid id, DateTimeOffset at, CancellationToken ct) { if (credentials.TryGetValue(id, out var c)) credentials[id] = c with { Metadata = c.Metadata with { LastUsedAt = at } }; return Task.CompletedTask; }
    public Task<IReadOnlyList<AdministrativeAuditEvent>> AuditAsync(string t, AdministrativeAuditQuery q, CancellationToken ct) => Task.FromResult<IReadOnlyList<AdministrativeAuditEvent>>(audits.GetValueOrDefault(t, []).Where(x => (q.From is null || x.OccurredAt >= q.From) && (q.To is null || x.OccurredAt <= q.To) && (q.Principal is null || x.Actor == q.Principal) && (q.Action is null || x.Action.Contains(q.Action, StringComparison.OrdinalIgnoreCase)) && (q.Resource is null || x.ResourceId.Contains(q.Resource, StringComparison.OrdinalIgnoreCase)) && (q.Subsystem is null || x.ResourceType.Equals(q.Subsystem, StringComparison.OrdinalIgnoreCase)) && (q.Result is null || x.Result.Equals(q.Result, StringComparison.OrdinalIgnoreCase)) && (q.ApprovalId is null || x.ApprovalId == q.ApprovalId)).OrderByDescending(x => x.OccurredAt).Take(Math.Clamp(q.Limit, 1, 1000)).ToArray());
    public Task<long> AuditCountAsync(string t, CancellationToken ct) => Task.FromResult((long)audits.GetValueOrDefault(t, []).Count);
}

public sealed class AdministrationService(IAdministrationStateStore store)
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    async Task<AdministrationState> State(string tenant, CancellationToken ct)
    {
        var s = await store.LoadAsync(tenant, ct);
        var built = AdministrationSafety.BuiltIns(tenant);
        if (s.Roles.Length == 0)
        {
            var seeded = s with { Roles = built };
            var audit = built.Select(x => A(tenant, "system:sprint33", "admin.role.seeded", "role", x.RoleId.ToString("D"), null, x.DefinitionHash, "built-in role seed", null)).ToArray();
            try { await store.SaveAsync(tenant, s.Revision, seeded, audit, ct); } catch (EnrollmentConflictException) { }
            return await store.LoadAsync(tenant, ct);
        }
        var changed = new List<AdministrativeRole>();
        var roles = s.Roles.ToList();
        foreach (var expected in built)
        {
            var current = roles.Where(x => x.RoleId == expected.RoleId && x.BuiltIn && x.Active).MaxBy(x => x.Version);
            if (current is not null && current.DefinitionHash == expected.DefinitionHash) continue;
            if (current is not null) roles = roles.Select(x => x.RoleId == current.RoleId && x.Version == current.Version ? x with { Active = false } : x).ToList();
            var next = expected with { Version = roles.Where(x => x.RoleId == expected.RoleId).Select(x => x.Version).DefaultIfEmpty(0).Max() + 1 };
            roles.Add(next); changed.Add(next);
        }
        if (changed.Count == 0) return s;
        var upgraded = s with { Roles = roles.ToArray() };
        var changes = changed.Select(x => A(tenant, "system:sprint33", "admin.role.versioned", "role", x.RoleId.ToString("D"), null, x.DefinitionHash, "built-in permission registry reconciliation", null)).ToArray();
        try { await store.SaveAsync(tenant, s.Revision, upgraded, changes, ct); } catch (EnrollmentConflictException) { }
        return await store.LoadAsync(tenant, ct);
    }
    static AdministrativeAuditEvent A(string t, string actor, string action, string type, string id, string? before, string? after, string reason, Guid? approval, string result = "success") => new(Guid.NewGuid(), t, DateTimeOffset.UtcNow, actor, action, type, id, before, after, reason, Guid.NewGuid().ToString("N"), approval, result, new Dictionary<string, string?> { { "provenance", "administration-service.v1" } });
    async Task<AdministrationState> Mutate(string t, string actor, string action, string type, string id, string reason, Func<AdministrationState, (AdministrationState State, string? Before, string? After, Guid? Approval)> change, CancellationToken ct)
    { for (var i = 0; i < 3; i++) { var s = await State(t, ct); var c = change(s); try { await store.SaveAsync(t, s.Revision, c.State, [A(t, actor, action, type, id, c.Before, c.After, reason, c.Approval)], ct); return await store.LoadAsync(t, ct); } catch (EnrollmentConflictException) when (i < 2) { } } throw new EnrollmentConflictException("ADMINISTRATION_STALE_VERSION", "Concurrent administrative change; reload and retry."); }
    public Task<AdministrationState> GetAsync(string t, CancellationToken ct) => State(t, ct);
    public Task RecordAuthenticationFailureAsync(string t, string actor, string reason, CancellationToken ct) =>
        Mutate(t, string.IsNullOrWhiteSpace(actor) ? "unknown" : actor, "authentication.failed", "authentication", "bootstrap", reason,
            s => (s, null, null, null), ct);
    public Task RecordAuditExportAsync(string t, string actor, Guid exportId, string contentHash, string reason, CancellationToken ct) =>
        Mutate(t, actor, "admin.audit.exported", "audit-export", exportId.ToString("D"), reason,
            s => (s, null, contentHash, null), ct);
    public async Task<AdministrativePrincipal> BootstrapPrincipalAsync(string t, string display, CancellationToken ct)
    {
        var id = AdministrationSafety.StableId("deployment-bootstrap", t); var s = await State(t, ct); var existing = s.Principals.SingleOrDefault(x => x.PrincipalId == id); if (existing is not null) return existing; var p = new AdministrativePrincipal(id, t, AdministrativePrincipalType.SystemPrincipal, display, AdministrativePrincipalStatus.Active, DateTimeOffset.UnixEpoch, null, "deployment-bootstrap", "Initial deployment recovery and system administration.", null, 1, null, null, "system:bootstrap"); var admin = s.Roles.Single(x => x.Name == "Tenant Administrator" && x.BuiltIn); var assignment = new AdministrativeRoleAssignment(AdministrationSafety.StableId("deployment-bootstrap-assignment", t), t, id, admin.RoleId, admin.Version, DateTimeOffset.UnixEpoch, null, false, "tenant", null, "deployment bootstrap role", "system:bootstrap", DateTimeOffset.UnixEpoch); await Mutate(t, "system:bootstrap", "admin.principal.seeded", "principal", id.ToString("D"), "explicit deployment bootstrap principal", x => (x with { Principals = [.. x.Principals, p], Assignments = [.. x.Assignments, assignment] }, null, AdministrationSafety.Hash(p), null), ct); return p;
    }
    public async Task<AdministrativePrincipal> CreatePrincipalAsync(string t, string actor, AdministrativePrincipalType type, string name, string purpose, DateTimeOffset? expires, CancellationToken ct)
    { if (type == AdministrativePrincipalType.SystemPrincipal || string.IsNullOrWhiteSpace(name) || name.Length > 160 || string.IsNullOrWhiteSpace(purpose) || purpose.Length > 500 || expires <= DateTimeOffset.UtcNow) throw new EnrollmentConflictException("PRINCIPAL_INVALID", "Principal type, metadata, or expiration is invalid."); var now = DateTimeOffset.UtcNow; var p = new AdministrativePrincipal(Guid.NewGuid(), t, type, name, AdministrativePrincipalStatus.Active, now, null, type == AdministrativePrincipalType.HumanUser ? "external-provider-not-configured" : "api-credential", purpose, expires, 0, null, null, actor); await Mutate(t, actor, "admin.principal.created", "principal", p.PrincipalId.ToString("D"), purpose, s => (s with { Principals = [.. s.Principals, p] }, null, AdministrationSafety.Hash(p), null), ct); return p; }
    public async Task<AdministrativePrincipal> SetPrincipalStatusAsync(string t, string actor, Guid id, AdministrativePrincipalStatus status, string reason, CancellationToken ct)
    { AdministrativePrincipal? value = null; await Mutate(t, actor, $"admin.principal.{status.ToString().ToLowerInvariant()}", "principal", id.ToString("D"), reason, s => { var old = s.Principals.SingleOrDefault(x => x.PrincipalId == id) ?? throw new KeyNotFoundException(); value = old with { Status = status, DisabledAt = status == AdministrativePrincipalStatus.Active ? null : DateTimeOffset.UtcNow }; return (s with { Principals = s.Principals.Select(x => x.PrincipalId == id ? value : x).ToArray() }, AdministrationSafety.Hash(old), AdministrationSafety.Hash(value), null); }, ct); return value!; }
    public async Task<AdministrativeRole> CreateRoleAsync(string t, string actor, string name, string description, string[] permissions, string reason, Guid? existing, CancellationToken ct)
    { AdministrationSafety.ValidateRole(name, permissions); AdministrativeRole? role = null; await Mutate(t, actor, existing is null ? "admin.role.created" : "admin.role.versioned", "role", (existing ?? Guid.Empty).ToString("D"), reason, s => { var history = existing is null ? [] : s.Roles.Where(x => x.RoleId == existing).ToArray(); if (history.Any(x => x.BuiltIn)) throw new EnrollmentConflictException("BUILTIN_ROLE_IMMUTABLE", "Built-in roles cannot be edited."); var id = existing ?? Guid.NewGuid(); role = new(id, t, history.Select(x => x.Version).DefaultIfEmpty(0).Max() + 1, name, description, false, permissions.Distinct().Order().ToArray(), AdministrationSafety.Hash(permissions.Distinct().Order().ToArray()), actor, reason, DateTimeOffset.UtcNow); return (s with { Roles = [.. s.Roles, role] }, history.MaxBy(x => x.Version)?.DefinitionHash, role.DefinitionHash, null); }, ct); return role!; }
    public async Task<AdministrativeRoleAssignment> AssignRoleAsync(string t, string actor, Guid principal, Guid role, int version, DateTimeOffset starts, DateTimeOffset? expires, bool elevated, string scope, string? scopeId, string reason, CancellationToken ct)
    {
        if (scope is not ("tenant" or "group" or "endpoint") || scope == "tenant" && scopeId is not null || scope != "tenant" && !Guid.TryParse(scopeId, out _)) throw new EnrollmentConflictException("ROLE_ASSIGNMENT_SCOPE_INVALID", "Role assignment scope is malformed."); return await AssignValidated(); async Task<AdministrativeRoleAssignment> AssignValidated()
        { if (starts > DateTimeOffset.UtcNow.AddDays(30) || expires <= starts || elevated && expires is null || expires > DateTimeOffset.UtcNow.AddDays(90) || string.IsNullOrWhiteSpace(reason)) throw new EnrollmentConflictException("ROLE_ASSIGNMENT_INVALID", "Role assignment time bounds or reason are invalid."); AdministrativeRoleAssignment? a = null; await Mutate(t, actor, "admin.role.assigned", "assignment", principal.ToString("D"), reason, s => { var p = s.Principals.SingleOrDefault(x => x.PrincipalId == principal) ?? throw new KeyNotFoundException(); var r = s.Roles.SingleOrDefault(x => x.RoleId == role && x.Version == version && x.Active) ?? throw new KeyNotFoundException(); if (p.TenantId != t || r.TenantId != t) throw new EnrollmentConflictException("TENANT_SCOPE_VIOLATION", "Cross-tenant role assignment rejected."); a = new(Guid.NewGuid(), t, principal, role, version, starts, expires, elevated, scope, scopeId, reason, actor, DateTimeOffset.UtcNow); return (s with { Assignments = [.. s.Assignments, a] }, null, AdministrationSafety.Hash(a), null); }, ct); return a!; }
    }
    public Task RevokeAssignmentAsync(string t, string actor, Guid id, string reason, CancellationToken ct) => Mutate(t, actor, "admin.role.revoked", "assignment", id.ToString("D"), reason, s => { var old = s.Assignments.SingleOrDefault(x => x.AssignmentId == id) ?? throw new KeyNotFoundException(); var value = old with { RevokedAt = DateTimeOffset.UtcNow, RevokedBy = actor }; return (s with { Assignments = s.Assignments.Select(x => x.AssignmentId == id ? value : x).ToArray() }, AdministrationSafety.Hash(old), AdministrationSafety.Hash(value), null); }, ct);
    public async Task<EffectivePermissionSet> EffectivePermissionsAsync(string t, Guid principal, CancellationToken ct)
    { var s = await State(t, ct); var p = s.Principals.SingleOrDefault(x => x.PrincipalId == principal) ?? throw new KeyNotFoundException(); var now = DateTimeOffset.UtcNow; var active = s.Assignments.Where(x => x.PrincipalId == principal && x.RevokedAt is null && x.StartsAt <= now && (x.ExpiresAt is null || x.ExpiresAt > now)); var values = active.SelectMany(a => s.Roles.Where(r => r.RoleId == a.RoleId && r.Version == a.RoleVersion && r.Active).SelectMany(r => r.Permissions.Select(x => new EffectivePermissionEntry(x, r.Name, r.RoleId, r.Version, a.ExpiresAt, a.ScopeType, a.ScopeId)))).DistinctBy(x => x.Permission).OrderBy(x => x.Permission).ToArray(); if (p.Type == AdministrativePrincipalType.SystemPrincipal && p.AuthenticationSource == "deployment-bootstrap") values = PermissionRegistry.All.Select(x => new EffectivePermissionEntry(x, "Deployment bootstrap system boundary", Guid.Empty, 1, null, "platform", null)).ToArray(); var restrictions = new List<string>(); if (p.Status != AdministrativePrincipalStatus.Active) restrictions.Add($"principal-{p.Status.ToString().ToLowerInvariant()}"); if (p.ExpiresAt <= now) restrictions.Add("principal-expired"); return new(principal, t, p.Status, values, restrictions.ToArray(), now); }
    public async Task<ApiCredentialSecret> CreateCredentialAsync(string t, string actor, Guid principal, string name, string purpose, DateTimeOffset expires, CancellationToken ct)
    { if (expires <= DateTimeOffset.UtcNow || expires > DateTimeOffset.UtcNow.AddDays(90) || string.IsNullOrWhiteSpace(name) || name.Length > 120 || string.IsNullOrWhiteSpace(purpose) || purpose.Length > 500) throw new EnrollmentConflictException("CREDENTIAL_LIFETIME_INVALID", "Credential metadata is required and it must expire within 90 days."); var s = await State(t, ct); var p = s.Principals.SingleOrDefault(x => x.PrincipalId == principal) ?? throw new KeyNotFoundException(); if (p.Type is not (AdministrativePrincipalType.ApiClient or AdministrativePrincipalType.ServiceAccount) || p.Status != AdministrativePrincipalStatus.Active) throw new EnrollmentConflictException("CREDENTIAL_PRINCIPAL_INVALID", "Credentials require an active non-human principal."); var id = Guid.NewGuid(); var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)); var prefix = $"osp_{id:N}"; var meta = new ApiCredentialMetadata(id, t, principal, p.CredentialVersion + 1, name, prefix, DateTimeOffset.UtcNow, expires, null, null, actor, purpose); await Mutate(t, actor, "admin.credential.created", "credential", id.ToString("D"), purpose, x => (x with { Credentials = [.. x.Credentials, meta], Principals = x.Principals.Select(v => v.PrincipalId == principal ? v with { CredentialVersion = meta.Version, CredentialsRotatedAt = DateTimeOffset.UtcNow } : v).ToArray() }, null, AdministrationSafety.Hash(meta), null), ct); await store.PutCredentialAsync(new(meta, PasswordHasher.Hash(secret)), ct); return new(meta, $"{prefix}_{secret}"); }
    public async Task<ApiCredentialSecret> RotateCredentialAsync(string t, string actor, Guid id, string reason, DateTimeOffset expires, CancellationToken ct) { var s = await State(t, ct); var old = s.Credentials.SingleOrDefault(x => x.CredentialId == id) ?? throw new KeyNotFoundException(); await RevokeCredentialAsync(t, actor, id, "rotation: " + reason, ct); return await CreateCredentialAsync(t, actor, old.PrincipalId, old.Name, old.Purpose, expires, ct); }
    public async Task RevokeCredentialAsync(string t, string actor, Guid id, string reason, CancellationToken ct) { await Mutate(t, actor, "admin.credential.revoked", "credential", id.ToString("D"), reason, s => { var old = s.Credentials.SingleOrDefault(x => x.CredentialId == id) ?? throw new KeyNotFoundException(); var value = old with { RevokedAt = DateTimeOffset.UtcNow }; return (s with { Credentials = s.Credentials.Select(x => x.CredentialId == id ? value : x).ToArray() }, AdministrationSafety.Hash(old), AdministrationSafety.Hash(value), null); }, ct); var stored = await store.CredentialAsync(id, ct); if (stored is not null) await store.PutCredentialAsync(stored with { Metadata = stored.Metadata with { RevokedAt = DateTimeOffset.UtcNow } }, ct); }
    public async Task<PrincipalContext?> AuthenticateCredentialAsync(string value, CancellationToken ct)
    { var p = value.Split('_', 3); if (p.Length != 3 || !Guid.TryParseExact(p[1], "N", out var id)) return null; var c = await store.CredentialAsync(id, ct); if (c is null || c.Metadata.RevokedAt is not null || c.Metadata.ExpiresAt <= DateTimeOffset.UtcNow || !PasswordHasher.Verify(p[2], c.SecretHash)) return null; var s = await State(c.Metadata.TenantId, ct); var metadata = s.Credentials.SingleOrDefault(x => x.CredentialId == id); if (metadata is null || metadata.RevokedAt is not null || metadata.ExpiresAt <= DateTimeOffset.UtcNow || metadata.Version != c.Metadata.Version || metadata.PrincipalId != c.Metadata.PrincipalId || metadata.TenantId != c.Metadata.TenantId) return null; var principal = s.Principals.SingleOrDefault(x => x.PrincipalId == c.Metadata.PrincipalId); if (principal is null || principal.Status != AdministrativePrincipalStatus.Active || principal.ExpiresAt <= DateTimeOffset.UtcNow) return null; var effective = await EffectivePermissionsAsync(c.Metadata.TenantId, principal.PrincipalId, ct); if (effective.Restrictions.Length > 0) return null; var used = DateTimeOffset.UtcNow; await store.TouchCredentialAsync(id, used, ct); await RecordActivity(c.Metadata.TenantId, id, principal.PrincipalId, used, ct); return new(principal.PrincipalId.ToString("D"), principal.TenantId, TenantPermissions(effective), principal.Type == AdministrativePrincipalType.ApiClient ? "api-client" : "service-account"); }
    async Task RecordActivity(string tenant, Guid credential, Guid principal, DateTimeOffset used, CancellationToken ct) { for (var i = 0; i < 3; i++) { var s = await State(tenant, ct); var next = s with { Credentials = s.Credentials.Select(x => x.CredentialId == credential ? x with { LastUsedAt = used } : x).ToArray(), Principals = s.Principals.Select(x => x.PrincipalId == principal ? x with { LastActivity = used } : x).ToArray() }; try { await store.SaveAsync(tenant, s.Revision, next, [], ct); return; } catch (EnrollmentConflictException) when (i < 2) { } } }
    public async Task<PrincipalContext?> ResolveManagedPrincipalAsync(PrincipalContext p, CancellationToken ct) { if (!Guid.TryParse(p.Subject, out var id)) return p; try { var e = await EffectivePermissionsAsync(p.TenantId, id, ct); var state = await State(p.TenantId, ct); var principal = state.Principals.Single(x => x.PrincipalId == id); var type = principal.Type switch { AdministrativePrincipalType.ApiClient => "api-client", AdministrativePrincipalType.ServiceAccount => "service-account", AdministrativePrincipalType.SystemPrincipal => "system", _ => "user" }; return e.Restrictions.Length == 0 && e.Status == AdministrativePrincipalStatus.Active ? p with { Permissions = TenantPermissions(e), Type = type } : null; } catch (KeyNotFoundException) { return null; } }
    static HashSet<string> TenantPermissions(EffectivePermissionSet value) => value.Permissions.Where(x => x.ScopeType is "tenant" or "platform").Select(x => x.Permission).Append("authenticated").ToHashSet(StringComparer.Ordinal);
    public async Task<bool> IsScopedPermissionAllowedAsync(string tenant, Guid principal, string permission, Guid endpoint, IReadOnlySet<Guid> endpointGroups, CancellationToken ct) { var e = await EffectivePermissionsAsync(tenant, principal, ct); if (e.Restrictions.Length > 0) return false; return e.Permissions.Any(x => x.Permission == permission && (x.ScopeType == "endpoint" && Guid.TryParse(x.ScopeId, out var id) && id == endpoint || x.ScopeType == "group" && Guid.TryParse(x.ScopeId, out id) && endpointGroups.Contains(id))); }
    public async Task<ConfigurationVersion> CreateConfigurationAsync(string t, string actor, string key, ConfigurationScope scope, Guid? scopeId, JsonElement value, string reason, string confirmationHash, CancellationToken ct)
    { var d = AdministrationSafety.Definition(key); if (!d.Scopes.Contains(scope) || scope == ConfigurationScope.PlatformDefault || scope != ConfigurationScope.Tenant && scopeId is null || string.IsNullOrWhiteSpace(reason)) throw new EnrollmentConflictException("CONFIGURATION_SCOPE_INVALID", "Configuration scope or reason is invalid."); AdministrationSafety.ValidateValue(d, value); var expected = AdministrationSafety.Hash(new { key, scope, scopeId, value, reason }); if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(confirmationHash))) throw new EnrollmentConflictException("CONFIGURATION_CONFIRMATION_INVALID", "Preview confirmation hash is stale or forged."); ConfigurationVersion? result = null; await Mutate(t, actor, "admin.configuration.version.created", "configuration", key, reason, s => { var history = s.Configurations.Where(x => x.Key == key && x.Scope == scope && x.ScopeId == scopeId).ToArray(); var identity = history.MaxBy(x => x.Version)?.ConfigurationId ?? Guid.NewGuid(); result = new(identity, t, key, history.Select(x => x.Version).DefaultIfEmpty(0).Max() + 1, scope, scopeId, value.Clone(), AdministrationSafety.Hash(value), d.HighRisk ? ConfigurationVersionState.PendingApproval : ConfigurationVersionState.Draft, actor, reason, DateTimeOffset.UtcNow, d.HighRisk ? Guid.NewGuid() : null, null, null, null, null, $"{history.MaxBy(x => x.Version)?.Value.GetRawText() ?? d.DefaultValue.GetRawText()} -> {value.GetRawText()}"); return (s with { Configurations = [.. s.Configurations, result] }, history.MaxBy(x => x.Version)?.ValueHash, result.ValueHash, result.ApprovalId); }, ct); return result!; }
    public static ConfigurationPreview Preview(string key, ConfigurationScope scope, Guid? scopeId, JsonElement value, string reason, int endpoints, int rollout) { var d = AdministrationSafety.Definition(key); AdministrationSafety.ValidateValue(d, value); if (rollout is < 1 or > 100) throw new EnrollmentConflictException("ROLLOUT_BOUNDS_INVALID", "Rollout percent must be 1-100."); var hash = AdministrationSafety.Hash(new { key, scope, scopeId, value, reason }); return new(key, scope, scopeId, d.DefaultValue, value, ["admin.policy"], d.SecurityClassification, endpoints, rollout, d.HighRisk, hash); }
    public async Task<ConfigurationVersion> ApproveConfigurationAsync(string t, string actor, Guid id, int version, string reason, CancellationToken ct) { ConfigurationVersion? value = null; await Mutate(t, actor, "admin.configuration.approved", "configuration", id.ToString("D"), reason, s => { var old = s.Configurations.SingleOrDefault(x => x.ConfigurationId == id && x.Version == version) ?? throw new KeyNotFoundException(); if (old.State != ConfigurationVersionState.PendingApproval || old.Author == actor) throw new EnrollmentConflictException("CONFIGURATION_APPROVAL_INVALID", "Separated approver and pending state are required."); value = old with { State = ConfigurationVersionState.Draft, ApprovedBy = actor, ApprovedAt = DateTimeOffset.UtcNow }; return (s with { Configurations = s.Configurations.Select(x => x.ConfigurationId == id && x.Version == version ? value : x).ToArray() }, old.ValueHash, value.ValueHash, old.ApprovalId); }, ct); return value!; }
    public async Task<ConfigurationVersion> ActivateConfigurationAsync(string t, string actor, Guid id, int version, int rollout, DateTimeOffset? start, DateTimeOffset? end, string reason, CancellationToken ct) { ConfigurationVersion? value = null; await Mutate(t, actor, "admin.configuration.activated", "configuration", id.ToString("D"), reason, s => { var old = s.Configurations.SingleOrDefault(x => x.ConfigurationId == id && x.Version == version) ?? throw new KeyNotFoundException(); if (old.State != ConfigurationVersionState.Draft || AdministrationSafety.Definition(old.Key).HighRisk && old.ApprovedBy is null) throw new EnrollmentConflictException("CONFIGURATION_ACTIVATION_BLOCKED", "Validated draft and required separated approval are required."); if (rollout is < 1 or > 100 || start is not null && end <= start || start is not null && end - start > TimeSpan.FromHours(24)) throw new EnrollmentConflictException("ROLLOUT_BOUNDS_INVALID", "Rollout or maintenance window is invalid."); value = old with { State = ConfigurationVersionState.Active, ActivatedAt = DateTimeOffset.UtcNow }; var prior = s.Configurations.Select(x => x.Key == old.Key && x.Scope == old.Scope && x.ScopeId == old.ScopeId && x.State == ConfigurationVersionState.Active ? x with { State = ConfigurationVersionState.Disabled, DeactivatedAt = DateTimeOffset.UtcNow } : x).ToArray(); var assignment = new ConfigurationAssignment(Guid.NewGuid(), t, id, version, old.Scope, old.ScopeId, DateTimeOffset.UtcNow, actor, rollout, start, end, true); return (s with { Configurations = prior.Select(x => x.ConfigurationId == id && x.Version == version ? value : x).ToArray(), ConfigurationAssignments = [.. s.ConfigurationAssignments, assignment] }, old.ValueHash, value.ValueHash, old.ApprovalId); }, ct); return value!; }
    public async Task<ConfigurationVersion> RollbackConfigurationAsync(string t, string actor, Guid id, int sourceVersion, string reason, CancellationToken ct) { var s = await State(t, ct); var old = s.Configurations.SingleOrDefault(x => x.ConfigurationId == id && x.Version == sourceVersion) ?? throw new KeyNotFoundException(); var preview = Preview(old.Key, old.Scope, old.ScopeId, old.Value, reason, 0, 100); return await CreateConfigurationAsync(t, actor, old.Key, old.Scope, old.ScopeId, old.Value, reason, preview.ConfirmationHash, ct); }
    public async Task<EffectiveConfiguration> EffectiveConfigurationAsync(string t, string key, Guid? group, Guid? endpoint, CancellationToken ct) { var d = AdministrationSafety.Definition(key); var s = await State(t, ct); var active = s.Configurations.Where(x => x.Key == key && x.State == ConfigurationVersionState.Active).ToArray(); var ordered = active.OrderBy(x => x.Scope switch { ConfigurationScope.Tenant => 1, ConfigurationScope.EndpointGroup when x.ScopeId == group => 2, ConfigurationScope.Endpoint when x.ScopeId == endpoint => 3, _ => 0 }).ToArray(); var effective = ordered.LastOrDefault(x => x.Scope == ConfigurationScope.Tenant || x.Scope == ConfigurationScope.EndpointGroup && x.ScopeId == group || x.Scope == ConfigurationScope.Endpoint && x.ScopeId == endpoint); var value = effective?.Value ?? d.DefaultValue; var ack = endpoint is null ? null : s.Acknowledgements.Where(x => x.EndpointId == endpoint && x.Key == key).MaxBy(x => x.ReportedAt); var drift = endpoint is null ? ConfigurationDriftState.Unknown : ack is null ? ConfigurationDriftState.Pending : ack.ExpectedVersion != (effective?.Version ?? 0) ? ConfigurationDriftState.Stale : !ack.Applied || ack.ReportedHash != AdministrationSafety.Hash(value) ? ConfigurationDriftState.Drifted : ConfigurationDriftState.InSync; return new(key, value, AdministrationSafety.Hash(value), effective?.Scope ?? ConfigurationScope.PlatformDefault, effective?.ScopeId, effective?.Version ?? 0, ordered.Where(x => x != effective).ToArray(), d.NonOverridableSafetyFloor ? $"platform safety floor: {d.DefaultValue.GetRawText()}" : null, drift, ack); }
    public Task AcknowledgeAsync(string t, string actor, PolicyAcknowledgement ack, CancellationToken ct) => Mutate(t, actor, "admin.policy.acknowledged", "endpoint", ack.EndpointId.ToString("D"), ack.Error ?? "policy acknowledgement", s => (s with { Acknowledgements = [.. s.Acknowledgements.Where(x => !(x.EndpointId == ack.EndpointId && x.Key == ack.Key)), ack] }, null, AdministrationSafety.Hash(ack), null), ct);
    public Task<IReadOnlyList<AdministrativeAuditEvent>> AuditAsync(string t, AdministrativeAuditQuery q, CancellationToken ct) { if (q.From is not null && q.To - q.From > TimeSpan.FromDays(90) || q.Limit is < 1 or > 1000) throw new EnrollmentConflictException("AUDIT_QUERY_BOUNDS", "Audit search is limited to 90 days and 1,000 rows."); return store.AuditAsync(t, q, ct); }
    public async Task<AdministrativeHealth> HealthAsync(string t, CancellationToken ct) { var s = await State(t, ct); var now = DateTimeOffset.UtcNow; var effective = await Task.WhenAll(s.Principals.Select(x => EffectivePermissionsAsync(t, x.PrincipalId, ct))); return new(s.Principals.Count(x => x.Type == AdministrativePrincipalType.HumanUser && x.Status == AdministrativePrincipalStatus.Active), s.Principals.Count(x => x.Status == AdministrativePrincipalStatus.Disabled), s.Principals.Count(x => x.Type == AdministrativePrincipalType.ServiceAccount), s.Principals.Count(x => x.Type == AdministrativePrincipalType.ApiClient), s.Credentials.Count(x => x.RevokedAt is null && x.ExpiresAt <= now.AddDays(14)), s.Roles.Count(x => !x.BuiltIn), s.Configurations.Length, effective.Sum(x => x.Restrictions.Length), s.Acknowledgements.Count(x => !x.Applied), s.Configurations.Count(x => x.State == ConfigurationVersionState.PendingApproval), s.Configurations.Count(x => AdministrationSafety.Definition(x.Key).HighRisk), await store.AuditCountAsync(t, ct), true); }
}
