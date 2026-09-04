using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Routing;
using OpenSecurityPlatform.Foundation;

static class AdministrationRoutes
{
    sealed record PrincipalCreate(AdministrativePrincipalType Type, string DisplayName, string Purpose, DateTimeOffset? ExpiresAt);
    sealed record ReasonRequest(string Reason);
    sealed record RoleCreate(string Name, string Description, string[] Permissions, string Reason, Guid? ExistingRoleId = null);
    sealed record AssignmentCreate(Guid PrincipalId, Guid RoleId, int RoleVersion, DateTimeOffset StartsAt, DateTimeOffset? ExpiresAt, bool TemporaryElevation, string ScopeType = "tenant", string? ScopeId = null, string Reason = "explicit role assignment");
    sealed record CredentialCreate(Guid PrincipalId, string Name, string Purpose, DateTimeOffset ExpiresAt);
    sealed record CredentialRotate(string Reason, DateTimeOffset ExpiresAt);
    sealed record ConfigurationPreviewRequest(string Key, ConfigurationScope Scope, Guid? ScopeId, JsonElement Value, string Reason, int RolloutPercent = 10);
    sealed record ConfigurationCreateRequest(string Key, ConfigurationScope Scope, Guid? ScopeId, JsonElement Value, string Reason, string ConfirmationHash);
    sealed record ConfigurationActivateRequest(int RolloutPercent, string Reason, DateTimeOffset? MaintenanceStart = null, DateTimeOffset? MaintenanceEnd = null);
    sealed record ConfigurationRollbackRequest(int SourceVersion, string Reason);
    sealed record AuditExportRequest(string Format, AdministrativeAuditQuery Query);
    sealed record PermissionRoute(string Method, string Route, string Permission, string Classification);

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/admin/overview", Overview).RequirePermission("admin.audit");
        app.MapGet("/api/v1/admin/principals", Principals).RequirePermission("admin.users");
        app.MapGet("/api/v1/admin/principals/{id:guid}", Principal).RequirePermission("admin.users");
        app.MapPost("/api/v1/admin/principals", CreatePrincipal).RequirePermission("admin.users");
        app.MapPost("/api/v1/admin/principals/{id:guid}:disable", (Guid id, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Status(id, AdministrativePrincipalStatus.Disabled, x, c, s, ct)).RequirePermission("admin.users");
        app.MapPost("/api/v1/admin/principals/{id:guid}:enable", (Guid id, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Status(id, AdministrativePrincipalStatus.Active, x, c, s, ct)).RequirePermission("admin.users");
        app.MapPost("/api/v1/admin/principals/{id:guid}:revoke", (Guid id, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Status(id, AdministrativePrincipalStatus.Revoked, x, c, s, ct)).RequirePermission("admin.users");
        app.MapPost("/api/v1/admin/principals/{id:guid}:expire", (Guid id, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Status(id, AdministrativePrincipalStatus.Expired, x, c, s, ct)).RequirePermission("admin.users");
        app.MapGet("/api/v1/admin/principals/{id:guid}/effective-permissions", EffectivePermissions).RequirePermission("admin.roles");
        app.MapGet("/api/v1/admin/roles", Roles).RequirePermission("admin.roles");
        app.MapGet("/api/v1/admin/roles/{id:guid}", Role).RequirePermission("admin.roles");
        app.MapPost("/api/v1/admin/roles", CreateRole).RequirePermission("admin.roles");
        app.MapPost("/api/v1/admin/roles/{id:guid}/versions", VersionRole).RequirePermission("admin.roles");
        app.MapPost("/api/v1/admin/role-assignments", AssignRole).RequirePermission("admin.roles");
        app.MapPost("/api/v1/admin/role-assignments/{id:guid}:revoke", RevokeAssignment).RequirePermission("admin.roles");
        app.MapGet("/api/v1/admin/permissions", Permissions).RequirePermission("admin.roles");
        app.MapGet("/api/v1/admin/permissions/routes", RoutePermissions).RequirePermission("admin.audit");
        app.MapGet("/api/v1/admin/api-clients", Credentials).RequirePermission("admin.api_clients");
        app.MapPost("/api/v1/admin/api-clients/credentials", CreateCredential).RequirePermission("admin.api_clients");
        app.MapPost("/api/v1/admin/api-clients/credentials/{id:guid}:rotate", RotateCredential).RequirePermission("admin.api_clients");
        app.MapPost("/api/v1/admin/api-clients/credentials/{id:guid}:revoke", RevokeCredential).RequirePermission("admin.api_clients");
        app.MapGet("/api/v1/admin/configuration-registry", Registry).RequirePermission("admin.policy");
        app.MapGet("/api/v1/admin/configurations", Configurations).RequirePermission("admin.policy");
        app.MapGet("/api/v1/admin/configurations/{id:guid}/{version:int}", ConfigurationDetail).RequirePermission("admin.policy");
        app.MapGet("/api/v1/admin/configurations/{id:guid}/{version:int}/diff", ConfigurationDiff).RequirePermission("admin.policy");
        app.MapPost("/api/v1/admin/configurations:preview", Preview).RequirePermission("admin.policy");
        app.MapPost("/api/v1/admin/configurations", CreateConfiguration).RequirePermission("admin.policy");
        app.MapPost("/api/v1/admin/configurations/{id:guid}/{version:int}:approve", ApproveConfiguration).RequirePermission("admin.policy");
        app.MapPost("/api/v1/admin/configurations/{id:guid}/{version:int}:activate", ActivateConfiguration).RequirePermission("admin.policy");
        app.MapPost("/api/v1/admin/configurations/{id:guid}:rollback", RollbackConfiguration).RequirePermission("admin.policy");
        app.MapGet("/api/v1/admin/configurations/{key}/effective", EffectiveConfiguration).RequirePermission("admin.policy");
        app.MapPost("/agent/v1/administration-policy:acknowledge", Acknowledge).RequirePermission("agent:heartbeat");
        app.MapGet("/api/v1/admin/audit", Audit).RequirePermission("admin.audit");
        app.MapGet("/api/v1/admin/audit/{id:guid}", AuditDetail).RequirePermission("admin.audit");
        app.MapPost("/api/v1/admin/audit-exports", AuditExport).RequirePermission("admin.audit");
        app.MapGet("/api/v1/admin/audit-exports/{id:guid}/manifest", ExportManifest).RequirePermission("admin.audit");
        app.MapGet("/api/v1/admin/audit-exports/{id:guid}/content", ExportContent).RequirePermission("admin.audit");
    }
    static string Tenant(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).TenantId;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static async Task<IResult> Overview(HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.HealthAsync(Tenant(c), ct));
    static async Task<IResult> Principals(HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, (await s.GetAsync(Tenant(c), ct)).Principals.OrderBy(x => x.DisplayName));
    static async Task<IResult> Principal(Guid id, HttpContext c, AdministrationService s, CancellationToken ct) { var x = (await s.GetAsync(Tenant(c), ct)).Principals.SingleOrDefault(x => x.PrincipalId == id); return x is null ? Results.NotFound() : Ok(c, x); }
    static async Task<IResult> CreatePrincipal(PrincipalCreate x, HttpContext c, AdministrationService s, CancellationToken ct) => Results.Created("/api/v1/admin/principals", new ApiEnvelope<object>(await s.CreatePrincipalAsync(Tenant(c), Actor(c), x.Type, x.DisplayName, x.Purpose, x.ExpiresAt, ct), new(c.TraceIdentifier, "1.0")));
    static async Task<IResult> Status(Guid id, AdministrativePrincipalStatus status, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.SetPrincipalStatusAsync(Tenant(c), Actor(c), id, status, x.Reason, ct));
    static async Task<IResult> EffectivePermissions(Guid id, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.EffectivePermissionsAsync(Tenant(c), id, ct));
    static async Task<IResult> Roles(HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, (await s.GetAsync(Tenant(c), ct)).Roles.OrderBy(x => x.Name).ThenByDescending(x => x.Version));
    static async Task<IResult> Role(Guid id, HttpContext c, AdministrationService s, CancellationToken ct) { var x = (await s.GetAsync(Tenant(c), ct)).Roles.Where(x => x.RoleId == id).OrderByDescending(x => x.Version).ToArray(); return x.Length == 0 ? Results.NotFound() : Ok(c, x); }
    static async Task<IResult> CreateRole(RoleCreate x, HttpContext c, AdministrationService s, CancellationToken ct) => Results.Created("/api/v1/admin/roles", new ApiEnvelope<object>(await s.CreateRoleAsync(Tenant(c), Actor(c), x.Name, x.Description, x.Permissions, x.Reason, null, ct), new(c.TraceIdentifier, "1.0")));
    static async Task<IResult> VersionRole(Guid id, RoleCreate x, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.CreateRoleAsync(Tenant(c), Actor(c), x.Name, x.Description, x.Permissions, x.Reason, id, ct));
    static async Task<IResult> AssignRole(AssignmentCreate x, HttpContext c, AdministrationService s, IEndpointRepository endpoints, IFleetUpdateRepository fleet, CancellationToken ct)
    {
        if (x.ScopeType == "endpoint" && (!Guid.TryParse(x.ScopeId, out var endpoint) || await endpoints.GetEndpointAsync(Tenant(c), endpoint, ct) is null) || x.ScopeType == "group" && (!Guid.TryParse(x.ScopeId, out var group) || !(await fleet.GroupsAsync(Tenant(c), ct)).Any(v => v.GroupId == group))) throw new EnrollmentConflictException("ROLE_ASSIGNMENT_SCOPE_INVALID", "Role assignment target is missing or outside the tenant.");
        return Ok(c, await s.AssignRoleAsync(Tenant(c), Actor(c), x.PrincipalId, x.RoleId, x.RoleVersion, x.StartsAt, x.ExpiresAt, x.TemporaryElevation, x.ScopeType, x.ScopeId, x.Reason, ct));
    }
    static async Task<IResult> RevokeAssignment(Guid id, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) { await s.RevokeAssignmentAsync(Tenant(c), Actor(c), id, x.Reason, ct); return Results.NoContent(); }
    static IResult Permissions(HttpContext c) => Ok(c, PermissionRegistry.All.Select(x => new { permission = x, registered = true, internalOnly = x is "system:admin" or "agent:heartbeat" }));
    static IResult RoutePermissions(HttpContext c, IEnumerable<EndpointDataSource> sources)
    {
        var routes = sources.SelectMany(x => x.Endpoints).OfType<RouteEndpoint>().Select(x => { var methods = x.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods; var method = methods is { Count: > 0 } ? methods[0] : "ANY"; var permission = x.Metadata.GetMetadata<RequiredPermissionMetadata>()?.Permission; var route = x.RoutePattern.RawText ?? ""; return new PermissionRoute(method, route, permission ?? "(none)", Classify(route, permission)); }).Where(x => x.Route.StartsWith("/api/", StringComparison.Ordinal) || x.Route.StartsWith("/agent/", StringComparison.Ordinal) || x.Route.StartsWith("/internal/", StringComparison.Ordinal)).OrderBy(x => x.Route).ToArray(); return Ok(c, new { routes, sensitiveWithoutExplicitPermission = routes.Count(x => x.Classification == "FAIL"), passed = routes.All(x => x.Classification != "FAIL") });
        static string Classify(string route, string? permission) { if (permission is not null) return "explicit"; return route.StartsWith("/api/v1/auth/", StringComparison.Ordinal) || route == "/agent/v1/register" || route == "/api/v1/openapi.json" || route.EndsWith("/download", StringComparison.Ordinal) || route.Contains("download?token", StringComparison.Ordinal) ? "explicit alternate credential" : "FAIL"; }
    }
    static async Task<IResult> Credentials(HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, (await s.GetAsync(Tenant(c), ct)).Credentials);
    static async Task<IResult> CreateCredential(CredentialCreate x, HttpContext c, AdministrationService s, CancellationToken ct) => Results.Created("/api/v1/admin/api-clients", new ApiEnvelope<object>(await s.CreateCredentialAsync(Tenant(c), Actor(c), x.PrincipalId, x.Name, x.Purpose, x.ExpiresAt, ct), new(c.TraceIdentifier, "1.0")));
    static async Task<IResult> RotateCredential(Guid id, CredentialRotate x, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.RotateCredentialAsync(Tenant(c), Actor(c), id, x.Reason, x.ExpiresAt, ct));
    static async Task<IResult> RevokeCredential(Guid id, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) { await s.RevokeCredentialAsync(Tenant(c), Actor(c), id, x.Reason, ct); return Results.NoContent(); }
    static IResult Registry(HttpContext c) => Ok(c, AdministrationSafety.ConfigurationRegistry);
    static async Task<IResult> Configurations(HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, (await s.GetAsync(Tenant(c), ct)).Configurations.OrderBy(x => x.Key).ThenByDescending(x => x.Version));
    static async Task<IResult> ConfigurationDetail(Guid id, int version, HttpContext c, AdministrationService s, CancellationToken ct) { var x = (await s.GetAsync(Tenant(c), ct)).Configurations.SingleOrDefault(x => x.ConfigurationId == id && x.Version == version); return x is null ? Results.NotFound() : Ok(c, x); }
    static async Task<IResult> ConfigurationDiff(Guid id, int version, HttpContext c, AdministrationService s, CancellationToken ct) { var state = await s.GetAsync(Tenant(c), ct); var x = state.Configurations.SingleOrDefault(x => x.ConfigurationId == id && x.Version == version); if (x is null) return Results.NotFound(); var prior = state.Configurations.Where(v => v.ConfigurationId == id && v.Version < version).MaxBy(v => v.Version); return Ok(c, new { configurationId = id, version, previousVersion = prior?.Version, before = prior?.Value, after = x.Value, x.Diff, x.ValueHash }); }
    static async Task<IResult> Preview(ConfigurationPreviewRequest x, HttpContext c, AdministrationService s, IEndpointRepository endpoints, IFleetUpdateRepository fleet, CancellationToken ct) { var count = await ValidateScope(Tenant(c), x.Scope, x.ScopeId, endpoints, fleet, ct); return Ok(c, AdministrationService.Preview(x.Key, x.Scope, x.ScopeId, x.Value, x.Reason, count, x.RolloutPercent)); }
    static async Task<IResult> CreateConfiguration(ConfigurationCreateRequest x, HttpContext c, AdministrationService s, IEndpointRepository endpoints, IFleetUpdateRepository fleet, CancellationToken ct) { await ValidateScope(Tenant(c), x.Scope, x.ScopeId, endpoints, fleet, ct); return Results.Created("/api/v1/admin/configurations", new ApiEnvelope<object>(await s.CreateConfigurationAsync(Tenant(c), Actor(c), x.Key, x.Scope, x.ScopeId, x.Value, x.Reason, x.ConfirmationHash, ct), new(c.TraceIdentifier, "1.0"))); }
    static async Task<IResult> ApproveConfiguration(Guid id, int version, ReasonRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.ApproveConfigurationAsync(Tenant(c), Actor(c), id, version, x.Reason, ct));
    static async Task<IResult> ActivateConfiguration(Guid id, int version, ConfigurationActivateRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.ActivateConfigurationAsync(Tenant(c), Actor(c), id, version, x.RolloutPercent, x.MaintenanceStart, x.MaintenanceEnd, x.Reason, ct));
    static async Task<IResult> RollbackConfiguration(Guid id, ConfigurationRollbackRequest x, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.RollbackConfigurationAsync(Tenant(c), Actor(c), id, x.SourceVersion, x.Reason, ct));
    static async Task<IResult> EffectiveConfiguration(string key, Guid? groupId, Guid? endpointId, HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.EffectiveConfigurationAsync(Tenant(c), key, groupId, endpointId, ct));
    static async Task<IResult> Acknowledge(PolicyAcknowledgement x, HttpContext c, AdministrationService s, CancellationToken ct) { var p = (PrincipalContext)c.Items["principal"]!; var ids = p.Subject.Split(':'); if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint) || endpoint != x.EndpointId || x.TenantId != p.TenantId) return Results.Unauthorized(); await s.AcknowledgeAsync(p.TenantId, p.Subject, x, ct); return Results.Accepted(); }
    static AdministrativeAuditQuery Query(HttpContext c) { var q = c.Request.Query; return new(DateTimeOffset.TryParse(q["from"], out var f) ? f : null, DateTimeOffset.TryParse(q["to"], out var t) ? t : null, q["principal"], q["action"], q["resource"], q["subsystem"], q["result"], Guid.TryParse(q["approvalId"], out var a) ? a : null, int.TryParse(q["limit"], out var n) ? n : 200); }
    static async Task<IResult> Audit(HttpContext c, AdministrationService s, CancellationToken ct) => Ok(c, await s.AuditAsync(Tenant(c), Query(c), ct));
    static async Task<IResult> AuditDetail(Guid id, HttpContext c, AdministrationService s, CancellationToken ct) { var x = (await s.AuditAsync(Tenant(c), new(Limit: 1000), ct)).SingleOrDefault(x => x.AuditId == id); return x is null ? Results.NotFound() : Ok(c, x); }
    static async Task<IResult> AuditExport(AuditExportRequest x, HttpContext c, AdministrationService s, IObjectStorage objects, CancellationToken ct)
    {
        if (x.Format is not ("jsonl" or "csv") || x.Query.From is null || x.Query.To is null || x.Query.To <= x.Query.From || x.Query.To - x.Query.From > TimeSpan.FromDays(90)) return Results.BadRequest();
        var rows = await s.AuditAsync(Tenant(c), x.Query with { Limit = Math.Clamp(x.Query.Limit, 1, 1000) }, ct);
        var content = x.Format == "jsonl" ? string.Join('\n', rows.Select(v => JsonSerializer.Serialize(v))) + "\n" : "auditId,occurredAt,actor,action,resourceType,resourceId,result,requestId\n" + string.Join('\n', rows.Select(v => string.Join(',', v.AuditId, v.OccurredAt.ToString("O"), Csv(v.Actor), Csv(v.Action), Csv(v.ResourceType), Csv(v.ResourceId), Csv(v.Result), Csv(v.RequestId)))) + "\n";
        var bytes = Encoding.UTF8.GetBytes(content); var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); var id = Guid.NewGuid(); var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "administrative-audit-export.v1", exportId = id, tenantId = Tenant(c), rowCount = rows.Count, requestedBy = Actor(c), requestedAt = DateTimeOffset.UtcNow, sha256 = hash, format = x.Format });
        await Upload(objects, Tenant(c), id, "content", bytes, x.Format == "csv" ? "text/csv" : "application/x-ndjson", ct); await Upload(objects, Tenant(c), id, "manifest", manifest, "application/json", ct);
        await s.RecordAuditExportAsync(Tenant(c), Actor(c), id, hash, "bounded administrative audit export", ct);
        return Results.Created($"/api/v1/admin/audit-exports/{id:D}/manifest", new ApiEnvelope<object>(new { id, rowCount = rows.Count, sha256 = hash, format = x.Format }, new(c.TraceIdentifier, "1.0")));
    }
    static async Task<IResult> ExportManifest(Guid id, HttpContext c, IObjectStorage objects, CancellationToken ct) => await Download(objects, Tenant(c), id, "manifest", "application/json", ct);
    static async Task<IResult> ExportContent(Guid id, HttpContext c, IObjectStorage objects, CancellationToken ct) => await Download(objects, Tenant(c), id, "content", "application/octet-stream", ct);
    static string ExportObjectId(Guid id, string suffix) => AdministrationSafety.StableId("administrative-audit-export", id.ToString("D"), suffix).ToString("D");
    static async Task Upload(IObjectStorage objects, string tenant, Guid id, string suffix, byte[] bytes, string media, CancellationToken ct) { var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); await using var stream = new MemoryStream(bytes, false); await objects.UploadAsync(tenant, ExportObjectId(id, suffix), stream, media, hash, ct); }
    static async Task<IResult> Download(IObjectStorage objects, string tenant, Guid id, string suffix, string media, CancellationToken ct) { var key = ExportObjectId(id, suffix); if (await objects.HeadAsync(tenant, key, ct) is not { } metadata) return Results.NotFound(); return Results.Stream(await objects.DownloadAsync(tenant, key, ct), metadata.MediaType ?? media); }
    static string Csv(string value) { var x = value; if (x.Length > 0 && "=+-@\t\r".Contains(x[0])) x = "'" + x; return '"' + x.Replace("\"", "\"\"") + '"'; }
    static async Task<int> ValidateScope(string tenant, ConfigurationScope scope, Guid? id, IEndpointRepository endpoints, IFleetUpdateRepository fleet, CancellationToken ct)
    {
        if (scope == ConfigurationScope.Tenant && id is null) return (await endpoints.ListEndpointsAsync(tenant, 500, null, null, null, ct)).Items.Count;
        if (scope == ConfigurationScope.Endpoint && id is { } endpoint && await endpoints.GetEndpointAsync(tenant, endpoint, ct) is not null) return 1;
        if (scope == ConfigurationScope.EndpointGroup && id is { } group) { var match = (await fleet.GroupsAsync(tenant, ct)).SingleOrDefault(x => x.GroupId == group); if (match is not null) return match.ExplicitMembers.Length; }
        throw new EnrollmentConflictException("CONFIGURATION_SCOPE_REFERENCE_INVALID", "Configuration scope reference is missing, malformed, or outside the tenant.");
    }
}

sealed record RequiredPermissionMetadata(string Permission);
