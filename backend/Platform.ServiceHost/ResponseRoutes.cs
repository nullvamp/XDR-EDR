using System.Security.Cryptography;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;
using OpenSecurityPlatform.Infrastructure;

static class ResponseRoutes
{
    sealed record ArtifactUrlRequest(int ExpiresInSeconds = 300);
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail) => Results.Problem(statusCode: 400, title: code, detail: detail, extensions: new Dictionary<string, object?> { { "code", code }, { "traceId", c.TraceIdentifier } });
    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/response-actions/definitions", Definitions).RequirePermission("response:read");
        app.MapGet("/api/v1/response-actions", Search).RequirePermission("response:read");
        app.MapGet("/api/v1/response-actions/{id:guid}", Get).RequirePermission("response:read");
        app.MapGet("/api/v1/response-actions/{id:guid}/history", History).RequirePermission("response:audit:read");
        app.MapGet("/api/v1/response-actions/{id:guid}/result", Result).RequirePermission("response:output:read");
        app.MapPost("/api/v1/response-actions", Create).RequirePermission("response:request:safe");
        app.MapPost("/api/v1/response-actions/{id:guid}:approve", Approve).RequirePermission("response:approve:elevated");
        app.MapPost("/api/v1/response-actions/{id:guid}:reject", Reject).RequirePermission("response:approve:elevated");
        app.MapPost("/api/v1/response-actions/{id:guid}:cancel", Cancel).RequirePermission("response:cancel");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/response-actions", EndpointHistory).RequirePermission("response:read");
        app.MapGet("/api/v1/response-actions/{actionId:guid}/artifacts/{artifactId:guid}", ArtifactMetadata).RequirePermission("response:artifact:download");
        app.MapGet("/api/v1/response-actions/{actionId:guid}/artifacts/{artifactId:guid}/content", ArtifactContent).RequirePermission("response:artifact:download");
        app.MapPost("/api/v1/response-actions/{actionId:guid}/artifacts/{artifactId:guid}:url", ArtifactUrl).RequirePermission("response:artifact:download");
        app.MapGet("/api/v1/response-artifacts/{artifactId:guid}/download", SignedArtifact);
        app.MapGet("/api/v1/response-health", Health).RequirePermission("response:audit:read");
        app.MapGet("/agent/v1/response-actions", Pending).RequirePermission("agent:heartbeat");
        app.MapGet("/agent/v1/response-actions/cancellations", Cancellations).RequirePermission("agent:heartbeat");
        app.MapPost("/agent/v1/response-actions/{id:guid}:transition", AgentTransition).RequirePermission("agent:heartbeat");
        app.MapPost("/agent/v1/response-actions/{id:guid}:result", AgentResult).RequirePermission("agent:heartbeat");
    }
    static IResult Definitions(HttpContext c) => Ok(c, ResponseSafety.Definitions.Values.OrderBy(x => x.ActionType));
    static async Task<IResult> Search(HttpContext c, IResponseActionRepository r, CancellationToken ct) { var q = c.Request.Query; return Ok(c, await r.SearchAsync(Tenant(c), Guid.TryParse(q["endpointId"], out var endpoint) ? endpoint : null, Enum.TryParse<ResponseActionState>(q["state"], true, out var state) ? state : null, int.TryParse(q["pageSize"], out var size) ? size : 100, q["cursor"], ct)); }
    static async Task<IResult> Get(Guid id, HttpContext c, IResponseActionRepository r, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> History(Guid id, HttpContext c, IResponseActionRepository r, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { } x ? Ok(c, x.AuditHistory) : Results.NotFound();
    static async Task<IResult> Result(Guid id, HttpContext c, IResponseActionRepository r, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { Result: { } result } ? Ok(c, result) : Results.NotFound();
    static async Task<IResult> Create(ResponseActionCreate input, HttpContext c, IResponseActionRepository r, IAlertIncidentRepository triage, CancellationToken ct)
    {
        if (IsolationSafety.IsIsolationAction(input.ActionType)) return Problem(c, "ISOLATION_ROUTE_REQUIRED", "Containment actions must use the policy-bound isolation API.");
        if (ProcessResponseSafety.IsProcessAction(input.ActionType)) return Problem(c, "PROCESS_RESPONSE_ROUTE_REQUIRED", "Process actions must use the stable-identity process-response API.");
        if (FileResponseSafety.IsFileResponseAction(input.ActionType)) return Problem(c, "FILE_RESPONSE_ROUTE_REQUIRED", "File actions must use the authoritative file-response API.");
        if (PersistenceResponseSafety.IsAction(input.ActionType)) return Problem(c, "PERSISTENCE_RESPONSE_ROUTE_REQUIRED", "Persistence actions must use the authoritative persistence-remediation API.");
        if (input.ActionType == ForensicCollectionSafety.ActionType) return Problem(c, "FORENSIC_COLLECTION_ROUTE_REQUIRED", "Forensic collection must use the profile-bound collection API.");
        var tenant = Tenant(c); var definition = ResponseSafety.GetDefinition(input.ActionType, input.ActionVersion); var permissions = (IReadOnlySet<string>)c.Items["permissions"]!; if (!permissions.Contains("platform:admin") && !permissions.Contains(definition.RequiredPermission)) return Results.Forbid(); var target = await r.ResolveTargetAsync(tenant, input.EndpointId, ct); if (target is null) return Results.NotFound(); if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) return Problem(c, "RESPONSE_ENDPOINT_DISABLED", "Disabled or revoked endpoint cannot receive actions."); if (!definition.SupportedPlatforms.Contains(target.Platform, StringComparer.OrdinalIgnoreCase)) return Problem(c, "RESPONSE_PLATFORM_UNSUPPORTED", "Action is unsupported on the target platform."); if (input.SourceAlertId is { } alert && await triage.GetAlertAsync(tenant, alert, ct) is null) return Problem(c, "RESPONSE_ALERT_CONTEXT", "Source alert is unavailable in this tenant."); if (input.SourceIncidentId is { } incident && await triage.GetIncidentAsync(tenant, incident, ct) is null) return Problem(c, "RESPONSE_INCIDENT_CONTEXT", "Source incident is unavailable in this tenant."); var value = await r.CreateAsync(new(tenant, target.EndpointId, target.AgentId, target.AgentInstallationId, Actor(c), input), ct); return Results.Created($"/api/v1/response-actions/{value.ResponseActionId:D}", new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    }
    static async Task<IResult> Approve(Guid id, ResponseApprovalRequest input, HttpContext c, IResponseActionRepository r, CancellationToken ct) => Ok(c, await r.ApproveAsync(Tenant(c), id, Actor(c), input, ct));
    static async Task<IResult> Reject(Guid id, ResponseRejectRequest input, HttpContext c, IResponseActionRepository r, CancellationToken ct) => Ok(c, await r.RejectAsync(Tenant(c), id, Actor(c), input, ct));
    static async Task<IResult> Cancel(Guid id, ResponseCancelRequest input, HttpContext c, IResponseActionRepository r, CancellationToken ct) => Ok(c, await r.CancelAsync(Tenant(c), id, Actor(c), input, ct));
    static async Task<IResult> EndpointHistory(Guid endpoint, HttpContext c, IResponseActionRepository r, CancellationToken ct) => Ok(c, await r.SearchAsync(Tenant(c), endpoint, null, 100, null, ct));
    static bool Agent(HttpContext c, out PrincipalContext principal, out Guid endpoint, out Guid agent) { endpoint = Guid.Empty; agent = Guid.Empty; principal = (PrincipalContext?)c.Items["principal"] ?? new("", "", new HashSet<string>(), ""); var ids = principal.Subject.Split(':'); return principal.Type == "agent" && ids.Length == 2 && Guid.TryParse(ids[0], out endpoint) && Guid.TryParse(ids[1], out agent); }
    static async Task<IResult> Pending(HttpContext c, IResponseActionRepository r, IServiceProvider services, CancellationToken ct) { if (!Agent(c, out var p, out var endpoint, out var agent)) return Results.Unauthorized(); var signer = services.GetService<CertificateAuthority>(); if (signer is null) return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); var installation = c.Request.Headers["X-Agent-Installation-Id"].FirstOrDefault(); if (string.IsNullOrWhiteSpace(installation)) return Results.Unauthorized(); var values = await r.DeliverAsync(p.TenantId, endpoint, agent, installation, ct); return Ok(c, values.Select(signer.SignResponseAction).ToArray()); }
    static async Task<IResult> Cancellations(HttpContext c, IResponseActionRepository r, CancellationToken ct) { if (!Agent(c, out var p, out var endpoint, out var agent)) return Results.Unauthorized(); var installation = c.Request.Headers["X-Agent-Installation-Id"].FirstOrDefault(); if (string.IsNullOrWhiteSpace(installation)) return Results.Unauthorized(); return Ok(c, await r.ListCancellationsAsync(p.TenantId, endpoint, agent, installation, ct)); }
    static async Task<IResult> AgentTransition(Guid id, ResponseAgentTransition input, HttpContext c, IResponseActionRepository r, CancellationToken ct) { if (id != input.ActionId || !Agent(c, out var p, out var endpoint, out var agent)) return Results.Unauthorized(); return Ok(c, await r.AgentTransitionAsync(p.TenantId, endpoint, agent, input, ct)); }
    static async Task<IResult> AgentResult(Guid id, ResponseAgentResultUpload input, HttpContext c,
        IResponseActionRepository r, IIsolationRepository isolation, IObjectStorage storage,
        ArtifactTransferStore transfers, CancellationToken ct)
    {
        if (id != input.Result.ActionId || !Agent(c, out var p, out var endpoint, out var agent)) return Results.Unauthorized();
        var installation = c.Request.Headers["X-Agent-Installation-Id"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(installation)) return Results.Unauthorized();
        var definition = ResponseSafety.GetDefinition(input.Result.ActionType, input.Result.ActionVersion);
        if (input.Artifacts.Length > definition.OutputBounds.MaximumArtifacts) return Problem(c, "RESPONSE_ARTIFACT_BOUNDS", "Too many artifacts.");
        var artifacts = new List<ResponseArtifact>(); long totalArtifactBytes = 0;
        foreach (var upload in input.Artifacts)
        {
            string objectId; long size;
            if (upload.TransferId is { } transferId)
            {
                var transfer = await transfers.AgentStatusAsync(p.TenantId, endpoint, agent, installation, transferId, ct);
                if (transfer.State != ArtifactTransferState.Completed || transfer.OwnerType != "response-action" ||
                    transfer.OwnerId != id || transfer.ArtifactId != upload.ArtifactId || transfer.Size != upload.Size ||
                    !string.Equals(transfer.Sha256, upload.Sha256, StringComparison.OrdinalIgnoreCase) || transfer.ObjectId is null)
                    return Problem(c, "RESPONSE_ARTIFACT_TRANSFER_BINDING", "Completed artifact transfer is not bound to this action result.");
                objectId = transfer.ObjectId; size = transfer.Size;
            }
            else
            {
                byte[] bytes; try { bytes = Convert.FromBase64String(upload.ContentBase64 ?? ""); }
                catch (FormatException) { return Problem(c, "RESPONSE_ARTIFACT_ENCODING", "Artifact encoding is invalid."); }
                size = bytes.LongLength; objectId = Guid.NewGuid().ToString("D");
                if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), upload.Sha256, StringComparison.OrdinalIgnoreCase))
                    return Problem(c, "RESPONSE_ARTIFACT_INTEGRITY", "Artifact hash is invalid.");
                await using var stream = new MemoryStream(bytes, false);
                await storage.UploadAsync(p.TenantId, objectId, stream, upload.MediaType, upload.Sha256, ct);
            }
            totalArtifactBytes += size;
            var forensicLimit = input.Result.ActionType == ForensicCollectionSafety.ActionType && !string.Equals(upload.Name, "forensic-collection-manifest.json", StringComparison.Ordinal) ? ForensicCollectionSafety.MaximumSingleArtifactBytes : definition.OutputBounds.MaximumArtifactBytes;
            if (size > forensicLimit || totalArtifactBytes > definition.OutputBounds.MaximumArtifactBytes)
                return Problem(c, "RESPONSE_ARTIFACT_INTEGRITY", "Artifact size or total quota is invalid.");
            var manifestId = InvestigationSafety.StableId("response-artifact-manifest", objectId);
            var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "response-artifact-manifest.v2", tenantBinding = p.TenantId, actionId = id, upload.ArtifactId, objectId, upload.Name, upload.MediaType, size, upload.Sha256, transferId = upload.TransferId, transport = upload.TransferId is null ? "legacy-base64" : ArtifactTransferSafety.SchemaVersion, createdAt = DateTimeOffset.UtcNow });
            var manifestHash = Convert.ToHexString(SHA256.HashData(manifest)).ToLowerInvariant();
            await using (var stream = new MemoryStream(manifest, false)) await storage.UploadAsync(p.TenantId, manifestId.ToString("D"), stream, "application/json", manifestHash, ct);
            artifacts.Add(new(upload.ArtifactId, upload.Name, upload.MediaType, size, upload.Sha256, objectId, manifestId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(7)));
        }
        var completed = await r.CompleteAsync(p.TenantId, endpoint, agent, input, artifacts.ToArray(), ct);
        await isolation.RecordResultAsync(completed, ct); return Ok(c, completed);
    }
    static async Task<(ResponseActionRecord Action, ResponseArtifact Artifact)?> FindArtifact(string tenant, Guid actionId, Guid artifactId, IResponseActionRepository r, CancellationToken ct) { var action = await r.GetAsync(tenant, actionId, ct); var artifact = action?.Result?.Artifacts.FirstOrDefault(x => x.ArtifactId == artifactId && x.ExpiresAt > DateTimeOffset.UtcNow); return action is null || artifact is null ? null : (action, artifact); }
    static async Task<IResult> ArtifactMetadata(Guid actionId, Guid artifactId, HttpContext c, IResponseActionRepository r, CancellationToken ct) => await FindArtifact(Tenant(c), actionId, artifactId, r, ct) is { } x ? Ok(c, x.Artifact) : Results.NotFound();
    static async Task<IResult> ArtifactContent(Guid actionId, Guid artifactId, HttpContext c, IResponseActionRepository r, IObjectStorage s, CancellationToken ct) { var x = await FindArtifact(Tenant(c), actionId, artifactId, r, ct); if (x is null) return Results.NotFound(); await r.RecordArtifactDownloadAsync(Tenant(c), actionId, artifactId, Actor(c), ct); return Results.Stream(await s.DownloadAsync(Tenant(c), x.Value.Artifact.ObjectId, ct), x.Value.Artifact.MediaType); }
    static async Task<IResult> ArtifactUrl(Guid actionId, Guid artifactId, ArtifactUrlRequest input, HttpContext c, IResponseActionRepository r, PlatformOptions o, CancellationToken ct) { if (await FindArtifact(Tenant(c), actionId, artifactId, r, ct) is null) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(input.ExpiresInSeconds, 5, 300)); return Ok(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/response-artifacts/{artifactId:D}/download?token={Uri.EscapeDataString(FileExportDownloadToken.Create(Tenant(c), artifactId, expires, o.JwtSigningKey))}", expiresAt = expires, actionId }); }
    static async Task<IResult> SignedArtifact(Guid artifactId, string token, IResponseActionRepository r, IObjectStorage s, PlatformOptions o, CancellationToken ct) { if (!FileExportDownloadToken.TryValidate(token, o.JwtSigningKey, out var tenant, out var target) || target != artifactId) return Results.NotFound(); var page = await r.SearchAsync(tenant, null, null, 200, null, ct); var action = page.Items.FirstOrDefault(x => x.Result?.Artifacts.Any(a => a.ArtifactId == artifactId && a.ExpiresAt > DateTimeOffset.UtcNow) == true); var artifact = action?.Result?.Artifacts.FirstOrDefault(a => a.ArtifactId == artifactId && a.ExpiresAt > DateTimeOffset.UtcNow); if (action is null || artifact is null) return Results.NotFound(); await r.RecordArtifactDownloadAsync(tenant, action.ResponseActionId, artifactId, "signed-url", ct); return Results.Stream(await s.DownloadAsync(tenant, artifact.ObjectId, ct), artifact.MediaType); }
    static async Task<IResult> Health(HttpContext c, IResponseActionRepository r, CancellationToken ct) => Ok(c, await r.HealthAsync(Tenant(c), ct));
}
