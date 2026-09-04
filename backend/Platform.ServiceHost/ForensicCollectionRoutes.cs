using System.Security.Cryptography;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;
using OpenSecurityPlatform.Infrastructure;

static class ForensicCollectionRoutes
{
    sealed record ArtifactUrlRequest(int ExpiresInSeconds = 300);
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IReadOnlySet<string> Permissions(HttpContext c) => (IReadOnlySet<string>)c.Items["permissions"]!;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail, int status = 400) => Results.Problem(statusCode: status, title: code, detail: detail, extensions: new Dictionary<string, object?> { { "code", code }, { "traceId", c.TraceIdentifier } });

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/forensic-collection-profiles", Profiles).RequirePermission("forensics:profiles:read");
        app.MapPost("/api/v1/forensic-collections:preview", Preview).RequirePermission("forensics:request:quick");
        app.MapPost("/api/v1/forensic-collections", Create).RequirePermission("forensics:request:quick");
        app.MapGet("/api/v1/forensic-collections", Search).RequirePermission("forensics:read");
        app.MapGet("/api/v1/forensic-collections/{id:guid}", Get).RequirePermission("forensics:read");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/forensic-collections", EndpointHistory).RequirePermission("forensics:read");
        app.MapPost("/api/v1/forensic-collections/{id:guid}:approve", Approve).RequirePermission("forensics:approve:sensitive");
        app.MapPost("/api/v1/forensic-collections/{id:guid}:cancel", Cancel).RequirePermission("forensics:cancel");
        app.MapGet("/api/v1/forensic-collections/{id:guid}/manifest", Manifest).RequirePermission("forensics:manifest:export");
        app.MapGet("/api/v1/forensic-collections/{id:guid}/custody", Custody).RequirePermission("forensics:custody:read");
        app.MapGet("/api/v1/forensic-collections/{id:guid}/items", Items).RequirePermission("forensics:read");
        app.MapGet("/api/v1/forensic-collections/{id:guid}/items/{itemId:guid}", Item).RequirePermission("forensics:read");
        app.MapGet("/api/v1/forensic-collections/{id:guid}/items/{itemId:guid}/content", Content).RequirePermission("forensics:evidence:download:sensitive");
        app.MapPost("/api/v1/forensic-collections/{id:guid}/items/{itemId:guid}:url", Url).RequirePermission("forensics:evidence:download:sensitive");
        app.MapGet("/api/v1/forensic-evidence/{artifactId:guid}/download", SignedContent);
        app.MapGet("/api/v1/forensic-collection-health", Health).RequirePermission("forensics:health:read");
    }

    static IResult Profiles(HttpContext c) => Ok(c, ForensicCollectionSafety.Profiles.Values.OrderBy(x => x.ProfileId));

    static async Task<IResult> Preview(ForensicCollectionRequest input, HttpContext c, IResponseActionRepository repository, IFileTelemetryRepository files, IAlertIncidentRepository triage, CancellationToken ct)
    {
        var resolved = await Resolve(input, c, repository, files, triage, ct); if (resolved.Error is not null) return resolved.Error;
        var parameters = ForensicCollectionSafety.ActionParameters(Guid.NewGuid(), Actor(c), input, resolved.Profile!);
        var warnings = input.RequestedArtifacts.SelectMany(x => x.ArtifactType switch
        {
            ForensicArtifactType.Registry => ["Registry content is metadata-only and value data is redacted."],
            ForensicArtifactType.File or ForensicArtifactType.Directory => ["Files changed during acquisition are retained only with explicit unstable classification."],
            ForensicArtifactType.WindowsEventLog => ["The exact approved channel and bounded record/time window will be exported without clearing the log."],
            _ => Array.Empty<string>()
        }).Distinct().ToArray();
        return Ok(c, new ForensicCollectionPreview(ForensicCollectionSafety.SchemaVersion, input.EndpointId,
            resolved.Target!.AgentInstallationId, resolved.Profile!, input.RequestedArtifacts, resolved.Profile!.MaximumItems,
            resolved.Profile.MaximumBytes, resolved.Profile.MaximumRuntimeSeconds, resolved.ApprovalRequired,
            warnings, ResponseSafety.ParameterHash(parameters), DateTimeOffset.UtcNow));
    }

    static async Task<IResult> Create(ForensicCollectionRequest input, HttpContext c, IResponseActionRepository repository, IFileTelemetryRepository files, IAlertIncidentRepository triage, CancellationToken ct)
    {
        var resolved = await Resolve(input, c, repository, files, triage, ct); if (resolved.Error is not null) return resolved.Error;
        var tenant = Tenant(c); var active = (await repository.SearchAsync(tenant, null, null, 200, null, ct)).Items.Where(IsCollection).Where(x => !ResponseSafety.IsTerminal(x.State)).ToArray();
        if (active.Count(x => x.EndpointId == input.EndpointId) >= ForensicCollectionSafety.MaximumConcurrentJobsPerEndpoint || active.Length >= ForensicCollectionSafety.MaximumConcurrentJobsPerTenant) return Problem(c, "FORENSIC_CONCURRENCY_QUOTA", "Concurrent collection quota reached.", 409);
        var collectionId = Guid.NewGuid(); var parameters = ForensicCollectionSafety.ActionParameters(collectionId, Actor(c), input, resolved.Profile!);
        var create = new ResponseActionCreate(input.EndpointId, ForensicCollectionSafety.ActionType, 1, parameters,
            resolved.Profile!.MaximumRuntimeSeconds, input.ExpiresInSeconds, collectionId.ToString("D"), input.SourceAlertId,
            input.SourceIncidentId, input.SourceEntityId, input.SaveAsDraft, input.PolicyVersion, resolved.ApprovalRequired);
        var action = await repository.CreateAsync(new(tenant, resolved.Target!.EndpointId, resolved.Target.AgentId,
            resolved.Target.AgentInstallationId, Actor(c), create), ct);
        return Results.Created($"/api/v1/forensic-collections/{collectionId:D}", new ApiEnvelope<object>(View(action), new(c.TraceIdentifier, "1.0")));
    }

    static async Task<IResult> Approve(Guid id, ResponseApprovalRequest input, HttpContext c, IResponseActionRepository repository, CancellationToken ct)
    {
        var action = await Find(Tenant(c), id, repository, ct); if (action is null) return Results.NotFound();
        return Ok(c, View(await repository.ApproveAsync(Tenant(c), action.ResponseActionId, Actor(c), input, ct)));
    }

    static async Task<IResult> Cancel(Guid id, ResponseCancelRequest input, HttpContext c, IResponseActionRepository repository, CancellationToken ct)
    {
        var action = await Find(Tenant(c), id, repository, ct); if (action is null) return Results.NotFound();
        return Ok(c, View(await repository.CancelAsync(Tenant(c), action.ResponseActionId, Actor(c), input, ct)));
    }

    static async Task<IResult> Search(HttpContext c, IResponseActionRepository repository, CancellationToken ct)
    {
        var q = c.Request.Query; var page = await repository.SearchAsync(Tenant(c), Guid.TryParse(q["endpointId"], out var endpoint) ? endpoint : null, null, 200, null, ct);
        var items = page.Items.Where(IsCollection).Select(View).ToArray(); return Ok(c, new { items, total = items.Length });
    }

    static async Task<IResult> EndpointHistory(Guid endpoint, HttpContext c, IResponseActionRepository repository, CancellationToken ct)
    {
        var page = await repository.SearchAsync(Tenant(c), endpoint, null, 200, null, ct); var values = page.Items.Where(IsCollection).Select(View).ToArray(); return Ok(c, new { items = values, total = values.Length });
    }

    static async Task<IResult> Get(Guid id, HttpContext c, IResponseActionRepository repository, CancellationToken ct) => await Find(Tenant(c), id, repository, ct) is { } value ? Ok(c, View(value)) : Results.NotFound();
    static async Task<IResult> Items(Guid id, HttpContext c, IResponseActionRepository repository, CancellationToken ct) => await Result(Tenant(c), id, repository, ct) is { } value ? Ok(c, value.Items) : Results.NotFound();
    static async Task<IResult> Item(Guid id, Guid itemId, HttpContext c, IResponseActionRepository repository, CancellationToken ct) => await Result(Tenant(c), id, repository, ct) is { } value && value.Items.FirstOrDefault(x => x.EvidenceItemId == itemId) is { } item ? Ok(c, item) : Results.NotFound();

    static async Task<IResult> Manifest(Guid id, HttpContext c, IResponseActionRepository repository, IObjectStorage storage, CancellationToken ct)
    {
        var found = await FindArtifact(Tenant(c), id, null, repository, true, ct); if (found is null) return Results.NotFound();
        await repository.RecordArtifactDownloadAsync(Tenant(c), found.Value.Action.ResponseActionId, found.Value.Artifact.ArtifactId, Actor(c), ct);
        return Results.Stream(await storage.DownloadAsync(Tenant(c), found.Value.Artifact.ObjectId, ct), "application/json");
    }

    static async Task<IResult> Custody(Guid id, HttpContext c, IResponseActionRepository repository, CancellationToken ct)
    {
        var action = await Find(Tenant(c), id, repository, ct); if (action is null) return Results.NotFound();
        var events = action.AuditHistory.Select(x => new ForensicCustodyEvent(x.AuditId, id, x.Action, x.Actor,
            x.OccurredAt, Hash(JsonSerializer.SerializeToUtf8Bytes(new { x.AuditId, collectionId = id, x.Action, x.Actor, x.OccurredAt, x.ParameterHash }, Json)),
            x.Reason)).ToArray(); return Ok(c, new { schemaVersion = "technical-chain-of-custody.v1", legalAdmissibilityClaimed = false, events });
    }

    static async Task<IResult> Content(Guid id, Guid itemId, HttpContext c, IResponseActionRepository repository, IObjectStorage storage, CancellationToken ct)
    {
        var found = await FindArtifact(Tenant(c), id, itemId, repository, false, ct); if (found is null) return Results.NotFound();
        await repository.RecordArtifactDownloadAsync(Tenant(c), found.Value.Action.ResponseActionId, found.Value.Artifact.ArtifactId, Actor(c), ct);
        return Results.Stream(await storage.DownloadAsync(Tenant(c), found.Value.Artifact.ObjectId, ct), found.Value.Artifact.MediaType);
    }

    static async Task<IResult> Url(Guid id, Guid itemId, ArtifactUrlRequest input, HttpContext c, IResponseActionRepository repository, PlatformOptions options, CancellationToken ct)
    {
        var found = await FindArtifact(Tenant(c), id, itemId, repository, false, ct); if (found is null) return Results.NotFound();
        var expires = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(input.ExpiresInSeconds, 5, 300));
        var token = FileExportDownloadToken.Create(Tenant(c), found.Value.Artifact.ArtifactId, expires, options.JwtSigningKey);
        return Ok(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/forensic-evidence/{found.Value.Artifact.ArtifactId:D}/download?token={Uri.EscapeDataString(token)}", expiresAt = expires, collectionId = id, itemId });
    }

    static async Task<IResult> SignedContent(Guid artifactId, string token, IResponseActionRepository repository, IObjectStorage storage, PlatformOptions options, CancellationToken ct)
    {
        if (!FileExportDownloadToken.TryValidate(token, options.JwtSigningKey, out var tenant, out var target) || target != artifactId) return Results.NotFound();
        var page = await repository.SearchAsync(tenant, null, null, 200, null, ct); var action = page.Items.Where(IsCollection).FirstOrDefault(x => x.Result?.Artifacts.Any(a => a.ArtifactId == artifactId && a.ExpiresAt > DateTimeOffset.UtcNow) == true); var artifact = action?.Result?.Artifacts.FirstOrDefault(x => x.ArtifactId == artifactId && x.ExpiresAt > DateTimeOffset.UtcNow); if (action is null || artifact is null) return Results.NotFound();
        await repository.RecordArtifactDownloadAsync(tenant, action.ResponseActionId, artifactId, "signed-exact-object-url", ct); return Results.Stream(await storage.DownloadAsync(tenant, artifact.ObjectId, ct), artifact.MediaType);
    }

    static async Task<IResult> Health(HttpContext c, IResponseActionRepository repository, CancellationToken ct)
    {
        var page = await repository.SearchAsync(Tenant(c), null, null, 200, null, ct); var jobs = page.Items.Where(IsCollection).ToArray(); var results = jobs.Select(ParseResult).Where(x => x is not null).Cast<ForensicCollectionResult>().ToArray();
        var completed = jobs.Where(x => x.StartedAt is not null && x.CompletedAt is not null).ToArray();
        return Ok(c, new { schemaVersion = "forensic-collection-health.v1", requests = jobs.Length, running = jobs.Count(x => x.State == ResponseActionState.Running), successful = results.Count(x => x.State == ForensicCollectionState.Succeeded), partial = results.Count(x => x.State == ForensicCollectionState.Partial), failed = results.Count(x => x.State == ForensicCollectionState.Failed), cancelled = results.Count(x => x.State is ForensicCollectionState.Cancelled or ForensicCollectionState.CancelledWithEvidence), expired = jobs.Count(x => x.State == ResponseActionState.Expired), itemsAcquired = results.Sum(x => x.CollectedItems), unstableItems = results.Sum(x => x.UnstableItems), hashFailures = results.Sum(x => x.Items.Count(i => i.FailureReason == "HashMismatch")), quotaRejections = results.Sum(x => x.Items.Count(i => i.FailureReason?.Contains("Quota", StringComparison.Ordinal) == true)), uploadFailures = jobs.Count(x => x.Result?.FailureReason?.Contains("upload", StringComparison.OrdinalIgnoreCase) == true), collectionLatencyMilliseconds = completed.Length == 0 ? 0 : completed.Average(x => (x.CompletedAt!.Value - x.StartedAt!.Value).TotalMilliseconds), bytesCollected = results.Sum(x => x.BytesCollected), metricLabelsContainSensitiveDimensions = false, updatedAt = DateTimeOffset.UtcNow });
    }

    static async Task<(ResponseTarget? Target, ForensicCollectionProfile? Profile, bool ApprovalRequired, IResult? Error)> Resolve(ForensicCollectionRequest input, HttpContext c, IResponseActionRepository repository, IFileTelemetryRepository files, IAlertIncidentRepository triage, CancellationToken ct)
    {
        try { ForensicCollectionSafety.ValidateRequest(input); } catch (EnrollmentConflictException ex) { return (null, null, false, Problem(c, ex.Code, ex.Message)); }
        var tenant = Tenant(c); var target = await repository.ResolveTargetAsync(tenant, input.EndpointId, ct); if (target is null) return (null, null, false, Results.NotFound()); if (!target.Platform.Equals("windows", StringComparison.OrdinalIgnoreCase)) return (null, null, false, Problem(c, "FORENSIC_PLATFORM", "The selected profile requires a Windows endpoint.")); if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) return (null, null, false, Problem(c, "FORENSIC_ENDPOINT_DISABLED", "Disabled or revoked endpoints cannot receive collections."));
        if (input.SourceAlertId is { } alert && await triage.GetAlertAsync(tenant, alert, ct) is null) return (null, null, false, Problem(c, "FORENSIC_ALERT_CONTEXT", "Source alert is unavailable in this tenant."));
        if (input.SourceIncidentId is { } incident && await triage.GetIncidentAsync(tenant, incident, ct) is null) return (null, null, false, Problem(c, "FORENSIC_INCIDENT_CONTEXT", "Source incident is unavailable in this tenant."));
        foreach (var requested in input.RequestedArtifacts.Where(x => x.ArtifactType == ForensicArtifactType.File))
        {
            var supplied = requested.FileTarget!; var authoritative = await files.GetAsync(tenant, input.EndpointId, supplied.FileEntityId, ct);
            if (authoritative is null || authoritative.State == FileEntityState.Deleted || authoritative.Metadata.Size is not { } size ||
                authoritative.NativeIdentity != supplied.NativeIdentity || size != supplied.ExpectedSize ||
                !string.Equals(authoritative.CurrentPath, supplied.CanonicalPath, StringComparison.OrdinalIgnoreCase) ||
                (supplied.ExpectedSha256 is not null && !string.Equals(authoritative.Hash.Sha256, supplied.ExpectedSha256, StringComparison.OrdinalIgnoreCase)))
                return (null, null, false, Problem(c, "FORENSIC_FILE_AUTHORITY", "File evidence must match the current tenant-bound authoritative file entity, native identity, path, size, and optional hash.", 409));
        }
        var profile = ForensicCollectionSafety.Profiles[input.ProfileId]; var permissions = Permissions(c); foreach (var artifact in input.RequestedArtifacts) { var required = Permission(artifact.ArtifactType); if (!permissions.Contains("platform:admin") && !permissions.Contains(required)) return (null, null, false, Results.Forbid()); }
        var sensitive = profile.Sensitivity == ForensicSensitivity.High || input.RequestedArtifacts.Any(x => x.ArtifactType is ForensicArtifactType.Registry or ForensicArtifactType.File or ForensicArtifactType.Directory or ForensicArtifactType.WindowsEventLog);
        return (target, profile, profile.ApprovalRequired || sensitive, null);
    }

    static string Permission(ForensicArtifactType type) => type switch { ForensicArtifactType.WindowsEventLog => "forensics:request:eventlog", ForensicArtifactType.Registry => "forensics:request:registry", ForensicArtifactType.File or ForensicArtifactType.Directory => "forensics:request:file", _ => "forensics:request:quick" };

    internal static async Task<IResult> FromLive(string operation, string argument, LiveSessionRecord session,
        int timeoutSeconds, HttpContext c, IFileTelemetryRepository files, IResponseActionRepository repository,
        IAlertIncidentRepository triage, CancellationToken ct)
    {
        if (operation == "collection-status") return await Get(Guid.Parse(argument), c, repository, ct);
        if (operation == "cancel-collection") return await Cancel(Guid.Parse(argument), new ResponseCancelRequest($"Live Response cancellation from session {session.SessionId:D}"), c, repository, ct);
        string profile; ForensicArtifactRequest[] requested;
        switch (operation)
        {
            case "triage":
                profile = "quick-triage";
                requested =
                [
                    new("system", ForensicArtifactType.SystemInformation, MaximumBytes: 256 * 1024),
                    new("processes", ForensicArtifactType.ProcessInventory, MaximumItems: 32, MaximumBytes: 512 * 1024),
                    new("users", ForensicArtifactType.UserSessionInventory, MaximumItems: 32, MaximumBytes: 256 * 1024),
                    new("services", ForensicArtifactType.ServiceInventory, MaximumItems: 32, MaximumBytes: 512 * 1024),
                    new("tasks", ForensicArtifactType.ScheduledTaskInventory, MaximumItems: 32, MaximumBytes: 512 * 1024),
                    new("network", ForensicArtifactType.NetworkState, MaximumItems: 32, MaximumBytes: 512 * 1024),
                    new("persistence", ForensicArtifactType.PersistenceSnapshot, MaximumItems: 32, MaximumBytes: 512 * 1024)
                ];
                break;
            case "collect-file":
                profile = "file-evidence"; var file = await files.GetAsync(Tenant(c), session.EndpointId, argument, ct); if (file is null || file.State == FileEntityState.Deleted || file.Metadata.Size is not { } size) return Results.NotFound();
                requested = [new("file", ForensicArtifactType.File, FileTarget: new(file.FileEntityId, file.NativeIdentity, file.CurrentPath, size, file.Hash.Sha256, file.LastObserved), MaximumBytes: Math.Min(size, ForensicCollectionSafety.MaximumSingleArtifactBytes))];
                break;
            case "collect-eventlog":
                profile = "windows-event-evidence"; requested = [new("eventlog", ForensicArtifactType.WindowsEventLog, Source: argument, MaximumBytes: 4 * 1024 * 1024, MaximumRecords: 1_000, LookbackMinutes: 60)]; break;
            case "collect-registry":
                profile = "registry-triage"; requested = [new("registry", ForensicArtifactType.Registry, Source: argument, MaximumDepth: 2, MaximumItems: 32, MaximumBytes: 1024 * 1024, MetadataOnly: true)]; break;
            default: return Problem(c, "LIVE_FORENSIC_COMMAND", "Unknown structured collection operation.");
        }
        var request = new ForensicCollectionRequest(session.EndpointId, profile, 1, requested,
            $"Live Response structured collection from session {session.SessionId:D}", Math.Clamp(timeoutSeconds + 120, 180, 3600),
            session.SourceAlertId, session.SourceIncidentId, session.SourceEntityId, false, ForensicCollectionSafety.PolicyVersion);
        return await Create(request, c, repository, files, triage, ct);
    }

    static bool IsCollection(ResponseActionRecord value) => value.ActionType == ForensicCollectionSafety.ActionType;
    static Guid CollectionId(ResponseActionRecord value) => value.Parameters.GetProperty("collectionId").GetGuid();
    static object View(ResponseActionRecord value) => new { schemaVersion = ForensicCollectionSafety.SchemaVersion, collectionId = CollectionId(value), actionId = value.ResponseActionId, value.TenantId, value.EndpointId, value.AgentInstallationId, value.AnalystId, profileId = value.Parameters.GetProperty("profileId").GetString(), profileVersion = value.Parameters.GetProperty("profileVersion").GetInt32(), profileHash = value.Parameters.GetProperty("profileHash").GetString(), requestedArtifacts = value.Parameters.GetProperty("requestedArtifacts"), value.ParameterHash, value.ApprovalState, value.ApproverId, state = ParseResult(value)?.State.ToString() ?? value.State.ToString(), value.RequestedAt, value.StartedAt, value.CompletedAt, value.ExpiresAt, value.SourceAlertId, value.SourceIncidentId, value.SourceEntityId, result = ParseResult(value), retentionState = value.Result?.Artifacts.All(x => x.ExpiresAt > DateTimeOffset.UtcNow) != false ? "retained" : "expired", auditCorrelationId = value.CorrelationId };
    static ForensicCollectionResult? ParseResult(ResponseActionRecord value) { try { return value.Result?.StructuredResult.Deserialize<ForensicCollectionResult>(Json); } catch (JsonException) { return null; } }
    static async Task<ResponseActionRecord?> Find(string tenant, Guid collectionId, IResponseActionRepository repository, CancellationToken ct) { var page = await repository.SearchAsync(tenant, null, null, 200, null, ct); return page.Items.Where(IsCollection).FirstOrDefault(x => CollectionId(x) == collectionId); }
    static async Task<ForensicCollectionResult?> Result(string tenant, Guid collectionId, IResponseActionRepository repository, CancellationToken ct) => await Find(tenant, collectionId, repository, ct) is { } action ? ParseResult(action) : null;
    static async Task<(ResponseActionRecord Action, ResponseArtifact Artifact)?> FindArtifact(string tenant, Guid collectionId, Guid? itemId, IResponseActionRepository repository, bool manifest, CancellationToken ct)
    {
        var action = await Find(tenant, collectionId, repository, ct); var result = action is null ? null : ParseResult(action); if (action is null || result is null) return null; Guid? artifactId = manifest ? result.ManifestArtifactId : result.Items.FirstOrDefault(x => x.EvidenceItemId == itemId)?.ArtifactId; var artifact = action.Result?.Artifacts.FirstOrDefault(x => x.ArtifactId == artifactId && x.ExpiresAt > DateTimeOffset.UtcNow); return artifact is null ? null : (action, artifact);
    }
    static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
}
