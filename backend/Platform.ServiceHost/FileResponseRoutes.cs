using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class FileResponseRoutes
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail, int status = 400) => Results.Problem(statusCode: status, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["code"] = code, ["traceId"] = c.TraceIdentifier });

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/files/{entity}/response-preview", Preview).RequirePermission("file-response:read");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/files/{entity}:quarantine", Quarantine).RequirePermission("file-response:quarantine");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/files/{entity}:delete", Delete).RequirePermission("file-response:delete");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/file-response-history", History).RequirePermission("file-response:history:read");
        app.MapGet("/api/v1/quarantines", List).RequirePermission("file-response:read");
        app.MapGet("/api/v1/quarantines/{id:guid}", Get).RequirePermission("file-response:read");
        app.MapPost("/api/v1/quarantines/{id:guid}:restore", Restore).RequirePermission("file-response:restore");
        app.MapPost("/api/v1/file-response-actions/{id:guid}:approve", Approve).RequirePermission("file-response:approve");
        app.MapPost("/api/v1/file-response-actions/{id:guid}:cancel", Cancel).RequirePermission("response:cancel");
        app.MapGet("/api/v1/file-response-health", Health).RequirePermission("file-response:history:read");
    }

    static async Task<IResult> Preview(Guid endpoint, string entity, HttpContext c, IFileTelemetryRepository files, IResponseActionRepository actions, CancellationToken ct)
    {
        var file = await files.GetAsync(Tenant(c), endpoint, entity, ct);
        var destination = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (file is null || destination is null) return Results.NotFound();
        var target = ToTarget(file);
        var protectedPath = IsProtectedWindowsPath(target.CanonicalPath);
        return Ok(c, new FileResponsePreview(FileResponseSafety.SchemaVersion, endpoint, destination.AgentInstallationId,
            "file.quarantine", target, protectedPath, protectedPath ? "operating-system-or-platform-path" : "none",
            file.LatestProcess is null ? 0 : 1, 0, "endpoint-revalidation-required", DateTimeOffset.UtcNow));
    }

    static Task<IResult> Quarantine(Guid endpoint, string entity, FileResponseRequest input, HttpContext c,
        IFileTelemetryRepository files, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) =>
        CreateFile("file.quarantine", endpoint, entity, input, c, files, actions, triage, ct);

    static Task<IResult> Delete(Guid endpoint, string entity, FileResponseRequest input, HttpContext c,
        IFileTelemetryRepository files, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) =>
        CreateFile("file.delete", endpoint, entity, input, c, files, actions, triage, ct);

    internal static async Task<IResult> CreateFile(string type, Guid endpoint, string entity, FileResponseRequest input, HttpContext c,
        IFileTelemetryRepository files, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct)
    {
        var file = await files.GetAsync(Tenant(c), endpoint, entity, ct);
        var destination = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (file is null || destination is null) return Results.NotFound();
        if (file.State == FileEntityState.Deleted || file.DeletedAt is not null) return Problem(c, "FILE_RESPONSE_ALREADY_ABSENT", "The canonical file was already absent before the request was created.", 409);
        if (!await ContextValid(input.SourceAlertId, input.SourceIncidentId, Tenant(c), triage, ct)) return Problem(c, "FILE_RESPONSE_SOURCE_CONTEXT", "Source alert or incident is unavailable in this tenant.");
        var target = ToTarget(file);
        if (IsProtectedWindowsPath(target.CanonicalPath)) return Problem(c, "FILE_RESPONSE_PROTECTED", "Operating-system and platform paths are protected from file response.", 409);
        return await Create(destination, type, FileResponseSafety.TargetParameters(input.Reason, target), input.Reason,
            input.ExpiresInSeconds, input.SourceAlertId, input.SourceIncidentId, input.SourceEntityId ?? entity, c, actions, ct);
    }

    internal static async Task<IResult> Restore(Guid id, FileRestoreRequest input, HttpContext c, IResponseActionRepository actions,
        IAlertIncidentRepository triage, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct);
        var source = page.Items.Where(x => TryRecord(x, out var r) && r.QuarantineId == id).OrderByDescending(x => x.CompletedAt).FirstOrDefault();
        if (source is null || !TryRecord(source, out var record)) return Results.NotFound();
        if (record.State is not (FileQuarantineState.Quarantined or FileQuarantineState.Partial) || !record.RestoreEligible)
            return Problem(c, "FILE_RESPONSE_RESTORE_NOT_ELIGIBLE", "The quarantine record is not eligible for restore.", 409);
        if (!await ContextValid(input.SourceAlertId, input.SourceIncidentId, Tenant(c), triage, ct)) return Problem(c, "FILE_RESPONSE_SOURCE_CONTEXT", "Source alert or incident is unavailable in this tenant.");
        var destination = await actions.ResolveTargetAsync(Tenant(c), source.EndpointId, ct);
        if (destination is null || destination.AgentInstallationId != record.AgentInstallationId) return Problem(c, "FILE_RESPONSE_ENDPOINT_BINDING", "The quarantine record no longer matches the active endpoint installation.", 409);
        var target = new FileResponseTarget(record.FileEntityId, record.OriginalNativeIdentity, record.OriginalPath,
            record.OriginalSize, record.Sha256, record.QuarantinedAt, record.OriginalCreationTime, record.OriginalLastWriteTime);
        if (IsProtectedWindowsPath(target.CanonicalPath)) return Problem(c, "FILE_RESPONSE_PROTECTED", "The original path is protected from restore.", 409);
        return await Create(destination, "file.restore", FileResponseSafety.QuarantineParameters(input.Reason, id, target), input.Reason,
            input.ExpiresInSeconds, input.SourceAlertId, input.SourceIncidentId, input.SourceEntityId ?? record.FileEntityId, c, actions, ct);
    }

    internal static async Task<IResult> CreateRecordAction(Guid id, string type, string reason, HttpContext c,
        IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct);
        var source = page.Items.Where(x => TryRecord(x, out var r) && r.QuarantineId == id)
            .OrderByDescending(x => x.CompletedAt).FirstOrDefault();
        if (source is null || !TryRecord(source, out var record)) return Results.NotFound();
        var destination = await actions.ResolveTargetAsync(Tenant(c), record.EndpointId, ct);
        if (destination is null || destination.AgentInstallationId != record.AgentInstallationId) return Problem(c, "FILE_RESPONSE_ENDPOINT_BINDING", "The quarantine record no longer matches the active endpoint installation.", 409);
        return await Create(destination, type, FileResponseSafety.RecordParameters(reason, id), reason, 300, null, null,
            record.FileEntityId, c, actions, ct);
    }

    static async Task<IResult> Create(ResponseTarget target, string type, JsonElement parameters, string reason, int expires,
        Guid? alert, Guid? incident, string sourceEntity, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        if (!string.Equals(target.Platform, "windows", StringComparison.OrdinalIgnoreCase)) return Problem(c, "FILE_RESPONSE_PLATFORM", "Sprint 20 file response is qualified only for Windows endpoints.");
        if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) return Problem(c, "FILE_RESPONSE_ENDPOINT_DISABLED", "Disabled or revoked endpoints cannot receive file actions.");
        var request = new ResponseActionCreate(target.EndpointId, type, 1, parameters, 180, Math.Clamp(expires, 30, 3600), null,
            alert, incident, sourceEntity, false, FileResponseSafety.PolicyVersion);
        var action = await actions.CreateAsync(new(Tenant(c), target.EndpointId, target.AgentId, target.AgentInstallationId, Actor(c), request), ct);
        return Results.Accepted($"/api/v1/response-actions/{action.ResponseActionId:D}", new ApiEnvelope<object>(new
        {
            action,
            parameterHash = ResponseSafety.ParameterHash(parameters),
            reason,
            restoreOverwrite = false,
            deletionTerminology = type == "file.delete" ? "normal-filesystem-deletion-not-secure-erase" : null
        }, new(c.TraceIdentifier, "1.0")));
    }

    static async Task<IResult> List(Guid? endpointId, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), endpointId, null, 200, null, ct);
        var records = page.Items.Where(x => TryRecord(x, out _)).Select(x => { _ = TryRecord(x, out var record); return new { record, action = x }; })
            .GroupBy(x => x.record.QuarantineId).Select(x => x.OrderByDescending(v => v.action.CompletedAt).First()).ToArray();
        return Ok(c, new { items = records, count = records.Length });
    }

    static async Task<IResult> Get(Guid id, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct);
        var action = page.Items.Where(x => TryRecord(x, out var r) && r.QuarantineId == id).OrderByDescending(x => x.CompletedAt).FirstOrDefault();
        return action is not null && TryRecord(action, out var record) ? Ok(c, new { record, action }) : Results.NotFound();
    }

    static async Task<IResult> History(Guid endpoint, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), endpoint, null, 200, null, ct);
        return Ok(c, page with { Items = page.Items.Where(x => FileResponseSafety.IsFileResponseAction(x.ActionType)).ToArray() });
    }

    static async Task<IResult> Health(HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct);
        var values = page.Items.Where(x => FileResponseSafety.IsFileResponseAction(x.ActionType)).ToArray();
        var records = values.Where(x => TryRecord(x, out _)).Select(x => { _ = TryRecord(x, out var r); return r!; }).ToArray();
        var latencies = values.Where(x => x.Result is not null).Select(x => (x.Result!.CompletedAt - x.Result.StartedAt).TotalMilliseconds).ToArray();
        long Requested(string type) => values.LongCount(x => x.ActionType == type);
        return Ok(c, new
        {
            schemaVersion = "file-response-health.v1",
            quarantineRequests = Requested("file.quarantine"),
            successfulQuarantines = records.LongCount(x => x.State == FileQuarantineState.Quarantined),
            partialResults = records.LongCount(x => x.State == FileQuarantineState.Partial),
            identityOrHashFailures = values.LongCount(x => x.Result?.FailureCategory == ResponseFailureCategory.Integrity),
            hashMismatches = values.LongCount(x => x.Result?.FailureReason == "HashMismatch"),
            lockedFileFailures = values.LongCount(x => x.Result?.FailureReason == "LockedOrAccessDenied"),
            protectedPathRejections = values.LongCount(x => x.Result?.FailureCategory == ResponseFailureCategory.Authorization),
            restoreRequests = Requested("file.restore"),
            successfulRestores = records.LongCount(x => x.State == FileQuarantineState.Restored),
            restoreConflicts = values.LongCount(x => x.Result?.FailureReason == "DestinationOccupied"),
            deleteRequests = Requested("file.delete"),
            quotaRejections = values.LongCount(x => x.Result?.FailureReason == "QuarantineQuotaExceeded"),
            cleanupFailures = 0,
            failedActions = values.LongCount(x => x.State == ResponseActionState.Failed),
            queueDepth = values.LongCount(x => !ResponseSafety.IsTerminal(x.State)),
            storedBytes = records.Where(x => x.RestoreEligible).Sum(x => x.OriginalSize),
            storeFiles = records.LongCount(x => x.RestoreEligible),
            storeMaximumBytes = FileResponseSafety.MaximumStoreBytes,
            storeMaximumFiles = FileResponseSafety.MaximumStoreFiles,
            actionLatencyMilliseconds = latencies.Length == 0 ? 0 : latencies.Average(),
            updatedAt = DateTimeOffset.UtcNow
        });
    }

    static async Task<IResult> Approve(Guid id, ResponseApprovalRequest input, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var action = await actions.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound();
        if (!FileResponseSafety.IsFileResponseAction(action.ActionType)) return Problem(c, "FILE_RESPONSE_ACTION_REQUIRED", "The action is not a file response action.");
        return Ok(c, await actions.ApproveAsync(Tenant(c), id, Actor(c), input, ct));
    }

    static async Task<IResult> Cancel(Guid id, ResponseCancelRequest input, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var action = await actions.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound();
        if (!FileResponseSafety.IsFileResponseAction(action.ActionType)) return Problem(c, "FILE_RESPONSE_ACTION_REQUIRED", "The action is not a file response action.");
        return Ok(c, await actions.CancelAsync(Tenant(c), id, Actor(c), input, ct));
    }

    static FileResponseTarget ToTarget(FileEntityView file)
    {
        var native = file.NativeIdentity;
        if ((string.IsNullOrWhiteSpace(native.VolumeId) || string.IsNullOrWhiteSpace(native.FileId)) &&
            file.Hash.NativeIdentityBefore is { } before && file.Hash.NativeIdentityAfter is { } after && SameNative(before, after))
            native = after;
        if (file.Metadata.Size is not { } size || string.IsNullOrWhiteSpace(native.VolumeId) || string.IsNullOrWhiteSpace(native.FileId))
            throw new EnrollmentConflictException("FILE_RESPONSE_IDENTITY_INCOMPLETE", "The file entity lacks the native identity and size required for safe response.");
        return new(file.FileEntityId, native, file.CurrentPath, size, file.Hash.Sha256, file.LastObserved, file.CreatedAt, file.Metadata.ModifiedAt);
    }

    static bool SameNative(FileNativeIdentity left, FileNativeIdentity right) =>
        !string.IsNullOrWhiteSpace(left.VolumeId) && !string.IsNullOrWhiteSpace(left.FileId) &&
        string.Equals(left.VolumeId, right.VolumeId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.FileId, right.FileId, StringComparison.OrdinalIgnoreCase);

    static bool TryRecord(ResponseActionRecord action, out FileQuarantineRecord record)
    {
        record = null!;
        try { record = action.Result!.StructuredResult.Deserialize<FileQuarantineRecord>(Json)!; return record is not null && record.TenantId == action.TenantId && record.EndpointId == action.EndpointId && record.AgentInstallationId == action.AgentInstallationId; }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or NullReferenceException) { return false; }
    }

    static bool IsProtectedWindowsPath(string path)
    {
        var normalized = path.Replace('/', '\\').TrimEnd('\\');
        if (normalized.Length == 2 && normalized[1] == ':') return true;
        return normalized.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"C:\Program Files\OpenSecurityPlatform\", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith(@"C:\ProgramData\OpenSecurityPlatform\", StringComparison.OrdinalIgnoreCase);
    }

    static async Task<bool> ContextValid(Guid? alert, Guid? incident, string tenant, IAlertIncidentRepository triage, CancellationToken ct) =>
        (alert is null || await triage.GetAlertAsync(tenant, alert.Value, ct) is not null) &&
        (incident is null || await triage.GetIncidentAsync(tenant, incident.Value, ct) is not null);
}
