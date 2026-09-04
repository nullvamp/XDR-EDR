using System.Security.Cryptography;
using System.Text;
using OpenSecurityPlatform.Foundation;

static class ProcessResponseRoutes
{
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail, int status = 400) => Results.Problem(statusCode: status, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["code"] = code, ["traceId"] = c.TraceIdentifier });

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/processes/{entity}/response-preview", Preview).RequirePermission("process-response:read");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/processes/{entity}:terminate", Terminate).RequirePermission("process-response:terminate");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/processes/{entity}:suspend", Suspend).RequirePermission("process-response:suspend");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/processes/{entity}:resume", Resume).RequirePermission("process-response:resume");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/processes/{entity}:status", Status).RequirePermission("process-response:read");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/processes/{entity}/tree-response-preview", TreePreview).RequirePermission("process-response:tree-terminate");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/processes/{entity}/tree:terminate", TreeTerminate).RequirePermission("process-response:tree-terminate");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/process-response-history", History).RequirePermission("process-response:history:read");
        app.MapGet("/api/v1/process-response-health", Health).RequirePermission("process-response:history:read");
        app.MapPost("/api/v1/process-response-actions/{id:guid}:approve", Approve).RequirePermission("process-response:approve");
        app.MapPost("/api/v1/process-response-actions/{id:guid}:cancel", Cancel).RequirePermission("response:cancel");
    }

    static Task<IResult> Terminate(Guid endpoint, string entity, ProcessResponseRequest input, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) => CreateSingle("process.terminate", endpoint, entity, input, c, processes, actions, triage, ct);
    static Task<IResult> Suspend(Guid endpoint, string entity, ProcessResponseRequest input, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) => CreateSingle("process.suspend", endpoint, entity, input, c, processes, actions, triage, ct);
    static Task<IResult> Resume(Guid endpoint, string entity, ProcessResponseRequest input, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) => CreateSingle("process.resume", endpoint, entity, input, c, processes, actions, triage, ct);
    static Task<IResult> Status(Guid endpoint, string entity, ProcessResponseRequest input, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) => CreateSingle("process.response_status", endpoint, entity, input, c, processes, actions, triage, ct);

    static async Task<IResult> Preview(Guid endpoint, string entity, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, CancellationToken ct)
    {
        var process = await processes.GetAsync(Tenant(c), endpoint, entity, ct);
        if (process is null) return Results.NotFound();
        var target = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (target is null) return Results.NotFound();
        return Ok(c, BuildPreview("process.terminate", target, process, [ToTarget(process, 0)], []));
    }

    static async Task<IResult> TreePreview(Guid endpoint, string entity, int? maximumDepth, int? maximumProcessCount, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, CancellationToken ct)
    {
        var depth = Math.Clamp(maximumDepth ?? 4, 1, ProcessResponseSafety.MaximumTreeDepth);
        var count = Math.Clamp(maximumProcessCount ?? 64, 1, ProcessResponseSafety.MaximumTreeProcesses);
        var tree = await processes.TreeAsync(Tenant(c), endpoint, entity, depth, ct);
        var target = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (tree is null || target is null) return Results.NotFound();
        var flattened = Flatten(tree, 0).Take(count).Select(x => ToTarget(x.Process, x.Depth)).OrderByDescending(x => x.Depth).ThenBy(x => x.ProcessStartTime).ThenBy(x => x.ProcessEntityId, StringComparer.Ordinal).ToArray();
        var protectedTargets = flattened.Where(x => IsObviouslyProtected(x, target)).Select(x => x.ProcessEntityId).ToArray();
        return Ok(c, BuildPreview("process_tree.terminate", target, tree.Process, flattened, protectedTargets));
    }

    static async Task<IResult> TreeTerminate(Guid endpoint, string entity, ProcessTreeResponseRequest input, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct)
    {
        var depth = Math.Clamp(input.MaximumDepth, 1, ProcessResponseSafety.MaximumTreeDepth);
        var count = Math.Clamp(input.MaximumProcessCount, 1, ProcessResponseSafety.MaximumTreeProcesses);
        var tree = await processes.TreeAsync(Tenant(c), endpoint, entity, depth, ct);
        var endpointTarget = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (tree is null || endpointTarget is null) return Results.NotFound();
        if (tree.Process.ExitTime is not null) return Problem(c, "PROCESS_RESPONSE_ALREADY_EXITED", "The root process had already exited before the request was created.", 409);
        if (!await ContextValid(input.SourceAlertId, input.SourceIncidentId, Tenant(c), triage, ct)) return Problem(c, "PROCESS_RESPONSE_SOURCE_CONTEXT", "Source alert or incident is unavailable in this tenant.");
        var targets = Flatten(tree, 0).Take(count).Select(x => ToTarget(x.Process, x.Depth)).OrderByDescending(x => x.Depth).ThenBy(x => x.ProcessStartTime).ThenBy(x => x.ProcessEntityId, StringComparer.Ordinal).ToArray();
        var protectedTargets = targets.Where(x => IsObviouslyProtected(x, endpointTarget)).Select(x => x.ProcessEntityId).ToArray();
        if (protectedTargets.Length > 0) return Problem(c, "PROCESS_RESPONSE_PROTECTED", "The pinned tree intersects a protected platform or critical process.", 409);
        var preview = BuildPreview("process_tree.terminate", endpointTarget, tree.Process, targets, protectedTargets);
        var parameters = ProcessResponseSafety.TreeParameters(input.Reason, preview, depth, count);
        return await Create(endpointTarget, "process_tree.terminate", parameters, input.Reason, input.ExpiresInSeconds, input.SourceAlertId, input.SourceIncidentId, input.SourceEntityId ?? entity, c, actions, ct);
    }

    internal static async Task<IResult> CreateSingle(string type, Guid endpoint, string entity, ProcessResponseRequest input, HttpContext c, IProcessTelemetryRepository processes, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct)
    {
        var process = await processes.GetAsync(Tenant(c), endpoint, entity, ct);
        var target = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (process is null || target is null) return Results.NotFound();
        if (!await ContextValid(input.SourceAlertId, input.SourceIncidentId, Tenant(c), triage, ct)) return Problem(c, "PROCESS_RESPONSE_SOURCE_CONTEXT", "Source alert or incident is unavailable in this tenant.");
        if (type != "process.response_status" && process.ExitTime is not null) return Problem(c, "PROCESS_RESPONSE_ALREADY_EXITED", "The canonical target had already exited before the request was created.", 409);
        var pinned = ToTarget(process, 0);
        if (IsObviouslyProtected(pinned, target)) return Problem(c, "PROCESS_RESPONSE_PROTECTED", "The target is a protected platform or critical process.", 409);
        return await Create(target, type, ProcessResponseSafety.Parameters(input.Reason, pinned), input.Reason, input.ExpiresInSeconds, input.SourceAlertId, input.SourceIncidentId, input.SourceEntityId ?? entity, c, actions, ct);
    }

    static async Task<IResult> Create(ResponseTarget target, string type, System.Text.Json.JsonElement parameters, string reason, int expires, Guid? alert, Guid? incident, string sourceEntity, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        if (!string.Equals(target.Platform, "windows", StringComparison.OrdinalIgnoreCase)) return Problem(c, "PROCESS_RESPONSE_PLATFORM", "Sprint 19 process response is qualified only for Windows endpoints.");
        if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) return Problem(c, "PROCESS_RESPONSE_ENDPOINT_DISABLED", "Disabled or revoked endpoints cannot receive process actions.");
        var create = new ResponseActionCreate(target.EndpointId, type, 1, parameters, 120, Math.Clamp(expires, 30, 3600), null, alert, incident, sourceEntity, false, "process-response-policy.v1", type != "process.response_status");
        var action = await actions.CreateAsync(new(Tenant(c), target.EndpointId, target.AgentId, target.AgentInstallationId, Actor(c), create), ct);
        return Results.Accepted($"/api/v1/response-actions/{action.ResponseActionId:D}", new ApiEnvelope<object>(new { action, previewHash = ResponseSafety.ParameterHash(parameters), reason }, new(c.TraceIdentifier, "1.0")));
    }

    static async Task<bool> ContextValid(Guid? alert, Guid? incident, string tenant, IAlertIncidentRepository triage, CancellationToken ct) =>
        (alert is null || await triage.GetAlertAsync(tenant, alert.Value, ct) is not null) &&
        (incident is null || await triage.GetIncidentAsync(tenant, incident.Value, ct) is not null);

    static ProcessResponseTarget ToTarget(ProcessEntityView p, int depth) => new(p.ProcessEntityId, p.ProcessId, p.StartTime, p.ExecutablePath, p.ExecutableMetadata?.Sha256, depth);
    static IEnumerable<(ProcessEntityView Process, int Depth)> Flatten(ProcessTreeNode node, int depth)
    {
        yield return (node.Process, depth);
        foreach (var child in node.Children) foreach (var value in Flatten(child, depth + 1)) yield return value;
    }
    static bool IsObviouslyProtected(ProcessResponseTarget p, ResponseTarget endpoint) => p.ProcessId is <= 4 ||
        string.Equals(p.ImagePath is null ? null : Path.GetFileName(p.ImagePath), "Platform.Agent.exe", StringComparison.OrdinalIgnoreCase);
    static ProcessResponsePreview BuildPreview(string type, ResponseTarget endpoint, ProcessEntityView root, ProcessResponseTarget[] targets, string[] protectedTargets)
    {
        var captured = DateTimeOffset.UtcNow;
        var material = string.Join('\n', targets.Select(x => $"{x.Depth}:{x.ProcessEntityId}:{x.ProcessId}:{x.ProcessStartTime:O}"));
        var version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
        return new(ProcessResponseSafety.SchemaVersion, endpoint.EndpointId, endpoint.AgentInstallationId, type, captured, version,
            ToTarget(root, 0), targets, protectedTargets, Math.Max(0, targets.Length - 1), root.UserName, root.SessionId,
            root.IntegrityLevel, root.ExecutableMetadata?.SignerSubject, root.ExecutableMetadata?.Sha256, 0, 0,
            type == "process_tree.terminate" ? "deepest-first; start-time; entity-id; root-last" : "single exact stable entity");
    }

    static async Task<IResult> History(Guid endpoint, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), endpoint, null, 200, null, ct);
        return Ok(c, page with { Items = page.Items.Where(x => ProcessResponseSafety.IsProcessAction(x.ActionType)).ToArray() });
    }
    static async Task<IResult> Health(HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct);
        var values = page.Items.Where(x => ProcessResponseSafety.IsProcessAction(x.ActionType)).ToArray();
        var completedLatencies = values.Where(x => x.Result is not null).Select(x => (x.Result!.CompletedAt - x.Result.StartedAt).TotalMilliseconds).ToArray();
        long Requested(string type) => values.LongCount(x => x.ActionType == type);
        long ResultState(string state) => values.LongCount(x => string.Equals(x.Result?.StructuredResult.TryGetProperty("state", out var s) == true ? s.GetString() : null, state, StringComparison.Ordinal));
        return Ok(c, new
        {
            schemaVersion = "process-response-health.v1",
            terminateRequests = Requested("process.terminate"),
            successfulTermination = ResultState("Terminated"),
            failedTermination = values.LongCount(x => x.ActionType == "process.terminate" && x.State == ResponseActionState.Failed),
            identityMismatchRejections = ResultState("IdentityMismatch"),
            protectedProcessRejections = values.LongCount(x => x.Result?.FailureCategory == ResponseFailureCategory.Authorization),
            alreadyExitedTargets = ResultState("ExitedBeforeAction"),
            suspendRequests = Requested("process.suspend"),
            resumeRequests = Requested("process.resume"),
            partialSuspensions = ResultState("Partial"),
            treeActions = Requested("process_tree.terminate"),
            treePartialResults = values.LongCount(x => x.ActionType == "process_tree.terminate" && x.Result?.StructuredResult.TryGetProperty("state", out var s) == true && s.GetString() == "Partial"),
            cancellations = values.LongCount(x => x.State is ResponseActionState.Cancelled or ResponseActionState.CancelRequested),
            actionLatencyMilliseconds = completedLatencies.Length == 0 ? 0 : completedLatencies.Average(),
            queueDepth = values.LongCount(x => !ResponseSafety.IsTerminal(x.State)),
            updatedAt = DateTimeOffset.UtcNow
        });
    }
    static async Task<IResult> Approve(Guid id, ResponseApprovalRequest input, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var action = await actions.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound();
        if (!ProcessResponseSafety.IsProcessAction(action.ActionType)) return Problem(c, "PROCESS_RESPONSE_ACTION_REQUIRED", "The action is not a process response action.");
        return Ok(c, await actions.ApproveAsync(Tenant(c), id, Actor(c), input, ct));
    }
    static async Task<IResult> Cancel(Guid id, ResponseCancelRequest input, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var action = await actions.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound();
        if (!ProcessResponseSafety.IsProcessAction(action.ActionType)) return Problem(c, "PROCESS_RESPONSE_ACTION_REQUIRED", "The action is not a process response action.");
        return Ok(c, await actions.CancelAsync(Tenant(c), id, Actor(c), input, ct));
    }
}
