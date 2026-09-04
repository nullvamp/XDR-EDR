using OpenSecurityPlatform.Foundation;

static class IsolationRoutes
{
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IReadOnlySet<string> Permissions(HttpContext c) => (IReadOnlySet<string>)c.Items["permissions"]!;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail, int status = 400) => Results.Problem(statusCode: status, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["code"] = code, ["traceId"] = c.TraceIdentifier });

    public static void Map(WebApplication app)
    {
        app.MapPost("/api/v1/endpoints/{endpoint:guid}:isolate", Isolate).RequirePermission("isolation:request");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}:unisolate", Unisolate).RequirePermission("isolation:unisolate");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/isolation:verify", Verify).RequirePermission("isolation:status:read");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/isolation", Status).RequirePermission("isolation:status:read");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/isolation/history", History).RequirePermission("isolation:status:read");
        app.MapPost("/api/v1/isolation-actions/{id:guid}:approve", Approve).RequirePermission("isolation:approve");
        app.MapPost("/api/v1/isolation-actions/{id:guid}:cancel", Cancel).RequirePermission("isolation:cancel");
        app.MapGet("/api/v1/isolation-policy", Policy).RequirePermission("isolation:status:read");
        app.MapPut("/api/v1/isolation-policy", UpdatePolicy).RequirePermission("isolation:policy:admin");
        app.MapGet("/api/v1/isolation-health", Health).RequirePermission("isolation:audit:read");
    }

    static Task<IResult> Isolate(Guid endpoint, IsolationActionRequest input, HttpContext c, IIsolationRepository isolation, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) =>
        Create("endpoint.isolate", endpoint, input, c, isolation, actions, triage, ct);
    static Task<IResult> Unisolate(Guid endpoint, IsolationActionRequest input, HttpContext c, IIsolationRepository isolation, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) =>
        Create("endpoint.unisolate", endpoint, input, c, isolation, actions, triage, ct);
    static Task<IResult> Verify(Guid endpoint, HttpContext c, IIsolationRepository isolation, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) =>
        Create("endpoint.isolation_status", endpoint, new(endpoint, "Analyst requested effective isolation verification.", 300), c, isolation, actions, triage, ct);

    static async Task<IResult> Create(string type, Guid endpoint, IsolationActionRequest input, HttpContext c,
        IIsolationRepository isolation, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct)
    {
        if (input.EndpointId != endpoint) return Problem(c, "ISOLATION_ENDPOINT_MISMATCH", "Route and payload endpoint bindings differ.");
        var tenant = Tenant(c); var target = await actions.ResolveTargetAsync(tenant, endpoint, ct);
        if (target is null) return Results.NotFound();
        if (!string.Equals(target.Platform, "windows", StringComparison.OrdinalIgnoreCase)) return Problem(c, "ISOLATION_PLATFORM_UNSUPPORTED", "Sprint 18 isolation is qualified only for Windows endpoints.");
        if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) return Problem(c, "ISOLATION_ENDPOINT_DISABLED", "Disabled or revoked endpoints cannot receive isolation actions.");
        if (input.SourceAlertId is { } alert && await triage.GetAlertAsync(tenant, alert, ct) is null) return Problem(c, "ISOLATION_ALERT_CONTEXT", "Source alert is unavailable in this tenant.");
        if (input.SourceIncidentId is { } incident && await triage.GetIncidentAsync(tenant, incident, ct) is null) return Problem(c, "ISOLATION_INCIDENT_CONTEXT", "Source incident is unavailable in this tenant.");
        var active = (await isolation.HistoryAsync(tenant, endpoint, ct)).FirstOrDefault(x => !ResponseSafety.IsTerminal(x.State));
        if (active is not null)
        {
            if (active.ActionType == type) return Ok(c, active);
            await isolation.RecordConflictAsync(tenant, ct);
            return Problem(c, "ISOLATION_TRANSITION_CONFLICT", "A conflicting endpoint isolation transition is already active.", 409);
        }
        var current = await isolation.GetAsync(tenant, endpoint, ct);
        if (type == "endpoint.isolate" && current?.EffectiveState == EndpointIsolationState.Isolated) return Ok(c, current);
        if (type == "endpoint.unisolate" && current?.EffectiveState == EndpointIsolationState.NotIsolated) return Ok(c, current);
        var policy = await isolation.PolicyAsync(tenant, ct);
        var mode = type == "endpoint.isolate" ? "isolate" : type == "endpoint.unisolate" ? "unisolate" : "status";
        var parameters = IsolationSafety.ActionParameters(mode, input.Reason, policy);
        var approval = !Permissions(c).Contains("platform:admin") && type switch { "endpoint.isolate" => policy.IsolationApprovalRequired, "endpoint.unisolate" => policy.UnisolationApprovalRequired, _ => false };
        var create = new ResponseActionCreate(endpoint, type, 1, parameters, 120,
            Math.Clamp(input.ExpiresInSeconds, 30, policy.PendingExpirySeconds), null, input.SourceAlertId,
            input.SourceIncidentId, input.SourceEntityId, false, policy.PolicyVersion, approval);
        var action = await actions.CreateAsync(new(tenant, endpoint, target.AgentId, target.AgentInstallationId, Actor(c), create), ct);
        return Results.Accepted($"/api/v1/response-actions/{action.ResponseActionId:D}", new ApiEnvelope<object>(action, new(c.TraceIdentifier, "1.0")));
    }

    static async Task<IResult> Status(Guid endpoint, HttpContext c, IIsolationRepository r, IResponseActionRepository actions, CancellationToken ct)
    {
        if (await actions.ResolveTargetAsync(Tenant(c), endpoint, ct) is null) return Results.NotFound();
        var snapshot = await r.GetAsync(Tenant(c), endpoint, ct);
        var active = (await r.HistoryAsync(Tenant(c), endpoint, ct)).FirstOrDefault(x => !ResponseSafety.IsTerminal(x.State));
        snapshot ??= new EndpointIsolationSnapshot(IsolationSafety.SchemaVersion, Tenant(c), endpoint, active?.AgentInstallationId ?? "unknown",
            EndpointIsolationState.Unknown, EndpointIsolationState.Unknown, null, null, "unknown",
            IsolationSafety.EnforcementMechanism, [], null, null, IsolationDriftState.Unknown, null, null, null,
            null, null, null, DateTimeOffset.UtcNow);
        if (active is not null)
        {
            var running = active.State is ResponseActionState.Acknowledged or ResponseActionState.Running or ResponseActionState.CancelRequested;
            var requested = active.ActionType switch
            {
                "endpoint.isolate" => running ? EndpointIsolationState.Isolating : EndpointIsolationState.IsolationPending,
                "endpoint.unisolate" => running ? EndpointIsolationState.Unisolating : EndpointIsolationState.UnisolationPending,
                _ => snapshot.RequestedState,
            };
            snapshot = snapshot with { RequestedState = requested, ActionId = active.ResponseActionId, Requester = active.AnalystId, Approver = active.ApproverId, Reason = active.Parameters.GetProperty("reason").GetString(), PolicyVersion = active.PolicyVersion, UpdatedAt = DateTimeOffset.UtcNow };
        }
        return Ok(c, snapshot);
    }
    static async Task<IResult> History(Guid endpoint, HttpContext c, IIsolationRepository r, IResponseActionRepository actions, CancellationToken ct) =>
        await actions.ResolveTargetAsync(Tenant(c), endpoint, ct) is null ? Results.NotFound() : Ok(c, await r.HistoryAsync(Tenant(c), endpoint, ct));
    static async Task<IResult> Approve(Guid id, ResponseApprovalRequest input, HttpContext c, IResponseActionRepository r, CancellationToken ct)
    {
        var action = await r.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound();
        if (!IsolationSafety.IsIsolationAction(action.ActionType)) return Problem(c, "ISOLATION_ACTION_REQUIRED", "The action is not an isolation action.");
        return Ok(c, await r.ApproveAsync(Tenant(c), id, Actor(c), input, ct));
    }
    static async Task<IResult> Cancel(Guid id, ResponseCancelRequest input, HttpContext c, IResponseActionRepository r, CancellationToken ct)
    {
        var action = await r.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound();
        if (!IsolationSafety.IsIsolationAction(action.ActionType)) return Problem(c, "ISOLATION_ACTION_REQUIRED", "The action is not an isolation action.");
        return Ok(c, await r.CancelAsync(Tenant(c), id, Actor(c), input, ct));
    }
    static async Task<IResult> Policy(HttpContext c, IIsolationRepository r, CancellationToken ct) => Ok(c, await r.PolicyAsync(Tenant(c), ct));
    static async Task<IResult> UpdatePolicy(IsolationPolicyUpdate input, HttpContext c, IIsolationRepository r, CancellationToken ct) => Ok(c, await r.UpdatePolicyAsync(Tenant(c), Actor(c), input, ct));
    static async Task<IResult> Health(HttpContext c, IIsolationRepository r, CancellationToken ct) => Ok(c, await r.HealthAsync(Tenant(c), ct));
}
