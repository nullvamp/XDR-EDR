using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed class PlaybookActionExecutor(IResponseActionRepository responses) : IPlaybookActionExecutor
{
    public async Task<PlaybookActionResult> ExecuteAsync(PlaybookActionContext context, CancellationToken ct)
    {
        if (context.ExistingResponseActionId is { } existing)
        {
            var prior = await responses.GetAsync(context.TenantId, existing, ct) ?? throw new EnrollmentConflictException("PLAYBOOK_RESPONSE_MISSING", "Bound response action is unavailable.");
            if (!ResponseSafety.IsTerminal(prior.State)) return new(false, false, false, true, prior.ResponseActionId, prior.State.ToString(), prior.ParameterHash, [$"response-action://{prior.ResponseActionId:D}"], prior.AgentInstallationId);
            var success = prior.State == ResponseActionState.Succeeded && prior.Result is not null; var partial = prior.State == ResponseActionState.Partial; var verified = success && prior.Result!.ResultHash.Length == 64;
            return new(success, partial, verified, false, prior.ResponseActionId, prior.State.ToString(), prior.Result?.ResultHash ?? prior.ParameterHash, [$"response-action://{prior.ResponseActionId:D}"], prior.AgentInstallationId);
        }
        var target = await responses.ResolveTargetAsync(context.TenantId, context.EndpointId, ct) ?? throw new EnrollmentConflictException("PLAYBOOK_ENDPOINT_MISSING", "Endpoint target is unavailable.");
        if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) throw new EnrollmentConflictException("PLAYBOOK_ENDPOINT_DISABLED", "Disabled or revoked endpoint cannot execute a playbook action.");
        if (context.ExpectedInstallationId is not null && !string.Equals(context.ExpectedInstallationId, target.AgentInstallationId, StringComparison.Ordinal)) return new(false, false, false, false, null, "TARGET_IDENTITY_MISMATCH", PlaybookSafety.Hash("identity-mismatch"), [], target.AgentInstallationId);
        var definition = ResponseSafety.GetDefinition(context.ActionType, context.ActionVersion); ResponseSafety.ValidateParameters(definition, context.Parameters);
        var input = new ResponseActionCreate(context.EndpointId, context.ActionType, context.ActionVersion, context.Parameters, Math.Clamp(context.TimeoutSeconds, definition.MinimumTimeoutSeconds, definition.MaximumTimeoutSeconds), 900, $"playbook:{context.ExecutionId:D}:{context.StepId}", SourceEntityId: context.TargetEntityId, PolicyVersion: "playbook-response-policy.v1");
        var action = await responses.CreateAsync(new(context.TenantId, target.EndpointId, target.AgentId, target.AgentInstallationId, context.Requester, input), ct);
        if (action.ApprovalState == ResponseApprovalState.Pending)
        {
            if (context.Approver is null) throw new EnrollmentConflictException("PLAYBOOK_RESPONSE_APPROVAL_MISSING", "Destructive response action lacks its bound playbook approver.");
            action = await responses.ApproveAsync(context.TenantId, action.ResponseActionId, context.Approver, new(action.ParameterHash, $"Playbook {context.ExecutionId:D} exact approved step {context.StepId}"), ct);
        }
        return new(false, false, false, true, action.ResponseActionId, "queued-awaiting-endpoint-verification", action.ParameterHash, [$"response-action://{action.ResponseActionId:D}"], target.AgentInstallationId);
    }
}
