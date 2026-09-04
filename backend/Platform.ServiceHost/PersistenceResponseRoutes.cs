using System.Globalization;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class PersistenceResponseRoutes
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail, int status = 400) => Results.Problem(statusCode: status, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["code"] = code, ["traceId"] = c.TraceIdentifier });

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/persistence/{entity}/remediation-preview", Preview).RequirePermission("persistence-response:read");
        app.MapPost("/api/v1/endpoints/{endpoint:guid}/persistence/{entity}:remediate", Remediate).RequirePermission("persistence-response:request");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/persistence-remediation-history", History).RequirePermission("persistence-response:history:read");
        app.MapGet("/api/v1/persistence-remediation-backups", ListBackups).RequirePermission("persistence-response:read");
        app.MapGet("/api/v1/persistence-remediation-backups/{id:guid}", GetBackup).RequirePermission("persistence-response:read");
        app.MapPost("/api/v1/persistence-remediation-backups/{id:guid}:restore", Restore).RequirePermission("persistence-response:restore");
        app.MapPost("/api/v1/persistence-remediation-actions/{id:guid}:approve", Approve).RequirePermission("persistence-response:approve");
        app.MapPost("/api/v1/persistence-remediation-actions/{id:guid}:cancel", Cancel).RequirePermission("response:cancel");
        app.MapGet("/api/v1/persistence-remediation-health", Health).RequirePermission("persistence-response:history:read");
    }

    static async Task<IResult> Preview(Guid endpoint, string entity, HttpContext c, IPersistenceTelemetryRepository persistence,
        IResponseActionRepository actions, CancellationToken ct)
    {
        var result = await ResolvePreview(endpoint, entity, c, persistence, actions, ct);
        return result.Preview is null ? result.Error! : Ok(c, result.Preview);
    }

    internal static Task<IResult> PreviewSingle(Guid endpoint, string entity, HttpContext c,
        IPersistenceTelemetryRepository persistence, IResponseActionRepository actions, CancellationToken ct) =>
        Preview(endpoint, entity, c, persistence, actions, ct);

    static async Task<IResult> Remediate(Guid endpoint, string entity, PersistenceRemediationRequest input, HttpContext c,
        IPersistenceTelemetryRepository persistence, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct)
    {
        var resolved = await ResolvePreview(endpoint, entity, c, persistence, actions, ct);
        if (resolved.Preview is null) return resolved.Error!;
        if (!resolved.Preview.SupportedActions.Contains(input.ActionType, StringComparer.Ordinal))
            return Problem(c, "PERSISTENCE_RESPONSE_ACTION_UNSUPPORTED", "The requested action is not supported for the authoritative object state.", 409);
        if (resolved.Preview.Protected) return Problem(c, "PERSISTENCE_RESPONSE_PROTECTED", resolved.Preview.ProtectionReason, 409);
        if (!await ContextValid(input.SourceAlertId, input.SourceIncidentId, Tenant(c), triage, ct))
            return Problem(c, "PERSISTENCE_RESPONSE_SOURCE_CONTEXT", "Source alert or incident is unavailable in this tenant.");
        return await Create(resolved.Destination!, input.ActionType,
            PersistenceResponseSafety.TargetParameters(input.Reason, resolved.Preview.Target), input.Reason, input.ExpiresInSeconds,
            input.SourceAlertId, input.SourceIncidentId, input.SourceEntityId ?? entity, c, actions, ct);
    }

    internal static async Task<IResult> CreateSingle(string actionType, Guid endpoint, string entity, PersistenceRemediationRequest input,
        HttpContext c, IPersistenceTelemetryRepository persistence, IResponseActionRepository actions, IAlertIncidentRepository triage, CancellationToken ct) =>
        await Remediate(endpoint, entity, input with { ActionType = actionType }, c, persistence, actions, triage, ct);

    static async Task<(PersistenceRemediationPreview? Preview, ResponseTarget? Destination, IResult? Error)> ResolvePreview(
        Guid endpoint, string entity, HttpContext c, IPersistenceTelemetryRepository persistence, IResponseActionRepository actions, CancellationToken ct)
    {
        if (entity.Length != 64 || !entity.All(Uri.IsHexDigit)) return (null, null, Problem(c, "PERSISTENCE_RESPONSE_ENTITY", "A canonical persistence entity identity is required."));
        var history = await persistence.EntityHistoryAsync(Tenant(c), endpoint, entity, 500, ct);
        var observation = history.Items.OrderByDescending(x => x.ObservedAt).FirstOrDefault();
        var destination = await actions.ResolveTargetAsync(Tenant(c), endpoint, ct);
        if (observation is null || destination is null) return (null, null, Results.NotFound());
        if (observation.InstallationId != destination.AgentInstallationId) return (null, null, Problem(c, "PERSISTENCE_RESPONSE_ENDPOINT_BINDING", "Telemetry no longer matches the active endpoint installation.", 409));
        if (Deleted(observation)) return (null, null, Problem(c, "PERSISTENCE_RESPONSE_ALREADY_ABSENT", "The authoritative persistence object is already absent.", 409));
        PersistenceRemediationTarget target;
        try { target = ToTarget(observation); }
        catch (EnrollmentConflictException ex) { return (null, null, Problem(c, ex.Code, ex.Message, 409)); }
        var supported = Supported(target, observation).ToArray();
        var protection = Protection(target);
        return (new(PersistenceResponseSafety.SchemaVersion, endpoint, destination.AgentInstallationId, target, supported,
            supported.Length > 0, supported.Length > 0, protection is not null, protection ?? "none",
            Dependencies(observation), ProcessRelationships(observation), 0, DateTimeOffset.UtcNow), destination, null);
    }

    static PersistenceRemediationTarget ToTarget(PersistenceObservation value)
    {
        var evidence = value.Configuration?.RawEvidenceEventIds ?? [];
        var references = new[] { $"postgresql://platform/persistence_events/{value.EventId:D}" }.Concat(evidence).Distinct(StringComparer.Ordinal).Take(64).ToArray();
        if (value.Service is { } service)
        {
            var generation = ResolveGeneration(value, service.EntityId, service.Name);
            var stateHash = PersistenceResponseSafety.StateHash(service.Name, service.BinaryPath, NormalizeStart(service.StartupType), service.Account,
                (service.DriverService == true).ToString(CultureInfo.InvariantCulture));
            return new(service.EntityId, value.EventId, value.ObjectKind, PersistenceRemediationKind.Service, "service", service.Name,
                generation, stateHash, service.State ?? "configured", references, ServiceName: service.Name, ServiceBinaryPath: service.BinaryPath,
                ServiceStartType: service.StartupType, ServiceAccount: service.Account, DriverService: service.DriverService);
        }
        if (value.ScheduledTask is { } task)
        {
            if (string.IsNullOrWhiteSpace(task.PolicyControlledXmlSha256)) throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_TASK_EVIDENCE", "Current policy-controlled task XML evidence is required for safe response.");
            var generation = ResolveGeneration(value, task.EntityId, task.Path);
            return new(task.EntityId, value.EventId, value.ObjectKind, PersistenceRemediationKind.ScheduledTask, "scheduled-task", task.Path,
                generation, PersistenceResponseSafety.StateHash(task.Path, task.PolicyControlledXmlSha256), task.DeletedAt is null ? task.Enabled == false ? "disabled" : "configured" : "deleted",
                references, TaskPath: task.Path, TaskXmlSha256: task.PolicyControlledXmlSha256);
        }
        var configuration = value.Configuration ?? throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_EVIDENCE", "Authoritative persistence evidence is incomplete.");
        var kind = Kind(configuration);
        var hive = configuration.RegistryPath is null ? null : configuration.RegistryPath.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) ? "HKCU" : configuration.RegistryPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) ? "HKLM" : null;
        var key = hive is null ? null : configuration.RegistryPath![(hive.Length + 1)..];
        var expected = kind switch
        {
            PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.GenericRegistryConfiguration => PersistenceResponseSafety.StateHash(configuration.NativeObjectIdentity, configuration.ActionPath),
            PersistenceRemediationKind.WmiFilter => PersistenceResponseSafety.StateHash(configuration.NativeObjectIdentity, null, null, configuration.TriggerMetadata),
            PersistenceRemediationKind.WmiConsumer => PersistenceResponseSafety.StateHash(configuration.NativeObjectIdentity, null, null, configuration.ActionPath ?? configuration.ConsumerMetadata),
            PersistenceRemediationKind.WmiBinding => PersistenceResponseSafety.StateHash(configuration.NativeObjectIdentity, configuration.FilterIdentity, configuration.ConsumerIdentity, null),
            _ => PersistenceResponseSafety.StateHash(configuration.NativeObjectIdentity, configuration.ActionPath)
        };
        return new(configuration.EntityId, value.EventId, value.ObjectKind, kind, configuration.Category, configuration.NativeObjectIdentity,
            configuration.Generation, expected, configuration.CurrentState, references, RegistryHive: hive,
            RegistryView: configuration.RegistryView, RegistryKeyPath: key, RegistryValueName: kind is PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.GenericRegistryConfiguration ? configuration.Name == "(Default)" ? "" : configuration.Name : null,
            RegistryValueEntityId: configuration.RegistryEntityId, TaskPath: null,
            WmiNamespace: kind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding ? configuration.NamespaceOrLocation : null,
            WmiClass: kind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding ? configuration.Subtype : null,
            WmiRelativePath: kind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding ? configuration.NativeObjectIdentity : null,
            FilterIdentity: configuration.FilterIdentity, ConsumerIdentity: configuration.ConsumerIdentity, FilePath: configuration.FilePath,
            ExpectedValue: configuration.ActionPath ?? configuration.TriggerMetadata);
    }

    static PersistenceRemediationKind Kind(PersistenceConfigurationEvidence value) => value.Category switch
    {
        "wmi-filter" => PersistenceRemediationKind.WmiFilter,
        "wmi-consumer" => PersistenceRemediationKind.WmiConsumer,
        "wmi-binding" => PersistenceRemediationKind.WmiBinding,
        "startup-item" => PersistenceRemediationKind.StartupFile,
        "autorun" => PersistenceRemediationKind.RegistryValue,
        _ when value.RegistryPath is not null => PersistenceRemediationKind.GenericRegistryConfiguration,
        _ => throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_KIND", "This persistence configuration has no supported reversible response primitive.")
    };

    static long ResolveGeneration(PersistenceObservation value, string entity, string canonical)
    {
        if (value.Configuration is { } configuration) return configuration.Generation;
        for (long generation = 1; generation <= 100_000; generation++)
            if (string.Equals(PersistenceSafety.EntityId(value.EndpointId, value.InstallationId, value.ObjectKind, canonical, generation), entity, StringComparison.Ordinal)) return generation;
        throw new EnrollmentConflictException("PERSISTENCE_RESPONSE_GENERATION", "Lifecycle generation could not be proven from canonical identity.");
    }

    static IEnumerable<string> Supported(PersistenceRemediationTarget target, PersistenceObservation value)
    {
        if (Protection(target) is not null) yield break;
        switch (target.RemediationKind)
        {
            case PersistenceRemediationKind.RegistryValue: yield return "registry.value.remove"; yield return "persistence.remove"; break;
            case PersistenceRemediationKind.Service: yield return "service.stop"; yield return "service.disable"; yield return "service.delete"; break;
            case PersistenceRemediationKind.ScheduledTask: yield return "scheduled_task.disable"; yield return "scheduled_task.delete"; break;
            case PersistenceRemediationKind.WmiBinding: yield return "wmi.binding.remove"; yield return "persistence.remove"; break;
            case PersistenceRemediationKind.WmiConsumer: yield return "wmi.consumer.remove"; yield return "persistence.remove"; break;
            case PersistenceRemediationKind.WmiFilter: yield return "wmi.filter.remove"; yield return "persistence.remove"; break;
            case PersistenceRemediationKind.GenericRegistryConfiguration when value.Configuration?.Category == "autorun": yield return "persistence.remove"; break;
        }
    }

    static string? Protection(PersistenceRemediationTarget target)
    {
        if (target.DriverService == true) return "driver-services-are-not-remediated";
        var protectedServices = new[] { "WinDefend", "WdNisSvc", "SecurityHealthService", "EventLog", "RpcSs", "DcomLaunch", "SamSs", "LSM", "Schedule", "Wmi", "Winmgmt", "BFE", "mpssvc" };
        if (target.ServiceName is { } service && (protectedServices.Contains(service, StringComparer.OrdinalIgnoreCase) || service.Contains("OpenSecurityPlatform", StringComparison.OrdinalIgnoreCase))) return "protected-operating-system-or-platform-service";
        if (target.TaskPath?.StartsWith("\\Microsoft\\Windows\\", StringComparison.OrdinalIgnoreCase) == true || target.TaskPath?.Contains("OpenSecurityPlatform", StringComparison.OrdinalIgnoreCase) == true && target.TaskPath?.StartsWith("\\OpenSecurityPlatform\\Sprint21\\", StringComparison.OrdinalIgnoreCase) != true) return "protected-operating-system-or-platform-task";
        if (target.RegistryKeyPath is { } path && (path.Contains("Winlogon", StringComparison.OrdinalIgnoreCase) || path.Contains("Control\\Lsa", StringComparison.OrdinalIgnoreCase) || path.Contains("AppCertDlls", StringComparison.OrdinalIgnoreCase) || path.Contains("Image File Execution Options", StringComparison.OrdinalIgnoreCase))) return "security-critical-registry-configuration";
        if (target.RemediationKind is PersistenceRemediationKind.GenericRegistryConfiguration or PersistenceRemediationKind.RegistryValue && target.RegistryKeyPath is { } registry && !registry.StartsWith("Software\\Microsoft\\Windows\\CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase) && !registry.StartsWith("Software\\OpenSecurityPlatform\\Sprint21", StringComparison.OrdinalIgnoreCase)) return "registry-location-not-in-remediation-allowlist";
        if ((target.RemediationKind is PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding) && !string.Equals(target.WmiNamespace, "root\\subscription", StringComparison.OrdinalIgnoreCase)) return "wmi-namespace-not-supported";
        if (target.RemediationKind == PersistenceRemediationKind.StartupFile) return "startup-file-remediation-is-delegated-to-file-response";
        return null;
    }

    static string[] Dependencies(PersistenceObservation value) => value.Service?.Dependencies ??
        new[] { value.Configuration?.FilterIdentity, value.Configuration?.ConsumerIdentity }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToArray();
    static int ProcessRelationships(PersistenceObservation value) => value.Service?.Process is null && value.ScheduledTask?.Process is null ? 0 : 1;
    static bool Deleted(PersistenceObservation value) => value.Kind.ToString().EndsWith("Deleted", StringComparison.Ordinal) || value.Service?.DeletedAt is not null || value.ScheduledTask?.DeletedAt is not null || value.Configuration?.DeletedAt is not null || value.Configuration?.CurrentState == "deleted";
    static string NormalizeStart(string? value) => value?.ToLowerInvariant() switch { "auto" or "automatic" => "automatic", "manual" => "manual", "disabled" => "disabled", "boot" => "boot", "system" => "system", _ => value?.ToLowerInvariant() ?? "unknown" };

    internal static async Task<IResult> Restore(Guid id, PersistenceRestoreRequest input, HttpContext c, IResponseActionRepository actions,
        IAlertIncidentRepository triage, CancellationToken ct)
    {
        var source = await FindBackup(id, c, actions, ct);
        if (source.Action is null || source.Record?.Backup is not { } backup) return Results.NotFound();
        if (!backup.RestoreEligible || backup.State == PersistenceRemediationState.Restored) return Problem(c, "PERSISTENCE_RESPONSE_RESTORE_NOT_ELIGIBLE", "The backup is not eligible for restore.", 409);
        if (!await ContextValid(input.SourceAlertId, input.SourceIncidentId, Tenant(c), triage, ct)) return Problem(c, "PERSISTENCE_RESPONSE_SOURCE_CONTEXT", "Source alert or incident is unavailable in this tenant.");
        var destination = await actions.ResolveTargetAsync(Tenant(c), backup.EndpointId, ct);
        if (destination is null || destination.AgentInstallationId != backup.AgentInstallationId) return Problem(c, "PERSISTENCE_RESPONSE_ENDPOINT_BINDING", "The backup no longer matches the active endpoint installation.", 409);
        var type = backup.Target.RemediationKind switch { PersistenceRemediationKind.Service => "service.restore", PersistenceRemediationKind.ScheduledTask => "scheduled_task.restore", PersistenceRemediationKind.WmiFilter or PersistenceRemediationKind.WmiConsumer or PersistenceRemediationKind.WmiBinding => "wmi.persistence.restore", PersistenceRemediationKind.RegistryValue or PersistenceRemediationKind.RegistryKey or PersistenceRemediationKind.GenericRegistryConfiguration => "registry.value.restore", _ => "persistence.restore" };
        return await Create(destination, type, PersistenceResponseSafety.BackupParameters(input.Reason, id), input.Reason,
            input.ExpiresInSeconds, input.SourceAlertId, input.SourceIncidentId, input.SourceEntityId ?? backup.Target.PersistenceEntityId, c, actions, ct);
    }

    static async Task<IResult> Create(ResponseTarget target, string type, JsonElement parameters, string reason, int expires,
        Guid? alert, Guid? incident, string sourceEntity, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        if (!string.Equals(target.Platform, "windows", StringComparison.OrdinalIgnoreCase)) return Problem(c, "PERSISTENCE_RESPONSE_PLATFORM", "Sprint 21 response is qualified only for Windows endpoints.");
        if (target.Status is EndpointStatus.Disabled or EndpointStatus.Revoked) return Problem(c, "PERSISTENCE_RESPONSE_ENDPOINT_DISABLED", "Disabled or revoked endpoints cannot receive remediation actions.");
        var request = new ResponseActionCreate(target.EndpointId, type, 1, parameters, 180, Math.Clamp(expires, 30, 3600), null,
            alert, incident, sourceEntity, false, PersistenceResponseSafety.PolicyVersion);
        var action = await actions.CreateAsync(new(Tenant(c), target.EndpointId, target.AgentId, target.AgentInstallationId, Actor(c), request), ct);
        return Results.Accepted($"/api/v1/response-actions/{action.ResponseActionId:D}", new ApiEnvelope<object>(new { action, parameterHash = ResponseSafety.ParameterHash(parameters), reason }, new(c.TraceIdentifier, "1.0")));
    }

    static async Task<(ResponseActionRecord? Action, PersistenceRemediationRecord? Record)> FindBackup(Guid id, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct);
        var action = page.Items.Where(x => TryRecord(x, out var record) && record.BackupId == id).OrderByDescending(x => x.CompletedAt).FirstOrDefault();
        return action is not null && TryRecord(action, out var found) ? (action, found) : (null, null);
    }

    static async Task<IResult> ListBackups(Guid? endpointId, HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), endpointId, null, 200, null, ct);
        var records = page.Items.Where(x => TryRecord(x, out var r) && r.Backup is not null).Select(x => { _ = TryRecord(x, out var r); return new { backup = r.Backup, action = x }; }).GroupBy(x => x.backup!.BackupId).Select(x => x.OrderByDescending(v => v.action.CompletedAt).First()).ToArray();
        return Ok(c, new { items = records, count = records.Length });
    }
    static async Task<IResult> GetBackup(Guid id, HttpContext c, IResponseActionRepository actions, CancellationToken ct) { var value = await FindBackup(id, c, actions, ct); return value.Action is null ? Results.NotFound() : Ok(c, new { backup = value.Record!.Backup, action = value.Action }); }
    static async Task<IResult> History(Guid endpoint, HttpContext c, IResponseActionRepository actions, CancellationToken ct) { var page = await actions.SearchAsync(Tenant(c), endpoint, null, 200, null, ct); return Ok(c, page with { Items = page.Items.Where(x => PersistenceResponseSafety.IsAction(x.ActionType)).ToArray() }); }

    static async Task<IResult> Health(HttpContext c, IResponseActionRepository actions, CancellationToken ct)
    {
        var page = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct); var values = page.Items.Where(x => PersistenceResponseSafety.IsAction(x.ActionType)).ToArray();
        var records = values.Where(x => TryRecord(x, out _)).Select(x => { _ = TryRecord(x, out var r); return r; }).ToArray();
        return Ok(c, new { schemaVersion = "persistence-remediation-health.v1", requested = values.LongLength, succeeded = values.LongCount(x => x.State == ResponseActionState.Succeeded), failed = values.LongCount(x => x.State == ResponseActionState.Failed), partial = records.LongCount(x => x.State == PersistenceRemediationState.Partial), protectedRejections = records.LongCount(x => x.State == PersistenceRemediationState.Protected), identityMismatches = records.LongCount(x => x.State == PersistenceRemediationState.TargetIdentityMismatch), sharedDependencyRejections = records.LongCount(x => x.State == PersistenceRemediationState.SharedDependency), restoreConflicts = records.LongCount(x => x.State == PersistenceRemediationState.DestinationOccupied), queueDepth = values.LongCount(x => !ResponseSafety.IsTerminal(x.State)), restoreEligibleBackups = records.LongCount(x => x.Backup?.RestoreEligible == true), storeMaximumBytes = PersistenceResponseSafety.MaximumStoreBytes, storeMaximumRecords = PersistenceResponseSafety.MaximumStoreRecords, updatedAt = DateTimeOffset.UtcNow });
    }

    static async Task<IResult> Approve(Guid id, ResponseApprovalRequest input, HttpContext c, IResponseActionRepository actions, CancellationToken ct) { var action = await actions.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound(); if (!PersistenceResponseSafety.IsAction(action.ActionType)) return Problem(c, "PERSISTENCE_RESPONSE_ACTION_REQUIRED", "The action is not persistence remediation."); return Ok(c, await actions.ApproveAsync(Tenant(c), id, Actor(c), input, ct)); }
    static async Task<IResult> Cancel(Guid id, ResponseCancelRequest input, HttpContext c, IResponseActionRepository actions, CancellationToken ct) { var action = await actions.GetAsync(Tenant(c), id, ct); if (action is null) return Results.NotFound(); if (!PersistenceResponseSafety.IsAction(action.ActionType)) return Problem(c, "PERSISTENCE_RESPONSE_ACTION_REQUIRED", "The action is not persistence remediation."); return Ok(c, await actions.CancelAsync(Tenant(c), id, Actor(c), input, ct)); }
    static bool TryRecord(ResponseActionRecord action, out PersistenceRemediationRecord record) { record = null!; try { record = action.Result!.StructuredResult.Deserialize<PersistenceRemediationRecord>(Json)!; return record is not null && record.TenantId == action.TenantId && record.EndpointId == action.EndpointId && record.AgentInstallationId == action.AgentInstallationId; } catch (Exception ex) when (ex is JsonException or InvalidOperationException or NullReferenceException) { return false; } }
    static async Task<bool> ContextValid(Guid? alert, Guid? incident, string tenant, IAlertIncidentRepository triage, CancellationToken ct) => (alert is null || await triage.GetAlertAsync(tenant, alert.Value, ct) is not null) && (incident is null || await triage.GetIncidentAsync(tenant, incident.Value, ct) is not null);
}
