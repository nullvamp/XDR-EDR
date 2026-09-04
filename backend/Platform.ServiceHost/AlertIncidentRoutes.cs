using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class AlertIncidentRoutes
{
    sealed record AssignmentRequest(string? Assignee, string? Team, string Reason = "assignment");
    sealed record StatusRequest(AlertStatus Status, string Reason = "status change");
    sealed record IncidentStatusRequest(IncidentStatus Status, string Reason = "status change");
    sealed record DispositionRequest(AlertDisposition Disposition, string Reason);
    sealed record NoteRequest(AnalystNoteKind Kind, string Content);
    sealed record BulkRequest(Guid[] AlertIds, AlertMutation Mutation);
    sealed record LinkRequest(Guid[] AlertIds, string Reason);
    sealed record MergeRequest(Guid SourceIncidentId, string Reason);
    sealed record SplitRequest(Guid[] AlertIds, string Title, string Reason);
    sealed record ExportRequest(string Format, Guid ObjectId, int MaximumRecords = 500);
    sealed record AutoGroupRequest(Guid[] AlertIds, string Policy = "strong-evidence.v1");
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok(HttpContext c, object value) => Results.Ok(new ApiEnvelope<object>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail) => Results.Problem(statusCode: 400, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["code"] = code, ["traceId"] = c.TraceIdentifier });

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/alerts", Alerts).RequirePermission("alert:read");
        app.MapGet("/api/v1/alerts/{id:guid}", Alert).RequirePermission("alert:read");
        app.MapGet("/api/v1/alerts/{id:guid}/timeline", AlertTimeline).RequirePermission("alert:read");
        app.MapGet("/api/v1/alerts/{id:guid}/evidence", AlertEvidence).RequirePermission("alert:read");
        app.MapGet("/api/v1/alerts/{id:guid}/pivots", AlertPivots).RequirePermission("alert:read");
        app.MapPost("/api/v1/alerts/{id:guid}:assign", AssignAlert).RequirePermission("alert:assign");
        app.MapPost("/api/v1/alerts/{id:guid}:acknowledge", Acknowledge).RequirePermission("alert:acknowledge");
        app.MapPost("/api/v1/alerts/{id:guid}:status", AlertStatusChange).RequirePermission("alert:status:change");
        app.MapPost("/api/v1/alerts/{id:guid}:disposition", AlertDispositionChange).RequirePermission("alert:disposition:set");
        app.MapPost("/api/v1/alerts/{id:guid}/comments", AddAlertComment).RequirePermission("alert:notes:add");
        app.MapPost("/api/v1/alerts/{id:guid}:close", CloseAlert).RequirePermission("alert:close");
        app.MapPost("/api/v1/alerts/{id:guid}:reopen", ReopenAlert).RequirePermission("alert:reopen");
        app.MapPost("/api/v1/alerts:bulk", BulkAlerts).RequirePermission("alert:status:change");
        app.MapGet("/api/v1/triage-queue", Alerts).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-queue/assigned-to-me", AssignedToMe).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-queue/unassigned", Unassigned).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-queue/high-priority", HighPriority).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-queue/aging", Aging).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-queue/recent", Recent).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-filters", Filters).RequirePermission("alert:read");
        app.MapPost("/api/v1/triage-filters", SaveFilter).RequirePermission("alert:read");
        app.MapGet("/api/v1/triage-assignees", Assignees).RequirePermission("alert:assign");

        app.MapGet("/api/v1/incidents", Incidents).RequirePermission("incident:read");
        app.MapGet("/api/v1/incidents/{id:guid}", Incident).RequirePermission("incident:read");
        app.MapPost("/api/v1/incidents", CreateIncident).RequirePermission("incident:create");
        app.MapPost("/api/v1/incidents:auto-group", AutoGroup).RequirePermission("incident:create");
        app.MapPost("/api/v1/incidents/{id:guid}:update", UpdateIncident).RequirePermission("incident:modify");
        app.MapGet("/api/v1/incidents/{id:guid}/timeline", IncidentTimeline).RequirePermission("incident:read");
        app.MapGet("/api/v1/incidents/{id:guid}/pivots", IncidentPivots).RequirePermission("incident:read");
        app.MapPost("/api/v1/incidents/{id:guid}:assign", AssignIncident).RequirePermission("incident:assign");
        app.MapPost("/api/v1/incidents/{id:guid}:status", IncidentStatusChange).RequirePermission("incident:modify");
        app.MapPost("/api/v1/incidents/{id:guid}:disposition", IncidentDispositionChange).RequirePermission("incident:modify");
        app.MapPost("/api/v1/incidents/{id:guid}/alerts", LinkAlerts).RequirePermission("incident:alerts:link");
        app.MapPost("/api/v1/incidents/{id:guid}:remove-alerts", UnlinkAlerts).RequirePermission("incident:alerts:link");
        app.MapPost("/api/v1/incidents/{id:guid}:merge", MergeIncidents).RequirePermission("incident:merge");
        app.MapPost("/api/v1/incidents/{id:guid}:split", SplitIncident).RequirePermission("incident:split");
        app.MapPost("/api/v1/incidents/{id:guid}/comments", AddIncidentComment).RequirePermission("incident:modify");
        app.MapPost("/api/v1/incidents/{id:guid}:close", CloseIncident).RequirePermission("incident:close");
        app.MapPost("/api/v1/incidents/{id:guid}:reopen", ReopenIncident).RequirePermission("incident:reopen");

        app.MapPost("/api/v1/alert-exports", ExportAlert).RequirePermission("alert:export");
        app.MapPost("/api/v1/incident-exports", ExportIncident).RequirePermission("incident:export");
        app.MapGet("/api/v1/triage-exports/{id:guid}/manifest", ExportManifest).RequirePermission("alert:export");
        app.MapGet("/api/v1/triage-exports/{id:guid}/content", ExportContent).RequirePermission("alert:export");
        app.MapGet("/api/v1/triage-exports/{id:guid}/url", ExportUrl).RequirePermission("alert:export");
        app.MapGet("/api/v1/triage-exports/{id:guid}/download", ExportDownload);
        app.MapGet("/api/v1/triage-health", Health).RequirePermission("triage:audit:read");
        app.MapPost("/internal/v1/alerts/from-finding/{id:guid}", AlertFromFinding).RequirePermission("system:admin");
        app.MapPost("/internal/v1/alerts/from-correlated-finding/{id:guid}", AlertFromCorrelation).RequirePermission("system:admin");
        app.MapPost("/internal/v1/triage:seed-controlled", Seed).RequirePermission("system:admin");
    }

    static AlertQuery AlertQueryFrom(HttpContext c, string? assigneeOverride = null, int? priorityOverride = null, string? sortOverride = null)
    {
        var q = c.Request.Query; return new(int.TryParse(q["severity"], out var sev) ? sev : null, priorityOverride ?? (int.TryParse(q["priority"], out var pri) ? pri : null), Enum.TryParse<AlertStatus>(q["status"], true, out var status) ? status : null, Enum.TryParse<AlertDisposition>(q["disposition"], true, out var disposition) ? disposition : null, assigneeOverride ?? q["assignee"], q["team"], Guid.TryParse(q["endpointId"], out var endpoint) ? endpoint : null, q["user"], Guid.TryParse(q["ruleId"], out var rule) ? rule : null, q["mitreTechnique"], q["evidenceQuality"], DateTimeOffset.TryParse(q["from"], out var from) ? from : null, DateTimeOffset.TryParse(q["to"], out var to) ? to : null, sortOverride ?? (q["sort"].Count == 0 ? "updated-desc" : q["sort"].ToString()), int.TryParse(q["pageSize"], out var size) ? size : 100, q["cursor"]);
    }
    static async Task<IResult> Alerts(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchAlertsAsync(Tenant(c), AlertQueryFrom(c), ct));
    static async Task<IResult> AssignedToMe(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchAlertsAsync(Tenant(c), AlertQueryFrom(c, Actor(c)), ct));
    static async Task<IResult> Unassigned(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchAlertsAsync(Tenant(c), AlertQueryFrom(c) with { Unassigned = true }, ct));
    static async Task<IResult> HighPriority(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchAlertsAsync(Tenant(c), AlertQueryFrom(c) with { MinimumPriority = 4 }, ct));
    static async Task<IResult> Aging(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchAlertsAsync(Tenant(c), AlertQueryFrom(c, sortOverride: "age-desc"), ct));
    static async Task<IResult> Recent(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchAlertsAsync(Tenant(c), AlertQueryFrom(c, sortOverride: "updated-desc"), ct));
    static async Task<IResult> Alert(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => await r.GetAlertAsync(Tenant(c), id, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> AlertTimeline(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => await r.GetAlertAsync(Tenant(c), id, ct) is null ? Results.NotFound() : Ok(c, await r.AlertAuditAsync(Tenant(c), id, ct));
    static async Task<IResult> AlertEvidence(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => await r.GetAlertAsync(Tenant(c), id, ct) is { } x ? Ok(c, x.Evidence) : Results.NotFound();
    static async Task<IResult> AlertPivots(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct)
    {
        var x = await r.GetAlertAsync(Tenant(c), id, ct); if (x is null) return Results.NotFound(); var process = x.Evidence.ProcessEntities.FirstOrDefault(); return Ok(c, new { endpoint = x.Evidence.EndpointIds.FirstOrDefault() is var endpoint && endpoint != Guid.Empty ? $"/api/v1/endpoints/{endpoint:D}" : null, processTree = process is null ? null : $"/api/v1/process-trees/{Uri.EscapeDataString(process)}", entityGraph = process is null ? null : new { endpoint = "/api/v1/entity-graph:query", rootEntityId = process }, attackStory = process is null ? null : $"/api/v1/attack-stories/{Uri.EscapeDataString(process)}", rawEvents = x.Evidence.EvidenceReferences, detectionRule = x.SourceFindingId is null ? null : $"/api/v1/detection-rules/{x.RuleId:D}?version={x.RuleVersion}", correlatedFinding = x.SourceCorrelatedFindingId is { } cf ? $"/api/v1/correlated-findings/{cf:D}" : null, threatHunt = process is null ? null : new { endpoint = "/api/v1/threat-hunts:execute", processEntityId = process } });
    }
    static async Task<IResult> AssignAlert(Guid id, AssignmentRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateAlertAsync(Tenant(c), id, Actor(c), new(Assignee: input.Assignee, Team: input.Team, Reason: input.Reason), ct));
    static async Task<IResult> Acknowledge(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateAlertAsync(Tenant(c), id, Actor(c), new(Status: AlertStatus.Acknowledged, Reason: "acknowledged"), ct));
    static async Task<IResult> AlertStatusChange(Guid id, StatusRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateAlertAsync(Tenant(c), id, Actor(c), new(Status: input.Status, Reason: input.Reason), ct));
    static async Task<IResult> AlertDispositionChange(Guid id, DispositionRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateAlertAsync(Tenant(c), id, Actor(c), new(Disposition: input.Disposition, Reason: input.Reason), ct));
    static async Task<IResult> AddAlertComment(Guid id, NoteRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.AddAlertNoteAsync(Tenant(c), id, Actor(c), input.Kind, input.Content, ct));
    static async Task<IResult> CloseAlert(Guid id, DispositionRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateAlertAsync(Tenant(c), id, Actor(c), new(Status: AlertStatus.Closed, Disposition: input.Disposition, Reason: input.Reason), ct));
    static async Task<IResult> ReopenAlert(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateAlertAsync(Tenant(c), id, Actor(c), new(Status: AlertStatus.Investigating, Reason: "reopened"), ct));
    static async Task<IResult> BulkAlerts(BulkRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.BulkMutateAlertsAsync(Tenant(c), Actor(c), input.AlertIds, input.Mutation, ct));
    static async Task<IResult> SaveFilter(SavedTriageFilter input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SaveFilterAsync(Tenant(c), Actor(c), input, ct));
    static async Task<IResult> Filters(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.FiltersAsync(Tenant(c), Actor(c), ct));
    static async Task<IResult> Assignees(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) { var page = await r.SearchAlertsAsync(Tenant(c), new(PageSize: 100), ct); return Ok(c, new { assignees = page.Items.Select(x => x.Assignee).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).Order().ToArray(), teams = page.Items.Select(x => x.Team).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).Order().ToArray(), source = "tenant-alert-assignments", truncated = page.Total > page.Items.Count }); }

    static IncidentQuery IncidentQueryFrom(HttpContext c) { var q = c.Request.Query; return new(Enum.TryParse<IncidentStatus>(q["status"], true, out var status) ? status : null, q["assignee"], q["team"], int.TryParse(q["priority"], out var p) ? p : null, int.TryParse(q["pageSize"], out var n) ? n : 100, q["cursor"]); }
    static async Task<IResult> Incidents(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SearchIncidentsAsync(Tenant(c), IncidentQueryFrom(c), ct));
    static async Task<IResult> Incident(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => await r.GetIncidentAsync(Tenant(c), id, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> CreateIncident(IncidentCreate input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) { var x = await r.CreateIncidentAsync(Tenant(c), Actor(c), input, ct); return Results.Created($"/api/v1/incidents/{x.IncidentId:D}", new ApiEnvelope<object>(x, new(c.TraceIdentifier, "1.0"))); }
    static async Task<IResult> AutoGroup(AutoGroupRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct)
    {
        if (input.Policy != "strong-evidence.v1") return Problem(c, "GROUPING_POLICY_INVALID", "Only the bounded strong-evidence.v1 policy is available."); if (input.AlertIds.Length is < 2 or > 100) return Problem(c, "GROUPING_BOUNDS", "Automatic grouping requires 2-100 alerts."); var alerts = new List<AlertRecord>(); foreach (var id in input.AlertIds.Distinct()) { var alert = await r.GetAlertAsync(Tenant(c), id, ct); if (alert is null) return Problem(c, "GROUPING_ALERT_INVALID", "Every grouped alert must exist in the same tenant."); alerts.Add(alert); }
        string? reason = null; var endpoint = alerts.SelectMany(x => x.Evidence.EndpointIds).GroupBy(x => x).FirstOrDefault(x => x.Count() == alerts.Count)?.Key; if (endpoint is not null) reason = $"same-endpoint:{endpoint:D};window=60m"; var process = alerts.SelectMany(x => x.Evidence.ProcessEntities).GroupBy(x => x).FirstOrDefault(x => x.Count() == alerts.Count)?.Key; if (process is not null) reason = $"same-process-tree:{process};window=60m"; var correlation = alerts.SelectMany(x => x.Evidence.CorrelatedFindingIds).GroupBy(x => x).FirstOrDefault(x => x.Count() == alerts.Count)?.Key; if (correlation is not null) reason = $"same-correlated-finding:{correlation:D};window=60m"; if (reason is null || alerts.Max(x => x.LastSeen) - alerts.Min(x => x.FirstSeen) > TimeSpan.FromHours(1)) return Problem(c, "GROUPING_EVIDENCE_INSUFFICIENT", "Automatic grouping requires shared strong evidence within one hour."); return Ok(c, await r.CreateIncidentAsync(Tenant(c), Actor(c), new($"Grouped incident: {alerts[0].Title}", $"Deterministic grouping of {alerts.Count} alerts", alerts.Select(x => x.AlertId).ToArray(), GroupingReason: reason), ct));
    }
    static async Task<IResult> UpdateIncident(Guid id, IncidentMutation input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateIncidentAsync(Tenant(c), id, Actor(c), input, ct));
    static async Task<IResult> AssignIncident(Guid id, AssignmentRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateIncidentAsync(Tenant(c), id, Actor(c), new(Assignee: input.Assignee, Team: input.Team, Reason: input.Reason), ct));
    static async Task<IResult> IncidentStatusChange(Guid id, IncidentStatusRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateIncidentAsync(Tenant(c), id, Actor(c), new(Status: input.Status, Reason: input.Reason), ct));
    static async Task<IResult> IncidentDispositionChange(Guid id, DispositionRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateIncidentAsync(Tenant(c), id, Actor(c), new(Disposition: input.Disposition, Reason: input.Reason), ct));
    static async Task<IResult> LinkAlerts(Guid id, LinkRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.LinkAlertsAsync(Tenant(c), id, Actor(c), input.AlertIds, false, input.Reason, ct));
    static async Task<IResult> UnlinkAlerts(Guid id, LinkRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.LinkAlertsAsync(Tenant(c), id, Actor(c), input.AlertIds, true, input.Reason, ct));
    static async Task<IResult> MergeIncidents(Guid id, MergeRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MergeIncidentsAsync(Tenant(c), id, input.SourceIncidentId, Actor(c), input.Reason, ct));
    static async Task<IResult> SplitIncident(Guid id, SplitRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.SplitIncidentAsync(Tenant(c), id, Actor(c), input.AlertIds, input.Title, input.Reason, ct));
    static async Task<IResult> AddIncidentComment(Guid id, NoteRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.AddIncidentNoteAsync(Tenant(c), id, Actor(c), input.Kind, input.Content, ct));
    static async Task<IResult> CloseIncident(Guid id, DispositionRequest input, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateIncidentAsync(Tenant(c), id, Actor(c), new(Status: IncidentStatus.Closed, Disposition: input.Disposition, Reason: input.Reason), ct));
    static async Task<IResult> ReopenIncident(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.MutateIncidentAsync(Tenant(c), id, Actor(c), new(Status: IncidentStatus.Investigating, Reason: "reopened"), ct));
    static async Task<IResult> IncidentTimeline(Guid id, HttpContext c, IAlertIncidentRepository r, IResponseActionRepository actions, IPlaybookRepository playbooks, CancellationToken ct) { var incident = await r.GetIncidentAsync(Tenant(c), id, ct); if (incident is null) return Results.NotFound(); var alerts = new List<object>(); foreach (var alertId in incident.AlertIds) if (await r.GetAlertAsync(Tenant(c), alertId, ct) is { } alert) alerts.Add(new { alert.AlertId, alert.FirstSeen, alert.LastSeen, alert.Title, alert.Evidence.EvidenceReferences, alert.AuditHistory }); var response = await actions.SearchAsync(Tenant(c), null, null, 200, null, ct); var executions = await playbooks.ExecutionsAsync(Tenant(c), "incident", id.ToString("D"), ct); return Ok(c, new { incident.AuditHistory, alerts, responseActions = response.Items.Where(x => x.SourceIncidentId == id).SelectMany(x => x.AuditHistory).OrderBy(x => x.OccurredAt).ToArray(), playbookEvents = executions.SelectMany(x => x.AuditHistory).OrderBy(x => x.OccurredAt).ToArray() }); }
    static async Task<IResult> IncidentPivots(Guid id, HttpContext c, IAlertIncidentRepository r, CancellationToken ct) { var incident = await r.GetIncidentAsync(Tenant(c), id, ct); if (incident is null) return Results.NotFound(); return Ok(c, new { incident.EndpointIds, incident.Users, processTrees = incident.ProcessEntities.Select(x => $"/api/v1/process-trees/{Uri.EscapeDataString(x)}"), attackStories = incident.ProcessEntities.Select(x => $"/api/v1/attack-stories/{Uri.EscapeDataString(x)}"), entityGraph = new { endpoint = "/api/v1/entity-graph:query", roots = incident.ProcessEntities }, findings = incident.AlertIds.Select(x => $"/api/v1/alerts/{x:D}"), threatHunt = new { endpoint = "/api/v1/threat-hunts:execute", roots = incident.ProcessEntities } }); }

    static async Task<IResult> AlertFromFinding(Guid id, HttpContext c, IDetectionRepository detections, IAlertIncidentRepository alerts, CancellationToken ct) { var finding = await detections.GetFindingAsync(Tenant(c), id, ct); if (finding is null) return Results.NotFound(); var rule = await detections.GetRuleAsync(Tenant(c), finding.DetectionId, finding.DetectionVersion, ct); if (rule is null) return Results.NotFound(); return await alerts.CreateAlertAsync(Tenant(c), Actor(c), AlertIncidentSafety.FromDetection(finding, rule), ct) is { } alert ? Ok(c, alert) : Problem(c, "FINDING_NOT_PRODUCTION", "Simulation, replay, dry-run and excluded findings require explicit authorized promotion."); }
    static async Task<IResult> AlertFromCorrelation(Guid id, HttpContext c, ICorrelationRepository correlations, IAlertIncidentRepository alerts, CancellationToken ct) { var finding = await correlations.GetFindingAsync(Tenant(c), id, ct); if (finding is null) return Results.NotFound(); return await alerts.CreateAlertAsync(Tenant(c), Actor(c), AlertIncidentSafety.FromCorrelation(finding), ct) is { } alert ? Ok(c, alert) : Problem(c, "FINDING_NOT_PRODUCTION", "Simulation, replay, dry-run and excluded findings require explicit authorized promotion."); }
    static async Task<IResult> Health(HttpContext c, IAlertIncidentRepository r, CancellationToken ct) => Ok(c, await r.HealthAsync(Tenant(c), ct));

    static async Task<IResult> Seed(HttpContext c, IAlertIncidentRepository r, CancellationToken ct)
    {
        var tenant = Tenant(c); var actor = Actor(c); var runKey = c.Request.Query["run"].FirstOrDefault() ?? "default";
        if (runKey.Length is < 1 or > 64 || runKey.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch != '-')) return Problem(c, "CONTROL_RUN_INVALID", "Controlled run identifiers must be 1-64 ASCII letters, digits, or hyphens.");
        var endpoint = InvestigationSafety.StableId(tenant, "sprint15-endpoint", runKey); var at = DateTimeOffset.UtcNow.AddMinutes(-5); AlertCandidate Candidate(int source, string process, int severity = 80) { var sourceText = $"{runKey}-{source.ToString(System.Globalization.CultureInfo.InvariantCulture)}"; var id = InvestigationSafety.StableId(tenant, "sprint15-finding", sourceText); var evidence = InvestigationSafety.StableId(tenant, "sprint15-evidence", sourceText); return new(tenant, AlertSourceType.DetectionFinding, id, id, null, Guid.Parse("15151515-0000-0000-0000-000000000001"), 1, 0, "Controlled suspicious process", "Sprint 15 controlled evidence", severity, 90, "execution", ["Execution"], ["T1204.002"], ["Process"], at.AddSeconds(source), at.AddSeconds(source), endpoint, process, process, $"controlled-group-{runKey}", new([endpoint], [process], ["S-1-5-18"], ["C:\\Sprint15Fixtures\\payload.exe"], ["192.0.2.15:443", "sprint15.test"], [], [evidence], [$"postgresql://platform/sprint15_controlled/{runKey}/{evidence:D}"], [id], [], [InvestigationSafety.StableId(tenant, "sprint15-story", runKey)], ["complete"], []), DetectionExecutionMode.Live, true); }
        var first = await r.CreateAlertAsync(tenant, actor, Candidate(1, $"sprint15-process-root-{runKey}"), ct); var duplicate = await r.CreateAlertAsync(tenant, actor, Candidate(2, $"sprint15-process-root-{runKey}"), ct); var related = await r.CreateAlertAsync(tenant, actor, Candidate(3, $"sprint15-process-child-{runKey}", 70) with { CorrelationKey = $"related-control-{runKey}" }, ct); return Ok(c, new { runKey, first, duplicate, related, endpoint, deduplicated = first?.AlertId == duplicate?.AlertId, exactEvidence = duplicate?.Evidence.EvidenceReferences.Length == 2 });
    }

    static Task<IResult> ExportAlert(ExportRequest input, HttpContext c, IAlertIncidentRepository r, IObjectStorage s, CancellationToken ct) => Export("alert", input, c, r, s, ct);
    static Task<IResult> ExportIncident(ExportRequest input, HttpContext c, IAlertIncidentRepository r, IObjectStorage s, CancellationToken ct) => Export("incident", input, c, r, s, ct);
    static async Task<IResult> Export(string type, ExportRequest input, HttpContext c, IAlertIncidentRepository r, IObjectStorage storage, CancellationToken ct)
    {
        if (input.Format is not ("jsonl" or "csv") || input.MaximumRecords is < 1 or > 1000) return Problem(c, "EXPORT_BOUNDS", "Export supports JSONL/CSV and 1-1,000 records."); object value = type == "alert" ? await r.GetAlertAsync(Tenant(c), input.ObjectId, ct) ?? throw new KeyNotFoundException() : await r.GetIncidentAsync(Tenant(c), input.ObjectId, ct) ?? throw new KeyNotFoundException(); var json = JsonSerializer.Serialize(value); static string Csv(string value) { var safe = value.Length > 0 && "=+-@\t\r".Contains(value[0]) ? "'" + value : value; return '"' + safe.Replace("\"", "\"\"") + '"'; }
        var content = input.Format == "jsonl" ? Encoding.UTF8.GetBytes(json + "\n") : Encoding.UTF8.GetBytes("objectType,objectId,payload\r\n" + string.Join(',', Csv(type), Csv(input.ObjectId.ToString("D")), Csv(json)) + "\r\n"); var hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(); var id = Guid.NewGuid(); var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "triage-export-manifest.v1", exportId = id, tenantBinding = Tenant(c), objectType = type, input.ObjectId, input.Format, sha256 = hash, evidenceReferencesIncluded = true, lifecycleIncluded = true, auditIncluded = true, createdAt = DateTimeOffset.UtcNow }); await Put(storage, Tenant(c), id, content, input.Format == "csv" ? "text/csv" : "application/x-ndjson", ct); await Put(storage, Tenant(c), Manifest(id), manifest, "application/json", ct); await r.RecordExportAuditAsync(Tenant(c), type, input.ObjectId, id, Actor(c), ct); return Results.Created($"/api/v1/triage-exports/{id:D}", new ApiEnvelope<object>(new { id, state = "Completed", sha256 = hash, input.Format }, new(c.TraceIdentifier, "1.0")));
    }
    static async Task<IResult> ExportManifest(Guid id, HttpContext c, IObjectStorage s, CancellationToken ct) => await s.HeadAsync(Tenant(c), Manifest(id).ToString("D"), ct) is null ? Results.NotFound() : Results.Stream(await s.DownloadAsync(Tenant(c), Manifest(id).ToString("D"), ct), "application/json");
    static async Task<IResult> ExportContent(Guid id, HttpContext c, IObjectStorage s, CancellationToken ct) => await s.HeadAsync(Tenant(c), id.ToString("D"), ct) is { } m ? Results.Stream(await s.DownloadAsync(Tenant(c), id.ToString("D"), ct), m.MediaType) : Results.NotFound();
    static async Task<IResult> ExportUrl(Guid id, HttpContext c, IObjectStorage s, PlatformOptions o, CancellationToken ct) { if (await s.HeadAsync(Tenant(c), id.ToString("D"), ct) is null) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddMinutes(5); return Ok(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/triage-exports/{id:D}/download?token={Uri.EscapeDataString(FileExportDownloadToken.Create(Tenant(c), id, expires, o.JwtSigningKey))}", expiresAt = expires }); }
    static async Task<IResult> ExportDownload(Guid id, string token, IObjectStorage s, PlatformOptions o, CancellationToken ct) { if (!FileExportDownloadToken.TryValidate(token, o.JwtSigningKey, out var tenant, out var target) || target != id || await s.HeadAsync(tenant, id.ToString("D"), ct) is not { } m) return Results.NotFound(); return Results.Stream(await s.DownloadAsync(tenant, id.ToString("D"), ct), m.MediaType); }
    static async Task Put(IObjectStorage s, string tenant, Guid id, byte[] bytes, string media, CancellationToken ct) { await using var stream = new MemoryStream(bytes); await s.UploadAsync(tenant, id.ToString("D"), stream, media, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), ct); }
    static Guid Manifest(Guid id) => InvestigationSafety.StableId("triage-export-manifest", id.ToString("D"));
}
