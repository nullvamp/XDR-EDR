using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class DetectionRoutes
{
    sealed record AssignRequest(int Version, Guid? EndpointId, Guid? EndpointGroupId, bool Enabled = true);
    sealed record SimulationRequest(Guid DetectionId, int Version, DetectionEvidenceEvent[] Events);
    sealed record LiveRequest(DetectionEvidenceEvent Event, bool ProductionFindings = true, DetectionExecutionMode Mode = DetectionExecutionMode.Live);
    sealed record ReplayRequest(Guid DetectionId, int Version, DateTimeOffset From, DateTimeOffset To, bool ProductionFindings = false, DetectionEvidenceEvent[]? ControlledFixtureEvents = null);
    sealed record FindingExportRequest(string Format, DetectionFindingQuery Query, int MaximumRecords = 10_000);

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/detection-rules", List).RequirePermission("detection:read");
        app.MapPost("/api/v1/detection-rules", Create).RequirePermission("detection:draft:manage");
        app.MapGet("/api/v1/detection-rules/{id:guid}", Get).RequirePermission("detection:read");
        app.MapGet("/api/v1/detection-rules/{id:guid}/versions", History).RequirePermission("detection:read");
        app.MapPost("/api/v1/detection-rules/{id:guid}/versions", Version).RequirePermission("detection:draft:manage");
        app.MapPost("/api/v1/detection-rule-versions/{id:guid}/{version:int}:validate", Validate).RequirePermission("detection:draft:manage");
        app.MapPost("/api/v1/detection-rule-versions/{id:guid}/{version:int}:test", Test).RequirePermission("detection:draft:manage");
        app.MapGet("/api/v1/detection-rule-versions/{id:guid}/{version:int}/tests", Tests).RequirePermission("detection:read");
        app.MapPost("/api/v1/detection-rule-versions/{id:guid}/{version:int}:activate", Activate).RequirePermission("detection:activate");
        app.MapPost("/api/v1/detection-rules/{id:guid}:disable", Disable).RequirePermission("detection:deactivate");
        app.MapPost("/api/v1/detection-rules/{id:guid}:rollback", Rollback).RequirePermission("detection:activate");
        app.MapPost("/api/v1/detection-rules/{id:guid}:assign", Assign).RequirePermission("detection:assignment:manage");
        app.MapPost("/api/v1/detection-simulations", Simulate).RequirePermission("detection:simulation:run");
        app.MapPost("/internal/v1/detection-events:evaluate", Live).RequirePermission("system:admin");
        app.MapPost("/internal/v1/detection-starter-fixtures:seed", SeedStarters).RequirePermission("system:admin");
        app.MapPost("/internal/v1/detection-production-pack:seed", SeedProduction).RequirePermission("system:admin");
        app.MapGet("/api/v1/detection-content/catalog", ContentCatalog).RequirePermission("detection:read");
        app.MapGet("/api/v1/detection-content/coverage", ContentCoverage).RequirePermission("detection:read");
        app.MapGet("/api/v1/detection-content/gaps", ContentGaps).RequirePermission("detection:read");
        app.MapPost("/api/v1/detection-replays", Replay).RequirePermission("detection:replay:run");
        app.MapGet("/api/v1/detection-replays/{id:guid}", ReplayStatus).RequirePermission("detection:replay:run");
        app.MapPost("/api/v1/detection-replays/{id:guid}:cancel", ReplayCancel).RequirePermission("detection:replay:run");
        app.MapGet("/api/v1/detection-replays/{id:guid}/results", ReplayResults).RequirePermission("finding:read");
        app.MapGet("/api/v1/findings", Findings).RequirePermission("finding:read");
        app.MapGet("/api/v1/findings/{id:guid}", Finding).RequirePermission("finding:read");
        app.MapGet("/api/v1/findings/{id:guid}/evidence", Evidence).RequirePermission("finding:read");
        app.MapGet("/api/v1/findings/{id:guid}/matched-conditions", Conditions).RequirePermission("finding:read");
        app.MapGet("/api/v1/findings/{id:guid}/rule-version", FindingRule).RequirePermission("finding:read");
        app.MapGet("/api/v1/findings/{id:guid}/history", FindingHistory).RequirePermission("finding:read");
        app.MapGet("/api/v1/detection-health", Health).RequirePermission("detection:health:read");
        app.MapGet("/api/v1/detection-rules/{id:guid}/health", RuleHealth).RequirePermission("detection:health:read");
        app.MapGet("/api/v1/detection-replay-health", ReplayHealth).RequirePermission("detection:health:read");
        app.MapPost("/api/v1/finding-exports", CreateExport).RequirePermission("finding:export");
        app.MapGet("/api/v1/finding-exports/{id:guid}/manifest", ExportManifest).RequirePermission("finding:export");
        app.MapGet("/api/v1/finding-exports/{id:guid}/content", ExportContent).RequirePermission("finding:export");
        app.MapPost("/api/v1/finding-exports/{id:guid}/download-url", ExportUrl).RequirePermission("finding:export");
        app.MapGet("/api/v1/finding-exports/{id:guid}/download", ExportDownload);
        app.MapGet("/api/v1/detection-exclusions", Exclusions).RequirePermission("detection:exclusion:manage");
        app.MapPost("/api/v1/detection-exclusions", CreateExclusion).RequirePermission("detection:exclusion:manage");
    }

    static async Task<IResult> List(HttpContext c, IDetectionRepository r, CancellationToken ct) => Ok(c, await r.ListRulesAsync(Tenant(c), ct));
    static async Task<IResult> Get(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => await r.GetRuleAsync(Tenant(c), id, null, ct) is { } value ? Ok(c, value) : Results.NotFound();
    static async Task<IResult> History(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => Ok(c, await r.RuleHistoryAsync(Tenant(c), id, ct));
    static async Task<IResult> Create(DetectionDefinition input, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var value = await r.CreateRuleAsync(Tenant(c), Actor(c), input, ct); return Results.Created($"/api/v1/detection-rules/{value.DetectionId}", Envelope(c, value));
    }
    static async Task<IResult> Version(Guid id, DetectionDefinition input, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        try { var value = await r.CreateVersionAsync(Tenant(c), Actor(c), id, input, ct); return Results.Created($"/api/v1/detection-rules/{id}/versions/{value.DetectionVersion}", Envelope(c, value)); } catch (KeyNotFoundException) { return Results.NotFound(); }
    }
    static async Task<IResult> Validate(Guid id, int version, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var rule = await r.GetRuleAsync(Tenant(c), id, version, ct); if (rule is null) return Results.NotFound(); var errors = DetectionDsl.Validate(rule with { Status = DetectionRuleStatus.Testing, Enabled = false }); var value = await r.RecordValidationAsync(Tenant(c), id, version, errors, ct); return errors.Count == 0 ? Ok(c, new { valid = true, rule = value, errors }) : Results.ValidationProblem(errors.ToDictionary());
    }
    static async Task<IResult> Test(Guid id, int version, DetectionRuleTestCase[] fixtures, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var tenant = Tenant(c); var rule = await r.GetRuleAsync(tenant, id, version, ct); if (rule is null) return Results.NotFound(); if (fixtures.Length is < 1 or > 64 || fixtures.Sum(x => x.Events.Length) > 10_000) return Problem(c, "DETECTION_TEST_BOUNDS", "Fixture count or total events exceeds bounded limits.", 400); var exclusions = await r.ListExclusionsAsync(tenant, ct); var results = fixtures.Select(x => (Test: x, Result: RunFixture(rule, x, exclusions))).ToArray(); await r.RecordTestsAsync(tenant, id, version, results, ct); return Ok(c, new { passed = results.All(x => x.Result.Passed), results = results.Select(x => new { x.Test.Name, x.Test.Kind, x.Result }) });
    }
    static DetectionRuleTestResult RunFixture(DetectionDefinition rule, DetectionRuleTestCase fixture, IReadOnlyList<DetectionExclusion> exclusions)
    {
        var matches = new List<DetectionEvidenceEvent>(); var findings = 0; var failures = new List<string>(); DetectionFinding? prior = null;
        foreach (var evidence in fixture.Events.OrderBy(x => x.EventTime).ThenBy(x => x.EventId))
        {
            if (evidence.TenantId != rule.TenantId) continue;
            var result = DetectionDsl.Evaluate(rule, evidence); if (!result.Matched) continue; var excluded = exclusions.Any(x => rule.ExclusionReferences.Contains(x.Id) && DetectionDsl.MatchesExclusion(x, evidence, evidence.EventTime)); if (excluded) continue; matches.Add(evidence); var start = evidence.EventTime.AddSeconds(-Math.Max(1, rule.WindowSeconds)); var window = rule.RuleType == DetectionRuleType.Threshold ? matches.Where(x => x.EventTime >= start && x.EventTime <= evidence.EventTime).ToArray() : [evidence]; var count = rule.DistinctCount ? window.Select(x => x.Fields.GetValueOrDefault(rule.DistinctField!)).Where(x => x is not null).Distinct(StringComparer.Ordinal).Count() : window.Length; if (count != rule.Threshold) continue; var suppressed = prior is not null && rule.Suppression.DurationMinutes > 0 && prior.CreatedAt >= evidence.EventTime.AddMinutes(-rule.Suppression.DurationMinutes); if (!suppressed) findings++; prior = new(Guid.NewGuid(), rule.TenantId, rule.DetectionId, rule.DetectionVersion, rule.Name, rule.Severity, rule.Confidence, window[0].EventTime, window[^1].EventTime, count, result.GroupKey, evidence.EndpointId, evidence.ProcessEntityId, evidence.EntityId, window.Select(x => x.EventId).ToArray(), window.Select(x => x.EvidenceReference).ToArray(), result.Conditions.Where(x => x.Matched).ToArray(), suppressed, suppressed ? "fixture-suppression" : null, null, false, null, DetectionDsl.EngineVersion, DetectionExecutionMode.Simulation, [], [], evidence.EventTime);
        }
        if (findings != fixture.ExpectedFindings) failures.Add($"expected-{fixture.ExpectedFindings}-actual-{findings}"); return new(failures.Count == 0, fixture.ExpectedFindings, findings, failures.ToArray(), DateTimeOffset.UtcNow);
    }
    static async Task<IResult> Tests(Guid id, int version, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var tests = await r.ListTestsAsync(Tenant(c), id, version, ct);
        return Ok(c, tests.Select(x => new { x.Name, x.Kind, x.Result }).ToArray());
    }
    static async Task<IResult> Activate(Guid id, int version, HttpContext c, IDetectionRepository r, CancellationToken ct) { try { return Ok(c, await r.ActivateAsync(Tenant(c), Actor(c), id, version, ct)); } catch (KeyNotFoundException) { return Results.NotFound(); } }
    static async Task<IResult> Disable(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) { try { return Ok(c, await r.DisableAsync(Tenant(c), Actor(c), id, ct)); } catch (KeyNotFoundException) { return Results.NotFound(); } }
    static async Task<IResult> Rollback(Guid id, int version, HttpContext c, IDetectionRepository r, CancellationToken ct) { try { return Ok(c, await r.ActivateAsync(Tenant(c), Actor(c), id, version, ct)); } catch (KeyNotFoundException) { return Results.NotFound(); } }
    static async Task<IResult> Assign(Guid id, AssignRequest input, HttpContext c, IDetectionRepository r, CancellationToken ct) { var value = new DetectionAssignment(Guid.Empty, Tenant(c), id, input.Version, input.EndpointId, input.EndpointGroupId, input.Enabled, default, ""); return Ok(c, await r.AssignAsync(Tenant(c), Actor(c), value, ct)); }
    static async Task<IResult> Simulate(SimulationRequest input, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        if (input.Events.Length is < 1 or > 10_000) return Problem(c, "DETECTION_SIMULATION_BOUNDS", "Simulation requires 1-10,000 events.", 400); var tenant = Tenant(c); var run = Guid.NewGuid(); var results = new List<DetectionEvaluationResult>(); foreach (var evidence in input.Events.OrderBy(x => x.EventTime).ThenBy(x => x.EventId)) results.Add(await r.EvaluateAsync(tenant, evidence, DetectionExecutionMode.Simulation, input.DetectionId, input.Version, run, false, ct)); return Ok(c, new { runId = run, mode = DetectionExecutionMode.Simulation, productionFindings = false, eventsEvaluated = input.Events.Length, matches = results.Count(x => x.Evaluation.Matched), findings = results.Where(x => x.Finding is not null).Select(x => x.Finding), excluded = results.Count(x => x.Excluded), suppressed = results.Count(x => x.Suppressed) });
    }
    static async Task<IResult> Live(LiveRequest input, HttpContext c, IDetectionRepository r, IAlertIncidentRepository alerts, CancellationToken ct)
    {
        if (input.Mode is not (DetectionExecutionMode.Live or DetectionExecutionMode.DryRun))
            return Problem(c, "DETECTION_EXECUTION_MODE", "This endpoint accepts only Live or DryRun mode.", 400);
        var productionFindings = input.Mode == DetectionExecutionMode.Live && input.ProductionFindings;
        var result = await r.EvaluateAsync(Tenant(c), input.Event, input.Mode, null, null, null, productionFindings, ct);
        if (result.Finding is { } finding && productionFindings && await r.GetRuleAsync(Tenant(c), finding.DetectionId, finding.DetectionVersion, ct) is { } rule) await alerts.CreateAlertAsync(Tenant(c), Actor(c), AlertIncidentSafety.FromDetection(finding, rule), ct);
        return Ok(c, result);
    }
    static async Task<IResult> SeedStarters(HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var tenant = Tenant(c); var output = new List<object>(); foreach (var fixture in DetectionStarterFixtures.Create(tenant)) { var existing = await r.GetRuleAsync(tenant, fixture.Rule.DetectionId, null, ct); if (existing is not null) { output.Add(new { existing.DetectionId, existing.DetectionVersion, status = existing.Status.ToString(), existing = true }); continue; } var exclusion = await r.CreateExclusionAsync(tenant, Actor(c), fixture.Exclusion, ct); var rule = await r.CreateRuleAsync(tenant, Actor(c), fixture.Rule with { ExclusionReferences = [exclusion.Id] }, ct); var errors = DetectionDsl.Validate(rule); rule = await r.RecordValidationAsync(tenant, rule.DetectionId, rule.DetectionVersion, errors, ct); var exclusions = await r.ListExclusionsAsync(tenant, ct); var results = fixture.Tests.Select(x => (Test: x, Result: RunFixture(rule, x, exclusions))).ToArray(); await r.RecordTestsAsync(tenant, rule.DetectionId, rule.DetectionVersion, results, ct); rule = await r.ActivateAsync(tenant, Actor(c), rule.DetectionId, rule.DetectionVersion, ct); await r.AssignAsync(tenant, Actor(c), new(Guid.Empty, tenant, rule.DetectionId, rule.DetectionVersion, null, null, true, default, ""), ct); output.Add(new { rule.DetectionId, rule.DetectionVersion, status = rule.Status.ToString(), tests = results.Select(x => new { x.Test.Kind, x.Result.Passed }) }); }
        return Ok(c, new { starterContent = "controlled-fixture-only", rules = output });
    }
    static async Task<IResult> SeedProduction(HttpContext c, IDetectionRepository r, IDetectionEventSource source, CancellationToken ct)
    {
        var tenant = Tenant(c); var actor = Actor(c); var output = new List<object>();
        var from = DateTimeOffset.UtcNow.AddDays(-6); var to = DateTimeOffset.UtcNow;
        var history = new Dictionary<DetectionDomain, IReadOnlyList<DetectionEvidenceEvent>>();
        foreach (var item in DetectionProductionPack.Create(tenant))
        {
            var rule = await r.GetRuleAsync(tenant, item.Rule.DetectionId, item.Rule.DetectionVersion, ct);
            if (rule is null)
            {
                var existingExclusions = await r.ListExclusionsAsync(tenant, ct);
                var exclusion = existingExclusions.FirstOrDefault(x => x.Id == item.Exclusion.Id)
                    ?? await r.CreateExclusionAsync(tenant, actor, item.Exclusion, ct);
                var definition = item.Rule with { ExclusionReferences = [exclusion.Id] };
                var existingIdentity = await r.GetRuleAsync(tenant, item.Rule.DetectionId, null, ct);
                rule = existingIdentity is null
                    ? await r.CreateRuleAsync(tenant, actor, definition, ct)
                    : await r.CreateVersionAsync(tenant, actor, item.Rule.DetectionId, definition, ct);
            }
            var errors = DetectionDsl.Validate(rule);
            rule = await r.RecordValidationAsync(tenant, rule.DetectionId, rule.DetectionVersion, errors, ct);
            var exclusions = await r.ListExclusionsAsync(tenant, ct);
            var results = item.Fixtures.Select(x => (Test: x, Result: RunFixture(rule, x, exclusions))).ToArray();
            await r.RecordTestsAsync(tenant, rule.DetectionId, rule.DetectionVersion, results, ct);
            if (!history.TryGetValue(rule.Domain, out var events)) history[rule.Domain] = events = await source.LoadAsync(tenant, rule.Domain, from, to, 10_000, ct);
            var historicalMatches = events.Count(x => DetectionDsl.Evaluate(rule, x).Matched);
            var boundedVolume = historicalMatches <= 1_000;
            if (errors.Count == 0 && results.All(x => x.Result.Passed) && boundedVolume && rule.Status != DetectionRuleStatus.Active)
            {
                rule = await r.ActivateAsync(tenant, actor, rule.DetectionId, rule.DetectionVersion, ct);
                await r.AssignAsync(tenant, actor, new(Guid.Empty, tenant, rule.DetectionId, rule.DetectionVersion, null, null, true, default, ""), ct);
            }
            output.Add(new
            {
                rule.DetectionId,
                rule.Name,
                item.Pack,
                rule.Status,
                fixtures = results.Length,
                testsPassed = results.All(x => x.Result.Passed),
                historicalEvents = events.Count,
                historicalMatches,
                boundedVolume,
                activated = rule.Status == DetectionRuleStatus.Active
            });
        }
        return Ok(c, new
        {
            schemaVersion = "detection-content-campaign.v1",
            production = true,
            from,
            to,
            rules = output,
            allQualityGatesPassed = output.All(x => (bool)x.GetType().GetProperty("testsPassed")!.GetValue(x)! && (bool)x.GetType().GetProperty("boundedVolume")!.GetValue(x)!)
        });
    }
    static async Task<IResult> ContentCatalog(HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var tenant = Tenant(c); var actual = (await r.ListRulesAsync(tenant, ct)).ToDictionary(x => x.DetectionId);
        var data = DetectionProductionPack.Create(tenant).Select(x => new
        {
            x.Rule.DetectionId,
            x.Rule.Name,
            x.Pack,
            x.Rule.Domain,
            x.Rule.Severity,
            x.Rule.Confidence,
            x.Rule.MitreTactics,
            x.Rule.MitreTechniques,
            status = actual.GetValueOrDefault(x.Rule.DetectionId)?.Status.ToString() ?? "NotInstalled",
            enabled = actual.GetValueOrDefault(x.Rule.DetectionId)?.Enabled ?? false,
            version = actual.GetValueOrDefault(x.Rule.DetectionId)?.DetectionVersion ?? 0,
            validationPassed = actual.GetValueOrDefault(x.Rule.DetectionId)?.LastValidationPassed ?? false,
            fixtureCount = x.Fixtures.Length,
            x.Rationale,
            x.KnownBenignCases,
            x.FalsePositiveDrivers,
            x.TuningGuidance,
            x.SupportLimitations
        });
        return Ok(c, data);
    }
    static async Task<IResult> ContentCoverage(HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var tenant = Tenant(c); var active = (await r.ListRulesAsync(tenant, ct)).Where(x => x.Enabled && x.Status == DetectionRuleStatus.Active).ToArray();
        var data = DetectionProductionPack.Create(tenant).GroupBy(x => new { Tactic = x.Rule.MitreTactics[0], Technique = x.Rule.MitreTechniques[0] })
            .Select(x => new
            {
                x.Key.Tactic,
                x.Key.Technique,
                telemetry = x.Select(v => v.Rule.Domain).Distinct(),
                rules = x.Select(v => v.Rule.DetectionId),
                activeRules = x.Count(v => active.Any(a => a.DetectionId == v.Rule.DetectionId)),
                fixtureEvidence = x.Sum(v => v.Fixtures.Length),
                support = x.All(v => active.Any(a => a.DetectionId == v.Rule.DetectionId)) ? "Covered" : "Partial"
            });
        return Ok(c, data);
    }
    static IResult ContentGaps(HttpContext c) => Ok(c, new[]
    {
        new { area = "Native Linux production validation", status = "ENVIRONMENT BLOCKER", reason = "No supported native Linux endpoint is available." },
        new { area = "macOS production validation", status = "EXTERNAL BLOCKER", reason = "No supported macOS endpoint is available." },
        new { area = "Hosted CI", status = "EXTERNAL BLOCKER", reason = "No hosted CI runner is connected to this workspace." },
        new { area = "Credential dumping and kernel-only behavior", status = "NOT OBSERVABLE BY SOURCE", reason = "Current canonical sources do not prove memory contents or kernel-only intent." },
        new { area = "True enterprise alert-volume scale", status = "ENVIRONMENT BLOCKER", reason = "Local controlled scale is not a physical enterprise fleet." }
    });
    static async Task<IResult> Replay(ReplayRequest input, HttpContext c, IDetectionRepository r, IDetectionEventSource source, CancellationToken ct)
    {
        var tenant = Tenant(c); var rule = await r.GetRuleAsync(tenant, input.DetectionId, input.Version, ct); if (rule is null) return Results.NotFound(); if (input.To <= input.From || input.To - input.From > TimeSpan.FromDays(7) || input.ControlledFixtureEvents?.Length > 10_000) return Problem(c, "DETECTION_REPLAY_BOUNDS", "Replay is limited to seven days and 10,000 events.", 400); var events = input.ControlledFixtureEvents is { Length: > 0 } fixture ? fixture.Where(x => x.EventTime >= input.From && x.EventTime <= input.To).OrderBy(x => x.EventTime).ThenBy(x => x.EventId).ToArray() : (await source.LoadAsync(tenant, rule.Domain, input.From, input.To, 10_000, ct)).ToArray(); var run = new DetectionRun(Guid.NewGuid(), tenant, rule.DetectionId, rule.DetectionVersion, DetectionExecutionMode.HistoricalReplay, input.From, input.To, "running", events.Length, 0, 0, 0, input.ProductionFindings, DateTimeOffset.UtcNow); await r.CreateRunAsync(tenant, run, rule, ct); var results = new List<DetectionEvaluationResult>(); foreach (var evidence in events) { var state = await r.GetRunAsync(tenant, run.Id, ct); if (state?.Status is "cancelling" or "cancelled") break; results.Add(await r.EvaluateAsync(tenant, evidence, DetectionExecutionMode.HistoricalReplay, rule.DetectionId, rule.DetectionVersion, run.Id, input.ProductionFindings, ct)); }
        var completed = await r.CompleteRunAsync(tenant, run.Id, results.Count, results.Count(x => x.Evaluation.Matched), results.Count(x => x.Finding is not null), "completed", ct); return Results.Accepted($"/api/v1/detection-replays/{run.Id}", Envelope(c, new { run = completed, authoritativeSource = input.ControlledFixtureEvents is not { Length: > 0 }, simulationDefault = !input.ProductionFindings, resultFindingIds = results.Where(x => x.Finding is not null).Select(x => x.Finding!.FindingId).ToArray() }));
    }
    static async Task<IResult> ReplayStatus(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => await r.GetRunAsync(Tenant(c), id, ct) is { } value ? Ok(c, value) : Results.NotFound();
    static async Task<IResult> ReplayCancel(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) { try { return Ok(c, await r.CancelRunAsync(Tenant(c), id, ct)); } catch (KeyNotFoundException) { return Results.NotFound(); } }
    static async Task<IResult> ReplayResults(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => await r.GetRunAsync(Tenant(c), id, ct) is { } run ? Ok(c, new { run, findings = await r.SearchFindingsAsync(Tenant(c), new(DetectionId: run.DetectionId, Mode: DetectionExecutionMode.HistoricalReplay), ct) }) : Results.NotFound();
    static async Task<IResult> Findings(HttpContext c, IDetectionRepository r, CancellationToken ct) { var q = c.Request.Query; var request = new DetectionFindingQuery(Guid.TryParse(q["detectionId"], out var detection) ? detection : null, Guid.TryParse(q["endpointId"], out var endpoint) ? endpoint : null, int.TryParse(q["minimumSeverity"], out var severity) ? severity : null, bool.TryParse(q["suppressed"], out var suppressed) ? suppressed : null, Enum.TryParse<DetectionExecutionMode>(q["mode"], true, out var mode) ? mode : null, DateTimeOffset.TryParse(q["from"], out var from) ? from : null, DateTimeOffset.TryParse(q["to"], out var to) ? to : null, int.TryParse(q["pageSize"], out var size) ? size : 100, q["cursor"]); return Ok(c, await r.SearchFindingsAsync(Tenant(c), request, ct)); }
    static async Task<IResult> Finding(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => await r.GetFindingAsync(Tenant(c), id, ct) is { } value ? Ok(c, value) : Results.NotFound();
    static async Task<IResult> Evidence(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => await r.GetFindingAsync(Tenant(c), id, ct) is { } value ? Ok(c, new { value.MatchingEventIds, value.EvidenceReferences, value.TelemetryQuality, value.MissingTelemetry }) : Results.NotFound();
    static async Task<IResult> Conditions(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) => await r.GetFindingAsync(Tenant(c), id, ct) is { } value ? Ok(c, value.MatchedConditions) : Results.NotFound();
    static async Task<IResult> FindingRule(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct) { var finding = await r.GetFindingAsync(Tenant(c), id, ct); if (finding is null) return Results.NotFound(); return await r.GetRuleAsync(Tenant(c), finding.DetectionId, finding.DetectionVersion, ct) is { } rule ? Ok(c, rule) : Results.NotFound(); }
    static async Task<IResult> FindingHistory(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        if (await r.GetFindingAsync(Tenant(c), id, ct) is null) return Results.NotFound();
        return Ok(c, await r.FindingHistoryAsync(Tenant(c), id, ct));
    }
    static async Task<IResult> Health(HttpContext c, IDetectionRepository r, CancellationToken ct) => Ok(c, await r.HealthAsync(Tenant(c), ct));
    static async Task<IResult> RuleHealth(Guid id, HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var rule = await r.GetRuleAsync(Tenant(c), id, null, ct); if (rule is null) return Results.NotFound();
        var tests = await r.ListTestsAsync(Tenant(c), id, rule.DetectionVersion, ct);
        return Ok(c, new { rule.DetectionId, rule.DetectionVersion, rule.Status, rule.Enabled, rule.LastValidationPassed, rule.LastValidatedAt, testsPassed = tests.Count(x => x.Result.Passed), testsFailed = tests.Count(x => !x.Result.Passed) });
    }
    static async Task<IResult> ReplayHealth(HttpContext c, IDetectionRepository r, CancellationToken ct)
    {
        var health = await r.HealthAsync(Tenant(c), ct);
        return Ok(c, new { health.ReplayQueueDepth, health.LastReplayDurationMilliseconds, health.EvaluationFailures, health.UpdatedAt });
    }
    static async Task<IResult> CreateExport(FindingExportRequest input, HttpContext c, IDetectionRepository r, IObjectStorage storage, CancellationToken ct)
    {
        var format = input.Format.ToLowerInvariant(); if (format is not ("jsonl" or "csv") || input.MaximumRecords is < 1 or > 10_000) return Problem(c, "DETECTION_EXPORT_BOUNDS", "Export format or maximum record count is invalid.", 400); var tenant = Tenant(c); var page = await r.SearchFindingsAsync(tenant, input.Query with { Cursor = null, PageSize = input.MaximumRecords }, ct); var values = page.Items.Take(input.MaximumRecords).ToArray(); byte[] content = format == "jsonl" ? Encoding.UTF8.GetBytes(string.Join('\n', values.Select(x => JsonSerializer.Serialize(x))) + '\n') : FindingCsv(values); var hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(); var id = Guid.NewGuid(); var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "detection-finding-export-manifest.v1", exportId = id, tenantBinding = tenant, format, recordCount = values.Length, query = input.Query, sha256 = hash, includes = new[] { "finding evidence", "rule metadata", "rule version", "matched conditions", "telemetry quality" }, createdAt = DateTimeOffset.UtcNow }); await Put(storage, tenant, id.ToString("D"), content, format == "csv" ? "text/csv" : "application/x-ndjson", ct); await Put(storage, tenant, ManifestId(id).ToString("D"), manifest, "application/json", ct); return Results.Created($"/api/v1/finding-exports/{id:D}", Envelope(c, new { id, state = "Completed", format, recordCount = values.Length, sha256 = hash }));
    }
    static async Task<IResult> ExportManifest(Guid id, HttpContext c, IObjectStorage storage, CancellationToken ct) => await storage.HeadAsync(Tenant(c), ManifestId(id).ToString("D"), ct) is null ? Results.NotFound() : Results.Stream(await storage.DownloadAsync(Tenant(c), ManifestId(id).ToString("D"), ct), "application/json");
    static async Task<IResult> ExportContent(Guid id, HttpContext c, IObjectStorage storage, CancellationToken ct) => await storage.HeadAsync(Tenant(c), id.ToString("D"), ct) is { } meta ? Results.Stream(await storage.DownloadAsync(Tenant(c), id.ToString("D"), ct), meta.MediaType) : Results.NotFound();
    static async Task<IResult> ExportUrl(Guid id, HttpContext c, IObjectStorage storage, PlatformOptions options, CancellationToken ct) { if (await storage.HeadAsync(Tenant(c), id.ToString("D"), ct) is null) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddMinutes(5); var token = FileExportDownloadToken.Create(Tenant(c), id, expires, options.JwtSigningKey); return Ok(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/finding-exports/{id:D}/download?token={Uri.EscapeDataString(token)}", expiresAt = expires }); }
    static async Task<IResult> ExportDownload(Guid id, string token, IObjectStorage storage, PlatformOptions options, CancellationToken ct) { if (!FileExportDownloadToken.TryValidate(token, options.JwtSigningKey, out var tenant, out var export) || export != id || await storage.HeadAsync(tenant, id.ToString("D"), ct) is not { } meta) return Results.NotFound(); return Results.Stream(await storage.DownloadAsync(tenant, id.ToString("D"), ct), meta.MediaType); }
    static async Task Put(IObjectStorage storage, string tenant, string id, byte[] bytes, string media, CancellationToken ct) { await using var stream = new MemoryStream(bytes); var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); await storage.UploadAsync(tenant, id, stream, media, hash, ct); }
    static Guid ManifestId(Guid exportId) { var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"detection-export-manifest:{exportId:D}")); return new Guid(bytes.AsSpan(0, 16)); }
    static byte[] FindingCsv(IEnumerable<DetectionFinding> values) { static string C(string? value) { var text = value ?? ""; if (text.Length > 0 && "=+-@\t\r".Contains(text[0])) text = "'" + text; return '"' + text.Replace("\"", "\"\"") + '"'; } var b = new StringBuilder("findingId,detectionId,detectionVersion,ruleName,severity,confidence,mode,endpointId,eventCount,evidence,conditions,quality,missingTelemetry,createdAt\n"); foreach (var x in values) b.AppendLine(string.Join(',', C(x.FindingId.ToString()), C(x.DetectionId.ToString()), C(x.DetectionVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)), C(x.RuleName), C(x.Severity.ToString(System.Globalization.CultureInfo.InvariantCulture)), C(x.Confidence.ToString(System.Globalization.CultureInfo.InvariantCulture)), C(x.ExecutionMode.ToString()), C(x.EndpointId?.ToString()), C(x.EventCount.ToString(System.Globalization.CultureInfo.InvariantCulture)), C(string.Join(';', x.EvidenceReferences)), C(JsonSerializer.Serialize(x.MatchedConditions)), C(string.Join(';', x.TelemetryQuality)), C(string.Join(';', x.MissingTelemetry)), C(x.CreatedAt.ToString("O")))); return Encoding.UTF8.GetBytes(b.ToString()); }
    static async Task<IResult> Exclusions(HttpContext c, IDetectionRepository r, CancellationToken ct) => Ok(c, await r.ListExclusionsAsync(Tenant(c), ct));
    static async Task<IResult> CreateExclusion(DetectionExclusion input, HttpContext c, IDetectionRepository r, CancellationToken ct) => Results.Created("/api/v1/detection-exclusions", Envelope(c, await r.CreateExclusionAsync(Tenant(c), Actor(c), input, ct)));
    static string Tenant(HttpContext c) => c.Items["tenant"]?.ToString() ?? "root";
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static ApiEnvelope<object> Envelope(HttpContext c, object value) => new(value, new(c.TraceIdentifier));
    static IResult Ok(HttpContext c, object value) => Results.Ok(Envelope(c, value));
    static IResult Problem(HttpContext c, string code, string detail, int status) => Results.Problem(statusCode: status, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["traceId"] = c.TraceIdentifier });
}
