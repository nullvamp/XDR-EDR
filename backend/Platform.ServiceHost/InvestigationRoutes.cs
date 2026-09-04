using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class InvestigationRoutes
{
    sealed record ExecuteRequest(HuntDefinition Hunt);
    sealed record SaveRequest(HuntDefinition Hunt, bool NewVersion = false);
    sealed record CloneRequest(string Name);
    sealed record ExportRequest(string Kind, string Format, string? RootEntityId = null, Guid? HuntRunId = null, GraphQuery? Query = null);
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    static string Actor(HttpContext c) => ((PrincipalContext)c.Items["principal"]!).Subject;
    static IResult Ok<T>(HttpContext c, T value) => Results.Ok(new ApiEnvelope<T>(value, new(c.TraceIdentifier, "1.0")));
    static IResult Problem(HttpContext c, string code, string detail) => Results.Problem(statusCode: 400, title: code, detail: detail, extensions: new Dictionary<string, object?> { ["code"] = code, ["traceId"] = c.TraceIdentifier });

    public static void Map(WebApplication app)
    {
        app.MapGet("/api/v1/process-trees/{root}", Tree).RequirePermission("investigation:tree:read");
        app.MapGet("/api/v1/process-trees/{root}/ancestors", Ancestors).RequirePermission("investigation:tree:read");
        app.MapGet("/api/v1/process-trees/{root}/descendants", Descendants).RequirePermission("investigation:tree:read");
        app.MapPost("/api/v1/entity-graph:query", Graph).RequirePermission("investigation:graph:read");
        app.MapGet("/api/v1/entities/{type}/{id}/neighbors", Neighbors).RequirePermission("investigation:graph:read");
        app.MapGet("/api/v1/relationships/{id:guid}", Relationship).RequirePermission("investigation:evidence:read");
        app.MapPost("/api/v1/attack-stories/{root}", Story).RequirePermission("investigation:story:read");
        app.MapPost("/api/v1/attack-stories/{root}/timeline", StoryTimeline).RequirePermission("investigation:story:read");
        app.MapPost("/api/v1/threat-hunts:validate", ValidateHunt).RequirePermission("hunt:execute");
        app.MapPost("/api/v1/threat-hunts:execute", ExecuteHunt).RequirePermission("hunt:execute");
        app.MapGet("/api/v1/threat-hunt-runs/{id:guid}", HuntRun).RequirePermission("hunt:execute");
        app.MapPost("/api/v1/threat-hunt-runs/{id:guid}:cancel", CancelHunt).RequirePermission("hunt:execute");
        app.MapGet("/api/v1/entities/{type}/{id}/pivots", Pivots).RequirePermission("hunt:execute");
        app.MapGet("/api/v1/saved-hunts", SavedHunts).RequirePermission("hunt:save");
        app.MapPost("/api/v1/saved-hunts", SaveHunt).RequirePermission("hunt:save");
        app.MapPost("/api/v1/saved-hunts/{id:guid}:clone", CloneHunt).RequirePermission("hunt:save");
        app.MapPost("/api/v1/saved-hunts/{id:guid}/versions", VersionHunt).RequirePermission("hunt:save");
        app.MapGet("/api/v1/saved-hunts/{id:guid}/history", HuntHistory).RequirePermission("hunt:save");
        app.MapDelete("/api/v1/saved-hunts/{id:guid}", DeleteHunt).RequirePermission("hunt:save");
        app.MapGet("/api/v1/investigation-health", Health).RequirePermission("investigation:graph:read");
        app.MapPost("/api/v1/investigation-exports", Export).RequirePermission("hunt:export");
        app.MapGet("/api/v1/investigation-exports/{id:guid}/manifest", ExportManifest).RequirePermission("hunt:export");
        app.MapGet("/api/v1/investigation-exports/{id:guid}/content", ExportContent).RequirePermission("hunt:export");
        app.MapGet("/api/v1/investigation-exports/{id:guid}/url", ExportUrl).RequirePermission("hunt:export");
        app.MapGet("/api/v1/investigation-exports/{id:guid}/download", ExportDownload);
        app.MapPost("/internal/v1/investigation:seed-controlled", Seed).RequirePermission("system:admin");
    }

    static GraphQuery Query(HttpContext c, string root)
    {
        var q = c.Request.Query; return new(root, Enum.TryParse<InvestigationEntityType>(q["type"], true, out var type) ? type : null, DateTimeOffset.TryParse(q["from"], out var from) ? from : null, DateTimeOffset.TryParse(q["to"], out var to) ? to : null, int.TryParse(q["depth"], out var d) ? d : 3, int.TryParse(q["maximumNodes"], out var n) ? n : 200, int.TryParse(q["maximumEdges"], out var e) ? e : 400, int.TryParse(q["expansion"], out var x) ? x : 50, int.TryParse(q["timeoutMilliseconds"], out var t) ? t : 5_000, int.TryParse(q["pageSize"], out var p) ? p : 100, q["cursor"]);
    }
    static async Task<IResult> Tree(string root, HttpContext c, IInvestigationRepository r, CancellationToken ct) => await r.ProcessTreeAsync(Tenant(c), root, Query(c, root), false, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> Ancestors(string root, HttpContext c, IInvestigationRepository r, CancellationToken ct) => await r.ProcessTreeAsync(Tenant(c), root, Query(c, root), true, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static Task<IResult> Descendants(string root, HttpContext c, IInvestigationRepository r, CancellationToken ct) => Tree(root, c, r, ct);
    static async Task<IResult> Graph(GraphQuery input, HttpContext c, IInvestigationRepository r, CancellationToken ct) => await r.GraphAsync(Tenant(c), input, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> Neighbors(string type, string id, HttpContext c, IInvestigationRepository r, CancellationToken ct) { if (!Enum.TryParse<InvestigationEntityType>(type, true, out var entityType)) return Problem(c, "ENTITY_TYPE_INVALID", "Entity type is invalid."); var query = Query(c, id) with { RootType = entityType, MaximumDepth = 1 }; return await r.GraphAsync(Tenant(c), query, ct) is { } x ? Ok(c, x) : Results.NotFound(); }
    static async Task<IResult> Relationship(Guid id, HttpContext c, IInvestigationRepository r, CancellationToken ct) { var values = await r.RelationshipAsync(Tenant(c), id, ct); return values.Count == 0 ? Results.NotFound() : Ok(c, values[0]); }
    static async Task<IResult> Story(string root, GraphQuery input, HttpContext c, IInvestigationRepository r, CancellationToken ct) => await r.StoryAsync(Tenant(c), root, input with { RootEntityId = root }, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> StoryTimeline(string root, GraphQuery input, HttpContext c, IInvestigationRepository r, CancellationToken ct) => await r.StoryAsync(Tenant(c), root, input with { RootEntityId = root }, ct) is { } x ? Ok(c, x.Timeline) : Results.NotFound();
    static async Task<IResult> ValidateHunt(HuntDefinition input, HttpContext c, IInvestigationRepository r, CancellationToken ct) => Ok(c, await r.ValidateHuntAsync(Tenant(c), input, ct));
    static async Task<IResult> ExecuteHunt(ExecuteRequest input, HttpContext c, IInvestigationRepository r, CancellationToken ct) { var run = await r.ExecuteHuntAsync(Tenant(c), input.Hunt, ct); return Results.Accepted($"/api/v1/threat-hunt-runs/{run.RunId:D}", new ApiEnvelope<HuntRun>(run, new(c.TraceIdentifier, "1.0"))); }
    static async Task<IResult> HuntRun(Guid id, HttpContext c, IInvestigationRepository r, CancellationToken ct) => await r.GetRunAsync(Tenant(c), id, ct) is { } x ? Ok(c, x) : Results.NotFound();
    static async Task<IResult> CancelHunt(Guid id, HttpContext c, IInvestigationRepository r, CancellationToken ct) { try { return Ok(c, await r.CancelRunAsync(Tenant(c), id, ct)); } catch (KeyNotFoundException) { return Results.NotFound(); } }
    static async Task<IResult> Pivots(string type, string id, HttpContext c, IInvestigationRepository r, CancellationToken ct) { if (!Enum.TryParse<InvestigationEntityType>(type, true, out var entityType)) return Problem(c, "ENTITY_TYPE_INVALID", "Entity type is invalid."); return await r.PivotsAsync(Tenant(c), id, entityType, ct) is { } x ? Ok(c, x) : Results.NotFound(); }
    static async Task<IResult> SavedHunts(HttpContext c, IInvestigationRepository r, CancellationToken ct) => Ok(c, await r.SavedHuntsAsync(Tenant(c), ct));
    static async Task<IResult> SaveHunt(SaveRequest input, HttpContext c, IInvestigationRepository r, CancellationToken ct) => Ok(c, await r.SaveHuntAsync(Tenant(c), Actor(c), input.Hunt, input.NewVersion, ct));
    static async Task<IResult> VersionHunt(Guid id, SaveRequest input, HttpContext c, IInvestigationRepository r, CancellationToken ct) => Ok(c, await r.SaveHuntAsync(Tenant(c), Actor(c), input.Hunt with { HuntId = id }, true, ct));
    static async Task<IResult> CloneHunt(Guid id, CloneRequest input, HttpContext c, IInvestigationRepository r, CancellationToken ct) { var history = await r.HuntHistoryAsync(Tenant(c), id, ct); var source = history.Count == 0 ? null : history[0]; return source is null ? Results.NotFound() : Ok(c, await r.SaveHuntAsync(Tenant(c), Actor(c), source with { HuntId = Guid.Empty, Version = 1, Name = input.Name, Owner = Actor(c), SharedWith = [] }, false, ct)); }
    static async Task<IResult> HuntHistory(Guid id, HttpContext c, IInvestigationRepository r, CancellationToken ct) => Ok(c, await r.HuntHistoryAsync(Tenant(c), id, ct));
    static async Task<IResult> DeleteHunt(Guid id, HttpContext c, IInvestigationRepository r, CancellationToken ct) { await r.DeleteHuntAsync(Tenant(c), Actor(c), id, ct); return Results.NoContent(); }
    static async Task<IResult> Health(HttpContext c, IInvestigationRepository r, CancellationToken ct) => Ok(c, await r.HealthAsync(Tenant(c), ct));

    static async Task<IResult> Seed(HttpContext c, IInvestigationRepository r, CancellationToken ct)
    {
        var tenant = Tenant(c); var endpoint = Guid.Parse("14141414-1414-1414-1414-141414141414"); var at = DateTimeOffset.UtcNow.AddMinutes(-10); var nodes = new List<InvestigationEntity>(); var edges = new List<InvestigationRelationship>();
        InvestigationEntity Node(string id, InvestigationEntityType type, int second, string display, Dictionary<string, string?>? fields = null) { var evidence = InvestigationSafety.StableId(tenant, id, "evidence"); return new(tenant, id, type, endpoint, display, at.AddSeconds(second), at.AddSeconds(second), fields ?? new() { ["processEntityId"] = id, ["path"] = $"C:\\Sprint14Fixtures\\{display}" }, [evidence], [$"postgresql://platform/sprint14_controlled/{evidence:D}"], "controlled-profile", ["complete"]); }
        void Edge(string source, InvestigationEntityType st, string destination, InvestigationEntityType dt, string relationship, int second) { var evidence = InvestigationSafety.StableId(tenant, source, destination, relationship, "evidence"); edges.Add(new(InvestigationSafety.StableId(tenant, source, destination, relationship), tenant, source, st, destination, dt, relationship, [evidence], [$"postgresql://platform/sprint14_controlled/{evidence:D}"], at.AddSeconds(second), at.AddSeconds(second), 100, "controlled-profile", false)); }
        for (var i = 0; i < 4; i++) nodes.Add(Node($"sprint14-process-{i}", InvestigationEntityType.Process, i, $"generation-{i}.exe", new() { ["processEntityId"] = $"sprint14-process-{i}", ["parentProcessEntityId"] = i == 0 ? null : $"sprint14-process-{i - 1}", ["path"] = $"C:\\Sprint14Fixtures\\generation-{i}.exe", ["commandLine"] = $"generation-{i}.exe --controlled", ["userSid"] = "S-1-5-18", ["sessionId"] = "0", ["integrity"] = "High", ["elevated"] = "true", ["sha256"] = new string((char)('a' + i), 64), ["signer"] = "Controlled Test Signer" }));
        for (var i = 1; i < 4; i++) Edge($"sprint14-process-{i - 1}", InvestigationEntityType.Process, $"sprint14-process-{i}", InvestigationEntityType.Process, "parent-of", i);
        var domains = new[] { ("file-1", InvestigationEntityType.File, "payload.exe", "modified"), ("registry-1", InvestigationEntityType.Registry, "HKCU\\Sprint14", "modified"), ("dns-1", InvestigationEntityType.Dns, "sprint14.test", "queried"), ("network-1", InvestigationEntityType.Network, "192.0.2.14:443", "connected-to"), ("module-1", InvestigationEntityType.Module, "fixture.dll", "loaded"), ("identity-1", InvestigationEntityType.Identity, "S-1-5-18", "executed-as"), ("execution-1", InvestigationEntityType.Execution, "thread-start", "executed"), ("persistence-1", InvestigationEntityType.Persistence, "controlled-task", "configured") };
        var second = 10; foreach (var d in domains) { nodes.Add(Node(d.Item1, d.Item2, second, d.Item3, new() { ["processEntityId"] = "sprint14-process-3", ["operation"] = d.Item4, ["dnsName"] = d.Item2 == InvestigationEntityType.Dns ? "sprint14.test" : null, ["remoteAddress"] = d.Item2 == InvestigationEntityType.Network ? "192.0.2.14" : null })); Edge("sprint14-process-3", InvestigationEntityType.Process, d.Item1, d.Item2, d.Item4, second++); }
        nodes.Add(Node("14141414-0000-0000-0000-000000000001", InvestigationEntityType.DetectionFinding, 30, "Sprint 13 controlled finding", new() { ["mitreTechnique"] = "T1204.002", ["processEntityId"] = "sprint14-process-3" })); Edge("sprint14-process-3", InvestigationEntityType.Process, "14141414-0000-0000-0000-000000000001", InvestigationEntityType.DetectionFinding, "evidence-for", 30);
        nodes.Add(Node("14141414-0000-0000-0000-000000000002", InvestigationEntityType.CorrelatedFinding, 31, "Sprint 13 controlled correlation", new() { ["mitreTechnique"] = "T1204.002", ["processEntityId"] = "sprint14-process-3" })); Edge("14141414-0000-0000-0000-000000000002", InvestigationEntityType.CorrelatedFinding, "14141414-0000-0000-0000-000000000001", InvestigationEntityType.DetectionFinding, "contains", 31);
        Edge("dns-1", InvestigationEntityType.Dns, "network-1", InvestigationEntityType.Network, "resolved-to", 20);
        nodes.Add(Node("sprint14-large-root", InvestigationEntityType.Process, 40, "large-root.exe"));
        for (var i = 0; i < 240; i++) { var id = $"sprint14-large-child-{i:D3}"; nodes.Add(Node(id, InvestigationEntityType.Process, 41 + i, $"large-child-{i:D3}.exe", new() { ["processEntityId"] = id, ["parentProcessEntityId"] = "sprint14-large-root", ["path"] = $"C:\\Sprint14Fixtures\\large-child-{i:D3}.exe" })); Edge("sprint14-large-root", InvestigationEntityType.Process, id, InvestigationEntityType.Process, "parent-of", 41 + i); }
        await r.UpsertAsync(tenant, nodes, edges, ct); return Ok(c, new { root = "sprint14-process-0", leaf = "sprint14-process-3", largeRoot = "sprint14-large-root", nodes = nodes.Count, edges = edges.Count, endpoint });
    }

    static async Task<IResult> Export(ExportRequest input, HttpContext c, IInvestigationRepository r, IObjectStorage storage, CancellationToken ct)
    {
        var tenant = Tenant(c); var format = input.Format.ToLowerInvariant(); if (format is not ("jsonl" or "csv" or "graph-json")) return Problem(c, "EXPORT_FORMAT", "Supported formats are JSONL, CSV, and bounded graph JSON."); object value;
        if (input.Kind == "hunt" && input.HuntRunId is { } runId) value = await r.GetRunAsync(tenant, runId, ct) ?? throw new KeyNotFoundException();
        else if (input.Kind == "tree" && input.RootEntityId is { } treeRoot) value = await r.ProcessTreeAsync(tenant, treeRoot, input.Query ?? new(treeRoot), false, ct) ?? throw new KeyNotFoundException();
        else if (input.Kind == "story" && input.RootEntityId is { } storyRoot) value = await r.StoryAsync(tenant, storyRoot, input.Query ?? new(storyRoot), ct) ?? throw new KeyNotFoundException();
        else if (input.RootEntityId is { } graphRoot) value = await r.GraphAsync(tenant, input.Query ?? new(graphRoot), ct) ?? throw new KeyNotFoundException(); else return Problem(c, "EXPORT_TARGET", "A bounded export target is required.");
        var json = JsonSerializer.Serialize(value); var bytes = format == "csv" ? Encoding.UTF8.GetBytes("kind,payload\r\n\"" + input.Kind.Replace("\"", "\"\"") + "\",\"" + json.Replace("\"", "\"\"") + "\"\r\n") : Encoding.UTF8.GetBytes(format == "jsonl" ? json + "\n" : json); var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); var id = Guid.NewGuid(); var manifest = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = "investigation-export-manifest.v1", exportId = id, tenantBinding = tenant, input.Kind, format, sha256 = hash, evidenceReferencesIncluded = true, createdAt = DateTimeOffset.UtcNow }); await Put(storage, tenant, id, bytes, format == "csv" ? "text/csv" : "application/json", ct); await Put(storage, tenant, Manifest(id), manifest, "application/json", ct); return Results.Created($"/api/v1/investigation-exports/{id:D}", new ApiEnvelope<object>(new { id, format, sha256 = hash, state = "Completed" }, new(c.TraceIdentifier, "1.0")));
    }
    static async Task<IResult> ExportManifest(Guid id, HttpContext c, IObjectStorage s, CancellationToken ct) => await s.HeadAsync(Tenant(c), Manifest(id).ToString("D"), ct) is null ? Results.NotFound() : Results.Stream(await s.DownloadAsync(Tenant(c), Manifest(id).ToString("D"), ct), "application/json");
    static async Task<IResult> ExportContent(Guid id, HttpContext c, IObjectStorage s, CancellationToken ct) => await s.HeadAsync(Tenant(c), id.ToString("D"), ct) is { } m ? Results.Stream(await s.DownloadAsync(Tenant(c), id.ToString("D"), ct), m.MediaType) : Results.NotFound();
    static async Task<IResult> ExportUrl(Guid id, HttpContext c, IObjectStorage s, PlatformOptions o, CancellationToken ct) { if (await s.HeadAsync(Tenant(c), id.ToString("D"), ct) is null) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddMinutes(5); return Ok(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/investigation-exports/{id:D}/download?token={Uri.EscapeDataString(FileExportDownloadToken.Create(Tenant(c), id, expires, o.JwtSigningKey))}", expiresAt = expires }); }
    static async Task<IResult> ExportDownload(Guid id, string token, IObjectStorage s, PlatformOptions o, CancellationToken ct) { if (!FileExportDownloadToken.TryValidate(token, o.JwtSigningKey, out var tenant, out var target) || target != id || await s.HeadAsync(tenant, id.ToString("D"), ct) is not { } m) return Results.NotFound(); return Results.Stream(await s.DownloadAsync(tenant, id.ToString("D"), ct), m.MediaType); }
    static async Task Put(IObjectStorage s, string tenant, Guid id, byte[] bytes, string media, CancellationToken ct) { await using var stream = new MemoryStream(bytes); await s.UploadAsync(tenant, id.ToString("D"), stream, media, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), ct); }
    static Guid Manifest(Guid id) => InvestigationSafety.StableId("investigation-export-manifest", id.ToString("D"));
}
