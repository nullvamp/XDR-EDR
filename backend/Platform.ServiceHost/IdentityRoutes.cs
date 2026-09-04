using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class IdentityRoutes
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static void Map(WebApplication app)
    {
        app.MapPost("/agent/v1/identity-event-batches", Ingest).RequirePermission("agent:heartbeat");
        app.MapGet("/agent/v1/identity-policy", AgentPolicy).RequirePermission("agent:heartbeat");
        app.MapPost("/agent/v1/identity-policy:acknowledge", Acknowledge).RequirePermission("agent:heartbeat");
        app.MapGet("/api/v1/identity-events", Search).RequirePermission("identity:read");
        app.MapGet("/api/v1/identity-events/{id:guid}", Get).RequirePermission("identity:details:read");
        app.MapGet("/api/v1/identity-entities/{entity}/history", History).RequirePermission("identity:details:read");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/identity-timeline", Timeline).RequirePermission("identity:read");
        app.MapGet("/api/v1/processes/{entity}/identity", ProcessIdentity).RequirePermission("identity:details:read");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/identity-telemetry-health", Health).RequirePermission("identity:health:read");
        app.MapGet("/api/v1/identity-telemetry/policies", Policies).RequirePermission("identity:policy:manage");
        app.MapPost("/api/v1/identity-telemetry/policies", CreatePolicy).RequirePermission("identity:policy:manage");
        app.MapPost("/api/v1/identity-telemetry/policies/{id:guid}:assign", Assign).RequirePermission("identity:policy:manage");
        app.MapGet("/api/v1/endpoints/{endpoint:guid}/identity-policy", Effective).RequirePermission("identity:policy:manage");
        app.MapPost("/api/v1/identity-exports", CreateExport).RequirePermission("identity:export");
        app.MapGet("/api/v1/identity-exports/{id:guid}", ExportStatus).RequirePermission("identity:export");
        app.MapGet("/api/v1/identity-exports/{id:guid}/manifest", ExportManifest).RequirePermission("identity:export");
        app.MapGet("/api/v1/identity-exports/{id:guid}/content", ExportContent).RequirePermission("identity:export");
        app.MapPost("/api/v1/identity-exports/{id:guid}/download-url", DownloadUrl).RequirePermission("identity:export");
        app.MapGet("/api/v1/identity-exports/{id:guid}/download", SignedDownload);
    }
    static async Task<IResult> Ingest(HttpContext context, IIdentityTelemetryRepository repository, CancellationToken ct)
    {
        if (!context.Request.IsHttps || context.Request.ContentLength is > 1048576) return Problem(context, "IDENTITY_BATCH_SIZE", "Batch exceeds compressed limit.", 413);
        if (context.Items["principal"] is not PrincipalContext { Type: "agent" } principal) return Results.Unauthorized();
        if (!long.TryParse(context.Request.Headers["X-Uncompressed-Length"], out var expected) || expected is < 1 or > 4194304 || !string.Equals(context.Request.Headers.ContentEncoding, "gzip", StringComparison.OrdinalIgnoreCase)) return Problem(context, "IDENTITY_COMPRESSION_INVALID", "Bounded gzip is required.", 400);
        try
        {
            await using var gzip = new GZipStream(context.Request.Body, CompressionMode.Decompress); await using var memory = new MemoryStream(); var buffer = new byte[81920]; long total = 0; int read;
            while ((read = await gzip.ReadAsync(buffer, ct)) > 0) { total += read; if (total > expected || total > 4194304) return Problem(context, "IDENTITY_DECOMPRESSION_LIMIT", "Declared limit exceeded.", 413); await memory.WriteAsync(buffer.AsMemory(0, read), ct); }
            if (total != expected) return Problem(context, "IDENTITY_LENGTH_MISMATCH", "Length mismatch.", 400);
            var batch = JsonSerializer.Deserialize<IdentityEventBatch>(memory.ToArray(), Json); if (batch is null || batch.Events.Count is < 1 or > 1000) return Problem(context, "IDENTITY_BATCH_INVALID", "Invalid batch.", 400);
            var ids = principal.Subject.Split(':'); if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint) || !Guid.TryParse(ids[1], out var agent) || batch.EndpointId != endpoint || batch.AgentId != agent) return Results.Unauthorized();
            var hash = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(batch.Events, Json))).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(hash), Encoding.ASCII.GetBytes(batch.ContentSha256.ToLowerInvariant()))) return Problem(context, "IDENTITY_INTEGRITY_INVALID", "Integrity failed.", 400);
            IdentityTelemetryHealth? health = null;
            if (context.Request.Headers["X-Identity-Health"].FirstOrDefault() is { Length: > 0 } encoded) { try { health = JsonSerializer.Deserialize<IdentityTelemetryHealth>(Convert.FromBase64String(encoded), Json); } catch (FormatException) { } }
            if (health is null || health.EndpointId != endpoint) return Problem(context, "IDENTITY_HEALTH_INVALID", "A valid bounded health snapshot is required.", 400);
            return Results.Ok((await repository.IngestAsync(principal.TenantId, batch, health, ct)).Acknowledgement);
        }
        catch (InvalidDataException) { return Problem(context, "IDENTITY_COMPRESSION_INVALID", "Compressed body is invalid.", 400); }
        catch (JsonException) { return Problem(context, "IDENTITY_BATCH_INVALID", "Batch JSON is invalid.", 400); }
    }
    static Task<IResult> Search(HttpContext c, IIdentityProjection p, PlatformMetrics metrics, CancellationToken ct) => SearchMeasured(c, p, metrics, Query(c.Request), ct);
    static async Task<IResult> Get(Guid id, HttpContext c, IIdentityTelemetryRepository r, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { } value ? Results.Ok(Envelope(c, value)) : Results.NotFound();
    static async Task<IResult> History(string entity, HttpContext c, IIdentityTelemetryRepository r, CancellationToken ct) { if (!Guid.TryParse(c.Request.Query["endpointId"], out var endpoint) || entity.Length != 64) return Problem(c, "IDENTITY_HISTORY_INVALID", "Endpoint and 64-character entity identity are required.", 400); return Results.Ok(Envelope(c, await r.EntityHistoryAsync(Tenant(c), endpoint, entity, 500, ct))); }
    static Task<IResult> Timeline(Guid endpoint, HttpContext c, IIdentityProjection p, PlatformMetrics metrics, CancellationToken ct) => SearchMeasured(c, p, metrics, Query(c.Request) with { EndpointId = endpoint }, ct);
    static Task<IResult> ProcessIdentity(string entity, HttpContext c, IIdentityProjection p, PlatformMetrics metrics, CancellationToken ct) => entity.Length != 64 ? Task.FromResult(Problem(c, "PROCESS_IDENTITY_INVALID", "Process entity identity is invalid.", 400)) : SearchMeasured(c, p, metrics, Query(c.Request) with { Process = entity }, ct);
    static async Task<IResult> SearchMeasured(HttpContext c, IIdentityProjection p, PlatformMetrics metrics, IdentitySearchRequest query, CancellationToken ct) { var started = Stopwatch.GetTimestamp(); try { return Results.Ok(Envelope(c, await p.SearchAsync(Tenant(c), query, ct))); } finally { metrics.IdentitySearch(Stopwatch.GetElapsedTime(started)); } }
    static async Task<IResult> Health(Guid endpoint, HttpContext c, IIdentityTelemetryRepository r, PlatformMetrics metrics, CancellationToken ct) { if (await r.HealthAsync(Tenant(c), endpoint, ct) is not { } value) return Results.NotFound(); var latency = metrics.IdentityLatency(); return Results.Ok(Envelope(c, value with { ProjectionLatencyMilliseconds = latency.ProjectionMilliseconds, SearchLatencyMilliseconds = latency.SearchMilliseconds })); }
    static async Task<IResult> Policies(HttpContext c, IIdentityPolicyRepository p, CancellationToken ct) => Results.Ok(Envelope(c, await p.ListAsync(Tenant(c), ct)));
    static async Task<IResult> CreatePolicy(PolicyCreate input, HttpContext c, IIdentityPolicyRepository p, CancellationToken ct) { var errors = IdentitySafety.Validate(input.Policy); if (errors.Count > 0) return Results.ValidationProblem(errors.ToDictionary()); var principal = (PrincipalContext)c.Items["principal"]!; var value = await p.CreateAsync(principal.TenantId, principal.Subject, input.Name, input.Policy, ct); return Results.Created($"/api/v1/identity-telemetry/policies/{value.Id}", Envelope(c, value)); }
    static async Task<IResult> Assign(Guid id, PolicyAssign input, HttpContext c, IIdentityPolicyRepository p, CancellationToken ct) { var principal = (PrincipalContext)c.Items["principal"]!; await p.AssignAsync(principal.TenantId, id, input.EndpointId, principal.Subject, ct); return Results.NoContent(); }
    static async Task<IResult> Effective(Guid endpoint, HttpContext c, IIdentityPolicyRepository p, CancellationToken ct) => Results.Ok(Envelope(c, await p.EffectiveAsync(Tenant(c), endpoint, ct)));
    static async Task<IResult> AgentPolicy(HttpContext c, IIdentityPolicyRepository p, CancellationToken ct) { var principal = (PrincipalContext)c.Items["principal"]!; var ids = principal.Subject.Split(':'); return ids.Length == 2 && Guid.TryParse(ids[0], out var endpoint) ? Results.Ok(await p.EffectiveAsync(principal.TenantId, endpoint, ct)) : Results.Unauthorized(); }
    static async Task<IResult> Acknowledge(HttpContext c, IdentityPolicyAcknowledgement ack, IIdentityPolicyRepository p, CancellationToken ct) { var principal = (PrincipalContext)c.Items["principal"]!; var ids = principal.Subject.Split(':'); if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint)) return Results.Unauthorized(); if (ack.PolicyId != Guid.Empty) await p.AcknowledgeAsync(principal.TenantId, endpoint, ack, ct); return Results.Accepted(); }
    static async Task<IResult> CreateExport(IdentityExportCreateRequest input, HttpContext c, IIdentityExportRepository r, CancellationToken ct) { if (input.Format is not ("jsonl" or "csv") || input.MaximumRecords is < 1 or > 10000) return Problem(c, "IDENTITY_EXPORT_INVALID", "Invalid bounded export.", 400); var principal = (PrincipalContext)c.Items["principal"]!; var job = await r.CreateAsync(principal.TenantId, principal.Subject, input, ct); return Results.Accepted($"/api/v1/identity-exports/{job.Id}", Envelope(c, job)); }
    static async Task<IResult> ExportStatus(Guid id, HttpContext c, IIdentityExportRepository r, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { } job ? Results.Ok(Envelope(c, job)) : Results.NotFound();
    static async Task<IResult> ExportManifest(Guid id, HttpContext c, IIdentityExportRepository r, IObjectStorage o, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { State: FileExportState.Completed } job ? Results.Stream(await o.DownloadAsync(job.TenantId, job.ManifestObjectId.ToString("D"), ct), "application/json") : Results.NotFound();
    static async Task<IResult> ExportContent(Guid id, HttpContext c, IIdentityExportRepository r, IObjectStorage o, CancellationToken ct) => await r.GetAsync(Tenant(c), id, ct) is { State: FileExportState.Completed } job ? Results.Stream(await o.DownloadAsync(job.TenantId, job.OutputObjectId.ToString("D"), ct), job.Format == "csv" ? "text/csv" : "application/x-ndjson") : Results.NotFound();
    static async Task<IResult> DownloadUrl(Guid id, FileExportDownloadRequest input, HttpContext c, IIdentityExportRepository r, PlatformOptions options, CancellationToken ct) { var tenant = Tenant(c); if (await r.GetAsync(tenant, id, ct) is not { State: FileExportState.Completed }) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(input.ExpiresInSeconds, 5, 300)); return Results.Ok(Envelope(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/identity-exports/{id}/download?token={Uri.EscapeDataString(FileExportDownloadToken.Create(tenant, id, expires, options.JwtSigningKey))}", expiresAt = expires })); }
    static async Task<IResult> SignedDownload(Guid id, string token, PlatformOptions options, IIdentityExportRepository r, IObjectStorage s, CancellationToken ct) { if (!FileExportDownloadToken.TryValidate(token, options.JwtSigningKey, out var tenant, out var export) || export != id || await r.GetAsync(tenant, id, ct) is not { State: FileExportState.Completed } job) return Results.NotFound(); return Results.Stream(await s.DownloadAsync(tenant, job.OutputObjectId.ToString("D"), ct), job.Format == "csv" ? "text/csv" : "application/x-ndjson"); }
    static IdentitySearchRequest Query(HttpRequest r) { Guid? endpoint = Guid.TryParse(r.Query["endpointId"], out var e) ? e : null; int? logon = int.TryParse(r.Query["logonType"], out var l) ? l : null; int? session = int.TryParse(r.Query["sessionId"], out var s) ? s : null; bool? remote = bool.TryParse(r.Query["remoteSession"], out var rm) ? rm : null; bool? elevated = bool.TryParse(r.Query["elevatedToken"], out var el) ? el : null; DateTimeOffset? from = DateTimeOffset.TryParse(r.Query["from"], out var f) ? f : null; DateTimeOffset? to = DateTimeOffset.TryParse(r.Query["to"], out var t) ? t : null; IdentityEventKind? kind = Enum.TryParse<IdentityEventKind>(r.Query["kind"], true, out var k) ? k : null; int size = int.TryParse(r.Query["pageSize"], out var p) ? Math.Clamp(p, 1, 500) : 100; string? V(string name) => string.IsNullOrWhiteSpace(r.Query[name]) ? null : r.Query[name].ToString(); return new(endpoint, V("account"), V("sid"), V("domain"), logon, V("result"), V("sourceIp"), remote, session, V("integrityLevel"), elevated, V("privilege"), V("process"), V("quality"), kind, from, to, size, V("cursor")); }
    static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!; static object Envelope(HttpContext c, object value) => new { traceId = c.TraceIdentifier, data = value }; static IResult Problem(HttpContext c, string code, string message, int status) => Results.Json(new ApiError(code, message, status, c.TraceIdentifier), statusCode: status);
    public sealed record PolicyCreate(string Name, IdentityTelemetryPolicy Policy); public sealed record PolicyAssign(Guid? EndpointId);
}
