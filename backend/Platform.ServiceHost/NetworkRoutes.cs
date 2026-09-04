using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class NetworkRoutes
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static void Map(WebApplication app)
    {
        app.MapPost("/agent/v1/network-event-batches", IngestAsync)
            .RequirePermission("agent:heartbeat");
        app.MapGet("/agent/v1/network-policy", EffectiveForAgentAsync)
            .RequirePermission("agent:heartbeat");
        app.MapPost("/agent/v1/network-policy:acknowledge", AcknowledgeForAgentAsync)
            .RequirePermission("agent:heartbeat");

        app.MapGet("/api/v1/network-events", SearchAsync).RequirePermission("network:read");
        app.MapGet("/api/v1/network-events/{eventId:guid}", EventAsync)
            .RequirePermission("network:details:read");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/network-connections/{entityId}", ConnectionAsync)
            .RequirePermission("network:connection:read");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/network-connections/{entityId}/history", HistoryAsync)
            .RequirePermission("network:read");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/network-timeline", TimelineAsync)
            .RequirePermission("network:read");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/processes/{processId}/network", ProcessAsync)
            .RequirePermission("network:relationship:read");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/network-listeners", ListenersAsync)
            .RequirePermission("network:listener:read");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/network-telemetry-health", HealthAsync)
            .RequirePermission("network:health:read");
        app.MapPost("/api/v1/network-events/projections:rebuild", RebuildAsync)
            .RequirePermission("system:admin");
        app.MapGet("/api/v1/network-events/projections:progress", Progress)
            .RequirePermission("system:admin");
        app.MapGet("/api/v1/network-events:export", ExportSyncAsync)
            .RequirePermission("network:export");
        app.MapPost("/api/v1/network-exports", CreateExportAsync)
            .RequirePermission("network:export");
        app.MapGet("/api/v1/network-exports/{id:guid}", ExportStatusAsync)
            .RequirePermission("network:export");
        app.MapGet("/api/v1/network-exports/{id:guid}/metadata", ExportMetadataAsync)
            .RequirePermission("network:export");
        app.MapGet("/api/v1/network-exports/{id:guid}/manifest", ExportManifestAsync)
            .RequirePermission("network:export");
        app.MapGet("/api/v1/network-exports/{id:guid}/content", ExportContentAsync)
            .RequirePermission("network:export");
        app.MapPost("/api/v1/network-exports/{id:guid}/download-url", ExportDownloadUrlAsync)
            .RequirePermission("network:export");
        app.MapGet("/api/v1/network-exports/{id:guid}/download", ExportSignedDownloadAsync);

        app.MapGet("/api/v1/network-telemetry/policies", ListPoliciesAsync)
            .RequirePermission("network:policy:manage");
        app.MapPost("/api/v1/network-telemetry/policies", CreatePolicyAsync)
            .RequirePermission("network:policy:manage");
        app.MapGet("/api/v1/endpoints/{endpointId:guid}/network-policy", EffectivePolicyAsync)
            .RequirePermission("network:policy:manage");
        app.MapPost("/api/v1/network-telemetry/policies/{id:guid}:assign", AssignPolicyAsync)
            .RequirePermission("network:policy:manage");
        app.MapPost("/api/v1/network-telemetry/policies/{id:guid}:rollback", RollbackPolicyAsync)
            .RequirePermission("network:policy:manage");
        app.MapGet("/api/v1/network-telemetry/policies/{id:guid}/exclusions", ListExclusionsAsync)
            .RequirePermission("network:exclusion:manage");
        app.MapPost("/api/v1/network-telemetry/policies/{id:guid}/exclusions", AddExclusionAsync)
            .RequirePermission("network:exclusion:manage");
        app.MapPut("/api/v1/network-telemetry/policies/{id:guid}/exclusions/{ruleId:guid}", UpdateExclusionAsync)
            .RequirePermission("network:exclusion:manage");
        app.MapDelete("/api/v1/network-telemetry/policies/{id:guid}/exclusions/{ruleId:guid}", DeleteExclusionAsync)
            .RequirePermission("network:exclusion:manage");
    }

    private static async Task<IResult> IngestAsync(HttpContext c, INetworkTelemetryRepository repository, PlatformMetrics metrics, CancellationToken ct)
    {
        if (!c.Request.IsHttps || c.Request.ContentLength is > 1024 * 1024)
            return Problem(c, "NETWORK_BATCH_SIZE", "Compressed network batch exceeds policy.", 413);
        if (c.Items["principal"] is not PrincipalContext { Type: "agent" } principal)
            return Results.Unauthorized();
        if (!long.TryParse(c.Request.Headers["X-Uncompressed-Length"], out var expected)
            || expected is < 1 or > 4 * 1024 * 1024
            || !string.Equals(c.Request.Headers.ContentEncoding, "gzip", StringComparison.OrdinalIgnoreCase))
            return Problem(c, "NETWORK_COMPRESSION_INVALID", "A bounded gzip network batch is required.", 400);
        try
        {
            await using var gzip = new GZipStream(c.Request.Body, CompressionMode.Decompress, false);
            await using var bounded = new MemoryStream();
            var buffer = new byte[81920]; long total = 0; int read;
            while ((read = await gzip.ReadAsync(buffer, ct)) > 0)
            {
                total += read;
                if (total > expected || total > 4 * 1024 * 1024)
                    return Problem(c, "NETWORK_DECOMPRESSION_LIMIT", "Network batch exceeded its declared limit.", 413);
                await bounded.WriteAsync(buffer.AsMemory(0, read), ct);
            }
            if (total != expected)
                return Problem(c, "NETWORK_LENGTH_MISMATCH", "Network batch length did not match its declaration.", 400);
            var batch = JsonSerializer.Deserialize<NetworkEventBatch>(bounded.ToArray(), Json);
            if (batch is null || batch.Events.Count is < 1 or > 1000
                || batch.FirstSequence != batch.Events.Min(x => x.Sequence)
                || batch.LastSequence != batch.Events.Max(x => x.Sequence))
                return Problem(c, "NETWORK_BATCH_INVALID", "Network batch contract is invalid.", 400);
            var ids = principal.Subject.Split(':');
            if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint) || !Guid.TryParse(ids[1], out var agent)
                || batch.EndpointId != endpoint || batch.AgentId != agent)
                return Results.Unauthorized();
            var actual = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(batch.Events, Json))).ToLowerInvariant();
            if (batch.ContentSha256.Length != 64 || !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(batch.ContentSha256.ToLowerInvariant())))
                return Problem(c, "NETWORK_INTEGRITY_INVALID", "Network event integrity validation failed.", 400);
            var health = HealthFromHeaders(c, endpoint, batch);
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            var result = await repository.IngestAsync(principal.TenantId, batch, health, ct);
            metrics.NetworkIngest(result, System.Diagnostics.Stopwatch.GetElapsedTime(started));
            return Results.Ok(result.Acknowledgement);
        }
        catch (Exception e) when (e is InvalidDataException or JsonException)
        {
            return Problem(c, "NETWORK_BATCH_INVALID", "Network batch could not be parsed.", 400);
        }
    }

    private static NetworkTelemetryHealth HealthFromHeaders(HttpContext c, Guid endpoint, NetworkEventBatch batch)
    {
        long H(string name) => long.TryParse(c.Request.Headers[name], out var value) ? Math.Max(0, value) : 0;
        var events = batch.Events;
        return new(endpoint, true, events[0].CollectorSource, events[0].CollectorVersion,
            events[0].NativeProvider, events.Max(x => x.ObservedAt), null,
            H("X-Queue-Depth"), H("X-Queue-Oldest-Age"), H("X-Dropped-Events"),
            H("X-Excluded-Events"), H("X-Source-Losses"), H("X-Sequence-Gaps"),
            events.LongCount(x => x.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase)),
            events.LongCount(x => x.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase)),
            events.LongCount(x => x.Local.AddressFamily == "IPv4"),
            events.LongCount(x => x.Local.AddressFamily == "IPv6"),
            events.LongCount(x => x.Kind == NetworkEventKind.ConnectionAttempted),
            events.LongCount(x => x.Kind == NetworkEventKind.ConnectionEstablished),
            events.LongCount(x => x.Kind == NetworkEventKind.ConnectionFailed),
            events.LongCount(x => x.Kind == NetworkEventKind.ConnectionClosed),
            events.LongCount(x => x.Direction == NetworkDirection.Inbound),
            events.LongCount(x => x.Kind is NetworkEventKind.ListenerStarted or NetworkEventKind.ListenerStopped),
            H("X-Attribution-Failures"), H("X-User-Attribution-Failures"),
            H("X-Pid-Reuse-Conflicts"), H("X-Lifecycle-Correlation-Failures"), "accepted",
            c.Request.Headers["X-Policy-Version"].FirstOrDefault() ?? "network-policy.v1",
            int.TryParse(c.Request.Headers["X-Applied-Policy-Version"], out var version) ? version : null,
            false, DateTimeOffset.UtcNow, batch.LastSequence,
            (c.Request.Headers["X-Known-Limitations"].FirstOrDefault() ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries),
            H("X-Native-Source-Events"), H("X-Normalized-Events"), H("X-Batches"),
            H("X-Upload-Failures"), H("X-Accepted-Events"), H("X-Duplicate-Events"),
            H("X-Rejected-Events"));
    }

    private static async Task<IResult> EffectiveForAgentAsync(HttpContext c, INetworkPolicyRepository p, CancellationToken ct)
    {
        var principal = (PrincipalContext)c.Items["principal"]!; var ids = principal.Subject.Split(':');
        return ids.Length == 2 && Guid.TryParse(ids[0], out var endpoint)
            ? Results.Ok(await p.EffectiveAsync(principal.TenantId, endpoint, ct)) : Results.Unauthorized();
    }
    private static async Task<IResult> AcknowledgeForAgentAsync(HttpContext c, NetworkPolicyAcknowledgement ack, INetworkPolicyRepository p, CancellationToken ct)
    {
        var principal = (PrincipalContext)c.Items["principal"]!; var ids = principal.Subject.Split(':');
        if (ids.Length != 2 || !Guid.TryParse(ids[0], out var endpoint)) return Results.Unauthorized();
        if (ack.PolicyId != Guid.Empty) await p.AcknowledgeAsync(principal.TenantId, endpoint, ack, ct);
        return Results.Accepted();
    }

    private static async Task<IResult> SearchAsync(HttpContext c, INetworkProjection p, CancellationToken ct) =>
        Results.Ok(Envelope(c, await p.SearchAsync(Tenant(c), Query(c.Request), ct)));
    private static async Task<IResult> EventAsync(Guid eventId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct) =>
        await r.GetEventAsync(Tenant(c), eventId, ct) is { } value ? Results.Ok(Envelope(c, value)) : Results.NotFound();
    private static async Task<IResult> ConnectionAsync(Guid endpointId, string entityId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct) =>
        entityId.Length == 64 && await r.GetConnectionAsync(Tenant(c), endpointId, entityId, ct) is { } value ? Results.Ok(Envelope(c, value)) : Results.NotFound();
    private static async Task<IResult> HistoryAsync(Guid endpointId, string entityId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct)
    { var x = Range(c.Request); return Results.Ok(Envelope(c, await r.ConnectionHistoryAsync(Tenant(c), endpointId, entityId, x.From, x.To, Limit(c.Request), ct))); }
    private static async Task<IResult> TimelineAsync(Guid endpointId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct) =>
        Results.Ok(Envelope(c, await r.EndpointTimelineAsync(Tenant(c), endpointId, Query(c.Request, endpointId), ct)));
    private static async Task<IResult> ProcessAsync(Guid endpointId, string processId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct)
    { var x = Range(c.Request); return Results.Ok(Envelope(c, await r.ProcessNetworkAsync(Tenant(c), endpointId, processId, x.From, x.To, Limit(c.Request), ct))); }
    private static async Task<IResult> ListenersAsync(Guid endpointId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct) =>
        Results.Ok(Envelope(c, await r.ListenersAsync(Tenant(c), endpointId, Limit(c.Request), ct)));
    private static async Task<IResult> HealthAsync(Guid endpointId, HttpContext c, INetworkTelemetryRepository r, CancellationToken ct) =>
        await r.HealthAsync(Tenant(c), endpointId, ct) is { } value ? Results.Ok(Envelope(c, value)) : Results.NotFound();
    private static async Task<IResult> RebuildAsync(HttpContext c, INetworkTelemetryRepository r, INetworkProjection p, CancellationToken ct) =>
        Results.Ok(Envelope(c, await p.RebuildAsync(await r.ListAllAsync(ct), ct)));
    private static IResult Progress(HttpContext c, INetworkProjection p) => Results.Ok(Envelope(c, p.GetRebuildProgress()));

    private static async Task<IResult> ExportSyncAsync(HttpContext c, INetworkProjection p, CancellationToken ct)
    {
        var page = await p.SearchAsync(Tenant(c), Query(c.Request) with { PageSize = 500 }, ct);
        var bytes = Encoding.UTF8.GetBytes(string.Join('\n', page.Items.Select(x => JsonSerializer.Serialize(x, Json))) + '\n');
        c.Response.Headers["X-Export-Schema"] = "network-export.v1";
        c.Response.Headers["X-Export-Records"] = page.Items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        c.Response.Headers["X-Content-SHA256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return Results.File(bytes, "application/x-ndjson", "network-telemetry.jsonl");
    }
    private static async Task<IResult> CreateExportAsync(NetworkExportCreateRequest input, HttpContext c, INetworkExportRepository exports, CancellationToken ct)
    {
        var format = input.Format.ToLowerInvariant();
        if (format is not ("jsonl" or "csv")) return Problem(c, "EXPORT_FORMAT_INVALID", "Format must be jsonl or csv.", 400);
        if (input.MaximumRecords is < 1 or > 10000) return Problem(c, "EXPORT_LIMIT_INVALID", "Maximum records must be between 1 and 10000.", 400);
        var now = DateTimeOffset.UtcNow; var query = input.Query with { From = input.Query.From ?? now.AddHours(-24), To = input.Query.To ?? now, Cursor = null, PageSize = input.MaximumRecords };
        if (query.To <= query.From || query.To - query.From > TimeSpan.FromDays(30)) return Problem(c, "TIME_RANGE_INVALID", "Export range must be positive and at most 30 days.", 400);
        var fields = input.Fields ?? [];
        if (fields.Length > 0 && fields.Distinct().Count() != NetworkExportWorker.EffectiveFields(fields).Length) return Problem(c, "EXPORT_FIELDS_INVALID", "One or more network export fields are unsupported.", 400);
        var principal = (PrincipalContext)c.Items["principal"]!;
        var value = await exports.CreateAsync(principal.TenantId, principal.Subject, input with { Format = format, Query = query, Fields = fields }, ct);
        return Results.Accepted($"/api/v1/network-exports/{value.Id}", Envelope(c, value));
    }
    private static async Task<IResult> ExportStatusAsync(Guid id, HttpContext c, INetworkExportRepository e, CancellationToken ct) => await e.GetAsync(Tenant(c), id, ct) is { } value ? Results.Ok(Envelope(c, value)) : Results.NotFound();
    private static Task<IResult> ExportMetadataAsync(Guid id, HttpContext c, INetworkExportRepository e, IObjectStorage o, CancellationToken ct) => ExportObjectAsync(id, c, e, o, 2, ct);
    private static Task<IResult> ExportManifestAsync(Guid id, HttpContext c, INetworkExportRepository e, IObjectStorage o, CancellationToken ct) => ExportObjectAsync(id, c, e, o, 1, ct);
    private static async Task<IResult> ExportObjectAsync(Guid id, HttpContext c, INetworkExportRepository e, IObjectStorage o, int kind, CancellationToken ct)
    { if (await e.GetAsync(Tenant(c), id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); var objectId = kind == 1 ? value.ManifestObjectId : value.MetadataObjectId; return Results.Stream(await o.DownloadAsync(value.TenantId, objectId.ToString("D"), ct), "application/json"); }
    private static async Task<IResult> ExportContentAsync(Guid id, HttpContext c, INetworkExportRepository e, IObjectStorage o, CancellationToken ct)
    { var principal = (PrincipalContext)c.Items["principal"]!; if (await e.GetAsync(principal.TenantId, id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); await e.AuditDownloadAsync(principal.TenantId, id, principal.Subject, ct); return Results.Stream(await o.DownloadAsync(value.TenantId, value.OutputObjectId.ToString("D"), ct), value.Format == "csv" ? "text/csv" : "application/x-ndjson"); }
    private static async Task<IResult> ExportDownloadUrlAsync(Guid id, FileExportDownloadRequest input, HttpContext c, INetworkExportRepository e, PlatformOptions platform, CancellationToken ct)
    { var tenant = Tenant(c); if (await e.GetAsync(tenant, id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); var expires = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(input.ExpiresInSeconds, 5, 300)); var token = FileExportDownloadToken.Create(tenant, value.Id, expires, platform.JwtSigningKey); return Results.Ok(Envelope(c, new { url = $"{c.Request.Scheme}://{c.Request.Host}/api/v1/network-exports/{id:D}/download?token={Uri.EscapeDataString(token)}", expiresAt = expires })); }
    private static async Task<IResult> ExportSignedDownloadAsync(Guid id, string token, PlatformOptions platform, INetworkExportRepository e, IObjectStorage o, CancellationToken ct)
    { if (!FileExportDownloadToken.TryValidate(token, platform.JwtSigningKey, out var tenant, out var tokenId) || tokenId != id || await e.GetAsync(tenant, id, ct) is not { State: FileExportState.Completed } value) return Results.NotFound(); await e.AuditDownloadAsync(tenant, id, "signed-url", ct); return Results.Stream(await o.DownloadAsync(tenant, value.OutputObjectId.ToString("D"), ct), value.Format == "csv" ? "text/csv" : "application/x-ndjson"); }

    private static async Task<IResult> ListPoliciesAsync(HttpContext c, INetworkPolicyRepository p, CancellationToken ct) => Results.Ok(Envelope(c, await p.ListAsync(Tenant(c), ct)));
    private static async Task<IResult> CreatePolicyAsync(NetworkPolicyCreateRequest input, HttpContext c, INetworkPolicyRepository p, CancellationToken ct)
    { var errors = NetworkPolicyValidation.Validate(input.Policy); if (errors.Count > 0) return Results.ValidationProblem(errors.ToDictionary()); var principal = (PrincipalContext)c.Items["principal"]!; var value = await p.CreateAsync(principal.TenantId, principal.Subject, input.Name, input.Policy, ct); return Results.Created($"/api/v1/network-telemetry/policies/{value.Id}", Envelope(c, value)); }
    private static async Task<IResult> EffectivePolicyAsync(Guid endpointId, HttpContext c, INetworkPolicyRepository p, CancellationToken ct) => Results.Ok(Envelope(c, await p.EffectiveAsync(Tenant(c), endpointId, ct)));
    private static async Task<IResult> AssignPolicyAsync(Guid id, NetworkPolicyAssignRequest input, HttpContext c, INetworkPolicyRepository p, CancellationToken ct)
    { var principal = (PrincipalContext)c.Items["principal"]!; await p.AssignAsync(principal.TenantId, id, input.EndpointId, principal.Subject, ct); return Results.Accepted(); }
    private static async Task<IResult> RollbackPolicyAsync(Guid id, NetworkPolicyRollbackRequest input, HttpContext c, INetworkPolicyRepository p, CancellationToken ct)
    { var principal = (PrincipalContext)c.Items["principal"]!; return Results.Ok(Envelope(c, await p.RollbackAsync(principal.TenantId, id, input.Version, principal.Subject, ct))); }
    private static async Task<IResult> ListExclusionsAsync(Guid id, HttpContext c, INetworkPolicyRepository p, CancellationToken ct) => (await p.ListAsync(Tenant(c), ct)).FirstOrDefault(x => x.Id == id) is { } v ? Results.Ok(Envelope(c, v.Policy.ExclusionRules?.ToArray() ?? [])) : Results.NotFound();
    private static async Task<IResult> AddExclusionAsync(Guid id, NetworkExclusionMutationRequest input, HttpContext c, INetworkPolicyRepository p, CancellationToken ct) => await MutateExclusionAsync(id, null, input, c, p, false, ct);
    private static async Task<IResult> UpdateExclusionAsync(Guid id, Guid ruleId, NetworkExclusionMutationRequest input, HttpContext c, INetworkPolicyRepository p, CancellationToken ct) => await MutateExclusionAsync(id, ruleId, input, c, p, false, ct);
    private static async Task<IResult> DeleteExclusionAsync(Guid id, Guid ruleId, HttpContext c, INetworkPolicyRepository p, CancellationToken ct) => await MutateExclusionAsync(id, ruleId, null, c, p, true, ct);
    private static async Task<IResult> MutateExclusionAsync(Guid id, Guid? ruleId, NetworkExclusionMutationRequest? input, HttpContext c, INetworkPolicyRepository p, bool delete, CancellationToken ct)
    {
        var principal = (PrincipalContext)c.Items["principal"]!; var source = (await p.ListAsync(principal.TenantId, ct)).FirstOrDefault(x => x.Id == id); if (source is null) return Results.NotFound();
        var rules = source.Policy.ExclusionRules?.ToList() ?? [];
        if (ruleId is { } rid) { var index = rules.FindIndex(x => x.Id == rid); if (index < 0) return Results.NotFound(); if (delete) rules.RemoveAt(index); else rules[index] = rules[index] with { Category = input!.Category, Pattern = input.Pattern, Enabled = input.Enabled, Reason = input.Reason }; }
        else rules.Add(new(Guid.NewGuid(), input!.Category, input.Pattern, input.Enabled, input.Reason, principal.Subject, DateTimeOffset.UtcNow));
        var policy = source.Policy with { ExclusionRules = rules }; var errors = NetworkPolicyValidation.Validate(policy); if (errors.Count > 0) return Results.ValidationProblem(errors.ToDictionary());
        var created = await p.CreateAsync(principal.TenantId, principal.Subject, source.Name, policy, ct); return Results.Ok(Envelope(c, created));
    }

    private static NetworkSearchRequest Query(HttpRequest r, Guid? endpoint = null)
    { var x = Range(r); return new(endpoint ?? (Guid.TryParse(r.Query["endpointId"], out var id) ? id : null), x.From, x.To, r.Query["localAddress"].FirstOrDefault(), r.Query["remoteAddress"].FirstOrDefault(), Int(r, "localPort"), Int(r, "remotePort"), r.Query["protocol"].FirstOrDefault(), r.Query["addressFamily"].FirstOrDefault(), Enum.TryParse<NetworkDirection>(r.Query["direction"], true, out var direction) ? direction : null, Enum.TryParse<NetworkConnectionState>(r.Query["state"], true, out var state) ? state : null, Enum.TryParse<NetworkEventKind>(r.Query["operation"], true, out var operation) ? operation : null, r.Query["process"].FirstOrDefault(), r.Query["user"].FirstOrDefault(), r.Query["collector"].FirstOrDefault(), r.Query["dataQuality"].FirstOrDefault(), bool.TryParse(r.Query["listener"], out var listener) ? listener : null, Limit(r), r.Query["cursor"].FirstOrDefault()); }
    private static (DateTimeOffset From, DateTimeOffset To) Range(HttpRequest r) { var now = DateTimeOffset.UtcNow; var from = DateTimeOffset.TryParse(r.Query["from"], out var f) ? f : now.AddHours(-24); var to = DateTimeOffset.TryParse(r.Query["to"], out var t) ? t : now; if (to <= from || to - from > TimeSpan.FromDays(30)) throw new EnrollmentConflictException("TIME_RANGE_INVALID", "Network queries require a positive range of at most 30 days."); return (from, to); }
    private static int Limit(HttpRequest r) => Math.Clamp(Int(r, "pageSize") ?? 100, 1, 500);
    private static int? Int(HttpRequest r, string key) => int.TryParse(r.Query[key], out var value) ? value : null;
    private static string Tenant(HttpContext c) => c.Items["tenant"]!.ToString()!;
    private static ApiEnvelope<T> Envelope<T>(HttpContext c, T value) => new(value, new(c.TraceIdentifier, "1.0"));
    private static IResult Problem(HttpContext c, string code, string message, int status) => Results.Json(new ApiError(code, message, status, c.TraceIdentifier), statusCode: status);
}

sealed record NetworkPolicyCreateRequest(string Name, NetworkTelemetryPolicy Policy);
sealed record NetworkPolicyAssignRequest(Guid? EndpointId);
sealed record NetworkPolicyRollbackRequest(int Version);
sealed record NetworkExclusionMutationRequest(string Category, string Pattern, bool Enabled = true, string Reason = "");
