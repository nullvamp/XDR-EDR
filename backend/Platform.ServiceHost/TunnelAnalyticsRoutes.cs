using OpenSecurityPlatform.Foundation;

static class TunnelAnalyticsRoutes
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/api/v1/tunnels/observations", Ingest).RequirePermission("telemetry:write");
        app.MapGet("/api/v1/tunnels/observations", async (Guid? endpointId, string? processEntityId, TunnelKind? kind, DateTimeOffset? from, DateTimeOffset? to, int? pageSize, string? cursor, HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => Ok(c, await r.SearchObservationsAsync(Tenant(c), new(endpointId, processEntityId, kind, null, from, to, pageSize ?? 100, cursor), ct))).RequirePermission("telemetry:read");
        app.MapGet("/api/v1/tunnels/observations/{id:guid}", async (Guid id, HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => await r.GetObservationAsync(Tenant(c), id, ct) is { } x ? Ok(c, x) : Results.NotFound()).RequirePermission("telemetry:read");
        app.MapGet("/api/v1/tunnels/findings", async (Guid? endpointId, string? processEntityId, TunnelKind? kind, TunnelConfidence? minimumConfidence, DateTimeOffset? from, DateTimeOffset? to, int? pageSize, string? cursor, HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => Ok(c, await r.SearchFindingsAsync(Tenant(c), new(endpointId, processEntityId, kind, minimumConfidence, from, to, pageSize ?? 100, cursor), ct))).RequirePermission("detections:read");
        app.MapGet("/api/v1/tunnels/findings/{id:guid}", async (Guid id, HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => await r.GetFindingAsync(Tenant(c), id, ct) is { } x ? Ok(c, x) : Results.NotFound()).RequirePermission("detections:read");
        app.MapGet("/api/v1/tunnels/observations/{id:guid}/chain", async (Guid id, int? maximumDepth, HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => Ok(c, await r.BuildChainAsync(Tenant(c), id, maximumDepth ?? 4, ct))).RequirePermission("investigations:read");
        app.MapGet("/api/v1/tunnels/rules", (HttpContext c) => Ok(c, TunnelProductionPack.Rules)).RequirePermission("detections:read");
        app.MapPost("/api/v1/tunnels/exclusions", async (TunnelExclusion x, HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => { var tenant = Tenant(c); return Results.Created("/api/v1/tunnels/exclusions", Envelope(c, await r.AddExclusionAsync(tenant, x with { TenantId = tenant }, Actor(c), ct))); }).RequirePermission("detections:write");
        app.MapGet("/api/v1/tunnels/exclusions", async (HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => Ok(c, await r.ExclusionsAsync(Tenant(c), ct))).RequirePermission("detections:read");
        app.MapGet("/api/v1/tunnels/health", async (HttpContext c, ITunnelAnalyticsRepository r, CancellationToken ct) => Ok(c, await r.HealthAsync(Tenant(c), ct))).RequirePermission("telemetry:read");
        app.MapGet("/api/v1/tunnels/reconciliation", async (HttpContext c, ITunnelAnalyticsRepository r, ITunnelAnalyticsProjection p, CancellationToken ct) => { var a = await r.CountsAsync(Tenant(c), ct); var s = await p.CountsAsync(Tenant(c), ct); return Ok(c, new { postgres = new { observations = a.Observations, findings = a.Findings }, openSearch = new { observations = s.Observations, findings = s.Findings }, exact = a == s }); }).RequirePermission("system:admin");
        app.MapPost("/internal/v1/tunnels/self-test", SelfTest).RequirePermission("system:admin");
    }

    static async Task<IResult> Ingest(IReadOnlyList<TunnelObservation> values, HttpContext c, ITunnelAnalyticsRepository r, ITunnelAnalyticsProjection p, IInvestigationRepository investigation, IThreatIntelligenceRepository intel, IAlertIncidentRepository alerts, CancellationToken ct)
    {
        var tenant = Tenant(c);
        var findings = await r.IngestAsync(tenant, values, ct);
        foreach (var x in values) await p.UpsertObservationAsync(x, ct);
        foreach (var f in findings)
        {
            await p.UpsertFindingAsync(f, ct);
            var fields = new Dictionary<string, string?> { { "tunnelKind", f.Kind.ToString() }, { "tunnelConfidence", f.Confidence.ToString() }, { "tunnelRuleId", f.RuleId }, { "remoteAddress", values.FirstOrDefault(x => x.ObservationId == f.ObservationIds[0])?.Remote?.Address } };
            var observation = new CorrelationObservation(f.FindingId, tenant, CorrelationInputKind.DetectionFinding, DetectionDomain.Tunnel, f.LastObserved, DateTimeOffset.UtcNow, f.EndpointId, f.ProcessEntityId, null, f.FindingId.ToString("D"), f.FindingId, null, fields, f.EvidenceReferences[0], false, f.MissingTelemetry.Length > 0, f.MissingTelemetry, [], f.Score);
            await investigation.UpsertObservationAsync(tenant, observation, ct);
            if (f.ProcessEntityId is not null && f.Relationships.Length > 0)
            {
                var nodes = f.Relationships.Select(x => new InvestigationEntity(tenant, x.DestinationEntityId, InvestigationEntityType.Network, f.EndpointId, x.DestinationEntityId, x.FirstObserved, x.LastObserved, new Dictionary<string, string?> { ["processEntityId"] = f.ProcessEntityId, ["tunnelKind"] = f.Kind.ToString(), ["relationship"] = x.Type.ToString() }, x.EvidenceIds, x.EvidenceReferences, x.Provenance, [], x.Ambiguous)).ToArray();
                var edges = f.Relationships.Select(x => new InvestigationRelationship(x.RelationshipId, tenant, f.ProcessEntityId, InvestigationEntityType.Process, x.DestinationEntityId, InvestigationEntityType.Network, x.Type.ToString(), x.EvidenceIds, x.EvidenceReferences, x.FirstObserved, x.LastObserved, x.Confidence, x.Provenance, x.Ambiguous)).ToArray();
                await investigation.UpsertAsync(tenant, nodes, edges, ct);
            }
            var source = values.FirstOrDefault(x => x.ObservationId == f.ObservationIds[0]);
            var evidence = new List<ThreatEvidence>();
            if (source?.Remote?.Address is { } address && System.Net.IPAddress.TryParse(address, out _)) evidence.Add(new(f.EvidenceIds[0], f.EndpointId, f.ProcessEntityId, f.FindingId.ToString("D"), f.LastObserved, address.Contains(':') ? ThreatIndicatorType.IPv6 : ThreatIndicatorType.IPv4, "remoteAddress", address, f.EvidenceReferences[0], []));
            if (source?.Remote?.Hostname is { } host) evidence.Add(new(f.EvidenceIds[0], f.EndpointId, f.ProcessEntityId, f.FindingId.ToString("D"), f.LastObserved, ThreatIndicatorType.Domain, "remoteHostname", host, f.EvidenceReferences[0], []));
            if (evidence.Count > 0) await intel.MatchAsync(tenant, evidence, ThreatMatchMode.Live, ct);
            if (!f.Excluded)
            {
                var ev = new AlertEvidence([f.EndpointId], f.ProcessEntityId is null ? [] : [f.ProcessEntityId], [], [], source?.Remote is null ? [] : [$"{source.Remote.Address}:{source.Remote.Port}"], [], f.EvidenceIds, f.EvidenceReferences, [f.FindingId], [], [], [], f.MissingTelemetry);
                var candidate = new AlertCandidate(tenant, AlertSourceType.DetectionFinding, f.FindingId, f.FindingId, null, TunnelAnalyticsSafety.StableId("tunnel-rule", f.RuleId), 1, 1, f.RuleName, string.Join("; ", f.Reasons), Math.Max(40, f.Score), f.Score, "tunnel", ["Command and Control"], ["T1572"], ["Process", "Network", "DNS"], f.FirstObserved, f.LastObserved, f.EndpointId, f.ProcessEntityId, f.FindingId.ToString("D"), $"tunnel:{f.EndpointId:D}:{f.ProcessEntityId}", ev, DetectionExecutionMode.Live, true);
                await alerts.CreateAlertAsync(tenant, "system:tunnel-analytics", candidate, ct);
            }
        }
        return Results.Accepted("/api/v1/tunnels/findings", Envelope(c, new { accepted = values.Count, findings = findings.Count }));
    }
    static async Task<IResult> SelfTest(HttpContext c, ITunnelAnalyticsRepository r, ITunnelAnalyticsProjection p, IInvestigationRepository investigation, IThreatIntelligenceRepository intel, IAlertIncidentRepository alerts, CancellationToken ct)
    {
        var t = Tenant(c); var key = Guid.NewGuid().ToString("N"); var endpoint = TunnelAnalyticsSafety.StableId(t, key, "endpoint"); var now = DateTimeOffset.UtcNow; TunnelObservation O(string name, TunnelKind kind, TunnelEndpoint? listener, TunnelEndpoint? remote, DateTimeOffset first, DateTimeOffset last, Dictionary<string, string?>? attrs = null, DnsTunnelFeatures? dns = null) { var e = TunnelAnalyticsSafety.StableId(t, key, name, "evidence"); return new(TunnelAnalyticsSafety.StableId(t, key, name), t, endpoint, $"process:{key}:{name}", kind, TunnelDirection.Outbound, listener, remote, first, last, [e], [$"postgresql://platform/sprint24_controlled/{e:D}"], attrs ?? new(), ["controlled"], dns); }
        var dnsSamples = Enumerable.Range(0, 40).Select(i => new DnsQuerySample($"{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(key + i)))[..48]}.controlled.example", "controlled.example", "TXT", i % 3 == 0, now.AddMilliseconds(i * 500))).ToArray(); var dns = DnsTunnelFeatureExtractor.Compute(dnsSamples);
        var a = O("A", TunnelKind.SshDynamicProxy, new("127.0.0.1", 1080), new("192.0.2.24", 22, "ssh.example"), now.AddMinutes(-2), now);
        var b = O("B", TunnelKind.SshReverseForward, new("0.0.0.0", 2222), new("198.51.100.24", 22), now.AddMinutes(-10), now);
        var c1 = O("C", TunnelKind.DnsTunnel, null, null, now.AddSeconds(-20), now, dns: dns);
        var d1 = O("D1", TunnelKind.NestedTunnel, new("127.0.0.1", 8080), new("127.0.0.1", 1080), now.AddMinutes(-2), now, new() { { "remoteFanOut", "6" } }); var d2 = O("D2", TunnelKind.SocksProxy, new("127.0.0.1", 1080), new("203.0.113.24", 443), now.AddMinutes(-2), now, new() { { "distinctClients", "4" } });
        var exclusion = await r.AddExclusionAsync(t, new(Guid.NewGuid(), t, 1, $"controlled {key}", "processEntityId", $"process:{key}:E", now.AddMinutes(-1), now.AddMinutes(10), "controlled benign proxy", "", default), "system:sprint24", ct); var e1 = O("E", TunnelKind.SshDynamicProxy, new("127.0.0.1", 2080), new("192.0.2.25", 22), now.AddSeconds(-20), now);
        var f1 = O("F1", TunnelKind.NestedTunnel, new("127.0.0.1", 3080), new("203.0.113.25", 443), now.AddMinutes(-6), now, new() { { "remoteFanOut", "8" } }); var f2 = O("F2", TunnelKind.NestedTunnel, new("127.0.0.1", 4080), new("203.0.113.26", 443), now.AddMinutes(-6), now, new() { { "remoteFanOut", "9" } });
        var all = new[] { a, b, c1, d1, d2, e1, f1, f2 }; await Ingest(all, c, r, p, investigation, intel, alerts, ct); var found = await r.SearchFindingsAsync(t, new(EndpointId: endpoint, PageSize: 100), ct); var chain = await r.BuildChainAsync(t, d1.ObservationId, 4, ct); return Ok(c, new { runKey = key, profiles = new { A = found.Items.Any(x => x.ObservationIds.Contains(d2.ObservationId) && x.Relationships.Any(r => r.Type == TunnelRelationshipType.ProcessOpensListener) && x.Relationships.Any(r => r.Type == TunnelRelationshipType.ProcessConnectsRemote)), B = found.Items.Any(x => x.ObservationIds.Contains(a.ObservationId)) && found.Items.Any(x => x.ObservationIds.Contains(b.ObservationId)), C = chain.Depth >= 1 && chain.Relationships.All(x => x.EvidenceIds.Length > 0), D = found.Items.Any(x => x.ObservationIds.Contains(c1.ObservationId)) && dns.QueryCount == 40, E = found.Items.Any(x => x.ObservationIds.Contains(e1.ObservationId) && x.Excluded && x.ExclusionId == exclusion.ExclusionId), F = found.Items.Count(x => x.ObservationIds.Contains(f1.ObservationId) || x.ObservationIds.Contains(f2.ObservationId)) == 2 }, dnsFeatures = dns, chain, icmp = "NOT OBSERVABLE BY SOURCE", payloadInspection = false, automaticResponse = false });
    }
    static string Tenant(HttpContext c) => c.Items["tenant"]?.ToString() ?? throw new UnauthorizedAccessException(); static string Actor(HttpContext c) => c.User.Identity?.Name ?? "unknown"; static ApiEnvelope<T> Envelope<T>(HttpContext c, T data) => new(data, new(c.TraceIdentifier, "1.0")); static IResult Ok<T>(HttpContext c, T data) => Results.Ok(Envelope(c, data));
}
