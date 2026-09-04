using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchThreatIntelligenceProjection(HttpClient client, string url,
    string? username, string? password) : IThreatIntelligenceProjection
{
    const string Indicators = "platform-threat-indicators-v1";
    const string IndicatorAlias = "platform-threat-indicators";
    const string Matches = "platform-ioc-matches-v1";
    const string MatchAlias = "platform-ioc-matches";
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public async Task EnsureAsync(CancellationToken ct)
    {
        await Ensure(Indicators, IndicatorAlias, "indicatorId", ct);
        await Ensure(Matches, MatchAlias, "matchId", ct);
    }
    async Task Ensure(string index, string alias, string id, CancellationToken ct)
    {
        var body = $"{{\"settings\":{{\"index.mapping.total_fields.limit\":512}},\"mappings\":{{\"dynamic\":\"strict\",\"properties\":{{\"tenantId\":{{\"type\":\"keyword\"}},\"{id}\":{{\"type\":\"keyword\"}},\"type\":{{\"type\":\"keyword\"}},\"canonicalValue\":{{\"type\":\"keyword\",\"ignore_above\":32766}},\"sourceId\":{{\"type\":\"keyword\"}},\"endpointId\":{{\"type\":\"keyword\"}},\"evidenceEventId\":{{\"type\":\"keyword\"}},\"active\":{{\"type\":\"boolean\"}},\"revoked\":{{\"type\":\"boolean\"}},\"excluded\":{{\"type\":\"boolean\"}},\"updatedAt\":{{\"type\":\"date\"}},\"data\":{{\"type\":\"object\",\"enabled\":false}}}}}},\"aliases\":{{\"{alias}\":{{}}}}}}";
        using var request = new HttpRequestMessage(HttpMethod.Put, $"{url}/{index}") { Content = new StringContent(body, Encoding.UTF8, "application/json") }; Auth(request); using var response = await client.SendAsync(request, ct); if (!response.IsSuccessStatusCode && response.StatusCode != System.Net.HttpStatusCode.BadRequest) response.EnsureSuccessStatusCode();
    }
    public Task UpsertIndicatorAsync(ThreatIndicator x, CancellationToken ct) => Put(IndicatorAlias, $"{x.TenantId}:{x.IndicatorId:D}:{x.Version}", new { x.TenantId, x.IndicatorId, type = x.Type.ToString(), x.CanonicalValue, x.SourceId, endpointId = (string?)null, evidenceEventId = (string?)null, active = x.ActiveAt(DateTimeOffset.UtcNow), x.Revoked, excluded = false, updatedAt = x.UpdatedAt, data = x }, ct);
    public Task UpsertMatchAsync(ThreatMatch x, CancellationToken ct) => Put(MatchAlias, $"{x.TenantId}:{x.MatchId:D}", new { x.TenantId, x.MatchId, type = x.MatchType.ToString(), canonicalValue = x.MatchedValue, x.SourceId, x.EndpointId, x.EvidenceEventId, active = true, revoked = false, x.Excluded, updatedAt = x.CreatedAt, data = x }, ct);
    async Task Put(string alias, string id, object body, CancellationToken ct) { using var request = new HttpRequestMessage(HttpMethod.Put, $"{url}/{alias}/_doc/{Uri.EscapeDataString(id)}") { Content = JsonContent.Create(body, options: Json) }; Auth(request); using var response = await client.SendAsync(request, ct); response.EnsureSuccessStatusCode(); }
    public async Task<(long Indicators, long Matches)> CountsAsync(string tenant, CancellationToken ct) => (await Count(IndicatorAlias, tenant, ct), await Count(MatchAlias, tenant, ct));
    async Task<long> Count(string alias, string tenant, CancellationToken ct) { using var request = new HttpRequestMessage(HttpMethod.Post, $"{url}/{alias}/_count") { Content = new StringContent(JsonSerializer.Serialize(new { query = new { term = new Dictionary<string, string> { ["tenantId"] = tenant } } }), Encoding.UTF8, "application/json") }; Auth(request); using var response = await client.SendAsync(request, ct); response.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); return doc.RootElement.GetProperty("count").GetInt64(); }
    void Auth(HttpRequestMessage request) { if (string.IsNullOrWhiteSpace(username)) return; request.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))); }
}
