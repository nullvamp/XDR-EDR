using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchTunnelAnalyticsProjection(HttpClient client, string url, string? username, string? password) : ITunnelAnalyticsProjection
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web); const string O = "platform-tunnel-observations"; const string F = "platform-tunnel-findings";
    public async Task EnsureAsync(CancellationToken ct) { await Ensure(O, "observationId", ct); await Ensure(F, "findingId", ct); }
    async Task Ensure(string index, string id, CancellationToken ct) { var body = $"{{\"settings\":{{\"index.mapping.total_fields.limit\":512}},\"mappings\":{{\"dynamic\":false,\"properties\":{{\"tenantId\":{{\"type\":\"keyword\"}},\"{id}\":{{\"type\":\"keyword\"}},\"endpointId\":{{\"type\":\"keyword\"}},\"processEntityId\":{{\"type\":\"keyword\"}},\"kind\":{{\"type\":\"keyword\"}},\"lastObserved\":{{\"type\":\"date\"}},\"data\":{{\"type\":\"object\",\"enabled\":false}}}}}}}}"; using var r = new HttpRequestMessage(HttpMethod.Put, $"{url}/{index}") { Content = new StringContent(body, Encoding.UTF8, "application/json") }; Auth(r); using var response = await client.SendAsync(r, ct); if (!response.IsSuccessStatusCode && response.StatusCode != System.Net.HttpStatusCode.BadRequest) response.EnsureSuccessStatusCode(); }
    public Task UpsertObservationAsync(TunnelObservation x, CancellationToken ct) => Put(O, $"{x.TenantId}:{x.ObservationId:D}", new { x.TenantId, x.ObservationId, x.EndpointId, x.ProcessEntityId, kind = x.Kind.ToString(), x.LastObserved, data = x }, ct);
    public Task UpsertFindingAsync(TunnelFinding x, CancellationToken ct) => Put(F, $"{x.TenantId}:{x.FindingId:D}", new { x.TenantId, x.FindingId, x.EndpointId, x.ProcessEntityId, kind = x.Kind.ToString(), x.LastObserved, data = x }, ct);
    async Task Put(string index, string id, object data, CancellationToken ct) { using var r = new HttpRequestMessage(HttpMethod.Put, $"{url}/{index}/_doc/{Uri.EscapeDataString(id)}") { Content = JsonContent.Create(data, options: Json) }; Auth(r); using var response = await client.SendAsync(r, ct); response.EnsureSuccessStatusCode(); }
    public async Task<(long Observations, long Findings)> CountsAsync(string tenant, CancellationToken ct) => (await Count(O, tenant, ct), await Count(F, tenant, ct));
    async Task<long> Count(string index, string tenant, CancellationToken ct) { using var r = new HttpRequestMessage(HttpMethod.Post, $"{url}/{index}/_count") { Content = new StringContent(JsonSerializer.Serialize(new { query = new { term = new Dictionary<string, string> { { "tenantId", tenant } } } }), Encoding.UTF8, "application/json") }; Auth(r); using var response = await client.SendAsync(r, ct); response.EnsureSuccessStatusCode(); using var d = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); return d.RootElement.GetProperty("count").GetInt64(); }
    void Auth(HttpRequestMessage r) { if (!string.IsNullOrWhiteSpace(username)) r.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))); }
}
