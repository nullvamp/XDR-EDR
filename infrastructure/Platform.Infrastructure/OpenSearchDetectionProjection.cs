using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchDetectionProjection : IDetectionProjection
{
    public const string Alias = "platform-detection-findings";
    readonly HttpClient _client;
    public OpenSearchDetectionProjection(HttpClient client, string url, string? user, string? password) { client.BaseAddress = new(url); client.Timeout = TimeSpan.FromSeconds(15); if (!string.IsNullOrWhiteSpace(user)) client.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"))); _client = client; }
    public async Task EnsureAsync(CancellationToken ct) { using var found = await _client.GetAsync($"_alias/{Alias}", ct); if (!found.IsSuccessStatusCode) { var index = $"{Alias}-v1"; using (var create = await _client.PutAsJsonAsync(index, Definition(), ct)) create.EnsureSuccessStatusCode(); using var alias = await _client.PostAsJsonAsync("_aliases", new { actions = new[] { new { add = new { index, alias = Alias } } } }, ct); alias.EnsureSuccessStatusCode(); } using var mapping = await _client.PutAsJsonAsync($"{Alias}/_mapping", Mapping(), ct); mapping.EnsureSuccessStatusCode(); }
    public async Task UpsertAsync(DetectionFinding finding, CancellationToken ct) { using var response = await _client.PutAsJsonAsync($"{Alias}/_doc/{finding.TenantId}-{finding.FindingId}", Doc(finding), ct); response.EnsureSuccessStatusCode(); }
    public async Task<long> CountAsync(string tenant, CancellationToken ct) { using var response = await _client.PostAsJsonAsync($"{Alias}/_count", new { query = new { term = new { tenant_id = tenant } } }, ct); response.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); return doc.RootElement.GetProperty("count").GetInt64(); }
    public async Task<bool> HealthAsync(CancellationToken ct) { try { using var response = await _client.GetAsync("_cluster/health", ct); return response.IsSuccessStatusCode; } catch (HttpRequestException) { return false; } }
    static object Doc(DetectionFinding x) => new { tenant_id = x.TenantId, finding_id = x.FindingId, detection_id = x.DetectionId, detection_version = x.DetectionVersion, rule_name = x.RuleName, severity = x.Severity, confidence = x.Confidence, endpoint_id = x.EndpointId, process_entity_id = x.ProcessEntityId, entity_id = x.EntityId, group_key = x.GroupKey, first_seen = x.FirstSeen, last_seen = x.LastSeen, created_at = x.CreatedAt, suppressed = x.Suppressed, excluded = x.Excluded, execution_mode = x.ExecutionMode.ToString(), status = x.Status, missing_telemetry = x.MissingTelemetry, telemetry_quality = x.TelemetryQuality, finding_data = x };
    static Dictionary<string, object> Properties() => new() { ["tenant_id"] = new { type = "keyword" }, ["finding_id"] = new { type = "keyword" }, ["detection_id"] = new { type = "keyword" }, ["detection_version"] = new { type = "integer" }, ["rule_name"] = new { type = "text", fields = new { keyword = new { type = "keyword" } } }, ["severity"] = new { type = "integer" }, ["confidence"] = new { type = "integer" }, ["endpoint_id"] = new { type = "keyword" }, ["process_entity_id"] = new { type = "keyword" }, ["entity_id"] = new { type = "keyword" }, ["group_key"] = new { type = "keyword" }, ["first_seen"] = new { type = "date" }, ["last_seen"] = new { type = "date" }, ["created_at"] = new { type = "date" }, ["suppressed"] = new { type = "boolean" }, ["excluded"] = new { type = "boolean" }, ["execution_mode"] = new { type = "keyword" }, ["status"] = new { type = "keyword" }, ["missing_telemetry"] = new { type = "keyword" }, ["telemetry_quality"] = new { type = "keyword" }, ["finding_data"] = new { type = "object", enabled = false } };
    static object Mapping() => new { properties = Properties() };
    static object Definition() => new { settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } }, mappings = new { dynamic = "strict", properties = Properties() } };
}
