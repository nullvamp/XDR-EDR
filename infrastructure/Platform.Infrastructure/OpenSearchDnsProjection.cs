using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchDnsProjection : IDnsProjection
{
    public const string Alias = "platform-dns-events";
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly HttpClient _client;
    public OpenSearchDnsProjection(HttpClient client, string baseUrl, string? username, string? password)
    { client.BaseAddress = new(baseUrl); client.Timeout = TimeSpan.FromSeconds(15); if (!string.IsNullOrWhiteSpace(username)) client.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))); _client = client; }
    public async Task EnsureAsync(CancellationToken ct)
    { using var found = await _client.GetAsync($"_alias/{Alias}", ct); if (found.IsSuccessStatusCode) return; var index = $"{Alias}-v1"; using (var create = await _client.PutAsJsonAsync(index, Definition(), ct)) create.EnsureSuccessStatusCode(); using var add = await _client.PostAsJsonAsync("_aliases", new { actions = new[] { new { add = new { index, alias = Alias } } } }, ct); add.EnsureSuccessStatusCode(); }
    public async Task UpsertAsync(string tenant, DnsObservation x, CancellationToken ct)
    { using var r = await _client.PutAsJsonAsync($"{Alias}/_doc/{tenant}-{x.EventId}", Document(tenant, x), ct); r.EnsureSuccessStatusCode(); }
    public async Task<DnsEventPage> SearchAsync(string tenant, DnsSearchRequest q, CancellationToken ct)
    {
        var f = new List<object> { new { term = new { tenant_id = tenant } } };
        if (q.EndpointId is not null) f.Add(new { term = new { endpoint_id = q.EndpointId } });
        if (q.From is not null || q.To is not null) f.Add(new { range = new { observed_at = new { gte = q.From, lte = q.To } } });
        if (!string.IsNullOrWhiteSpace(q.QueryName)) f.Add(new { term = new { canonical_query_name = q.QueryName.TrimEnd('.').ToLowerInvariant() } });
        if (!string.IsNullOrWhiteSpace(q.Suffix)) { var suffix = q.Suffix.Trim('.').ToLowerInvariant(); f.Add(new { @bool = new { should = new object[] { new { term = new { canonical_query_name = suffix } }, new { wildcard = new { canonical_query_name = $"*.{suffix}" } } }, minimum_should_match = 1 } }); }
        if (!string.IsNullOrWhiteSpace(q.RecordType)) f.Add(new { term = new { record_type = q.RecordType.ToUpperInvariant() } });
        if (!string.IsNullOrWhiteSpace(q.ResponseCode)) f.Add(new { term = new { response_code = q.ResponseCode } });
        if (!string.IsNullOrWhiteSpace(q.ResolvedAddress)) f.Add(new { term = new { resolved_addresses = q.ResolvedAddress } });
        if (!string.IsNullOrWhiteSpace(q.ResolvedCidr)) f.Add(new { term = new { resolved_addresses = q.ResolvedCidr } });
        if (!string.IsNullOrWhiteSpace(q.Resolver)) f.Add(new { term = new { resolver_address = q.Resolver } });
        if (!string.IsNullOrWhiteSpace(q.Collector)) f.Add(new { term = new { collector_source = q.Collector } });
        if (!string.IsNullOrWhiteSpace(q.Quality)) f.Add(new { term = new { data_quality = q.Quality } });
        var must = new[] { q.Process, q.User }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => (object)new { simple_query_string = new { query = Escape(x), fields = new[] { "process", "user" } } }).ToArray();
        var body = new Dictionary<string, object?> { { "size", Math.Clamp(q.PageSize, 1, 500) }, { "query", new { @bool = new { filter = f, must } } }, { "sort", new object[] { new { observed_at = new { order = "desc" } }, new { event_id = new { order = "desc" } } } } };
        if (!string.IsNullOrWhiteSpace(q.Cursor)) body["search_after"] = JsonSerializer.Deserialize<object[]>(TenantCursor.Unprotect(tenant, q.Cursor));
        using var response = await _client.PostAsJsonAsync($"{Alias}/_search", body, ct); response.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); var values = new List<DnsObservation>(); string? cursor = null; foreach (var hit in doc.RootElement.GetProperty("hits").GetProperty("hits").EnumerateArray()) { values.Add(JsonSerializer.Deserialize<DnsObservation>(hit.GetProperty("_source").GetProperty("event_data").GetRawText(), Json)!); cursor = TenantCursor.Protect(tenant, hit.GetProperty("sort").GetRawText()); }
        return new(values, cursor);
    }
    public async Task<bool> HealthAsync(CancellationToken ct) { try { using var r = await _client.GetAsync("_cluster/health", ct); return r.IsSuccessStatusCode; } catch (HttpRequestException) { return false; } }
    static object Document(string tenant, DnsObservation x) => new { tenant_id = tenant, endpoint_id = x.EndpointId, event_id = x.EventId, transaction_entity_id = x.TransactionEntityId, canonical_query_name = x.CanonicalQueryName, original_query_name = x.OriginalQueryName, record_type = x.RecordType, response_code = x.ResponseCode, resolver_address = x.ResolverAddress, resolved_addresses = x.Answers.Select(a => a.ResolvedAddress).Where(a => a is not null), process = x.Process?.ProcessEntityId ?? x.Process?.Image, user = x.User, collector_source = x.CollectorSource, data_quality = x.DataQualityFlags, observed_at = x.ObservedAt, event_data = x };
    static object Definition() => new { settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } }, mappings = new { dynamic = "strict", properties = new Dictionary<string, object> { { "tenant_id", new { type = "keyword" } }, { "endpoint_id", new { type = "keyword" } }, { "event_id", new { type = "keyword" } }, { "transaction_entity_id", new { type = "keyword" } }, { "canonical_query_name", new { type = "keyword" } }, { "original_query_name", new { type = "keyword" } }, { "record_type", new { type = "keyword" } }, { "response_code", new { type = "keyword" } }, { "resolver_address", new { type = "ip" } }, { "resolved_addresses", new { type = "ip" } }, { "process", new { type = "keyword" } }, { "user", new { type = "keyword" } }, { "collector_source", new { type = "keyword" } }, { "data_quality", new { type = "keyword" } }, { "observed_at", new { type = "date" } }, { "event_data", new { type = "object", enabled = false } } } } };
    static string Escape(string? value) => string.Concat((value ?? "").Take(256).Select(c => char.IsLetterOrDigit(c) || char.IsWhiteSpace(c) || c is '.' or '_' or '-' or '/' or '\\' or ':' ? c : ' '));
}
