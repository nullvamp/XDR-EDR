using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchRegistryProjection : IRegistryProjection, IDisposable
{
    public const string Alias = "platform-registry-events";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _client;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private RegistryProjectionRebuildProgress _progress = new(Guid.Empty, Alias, "global", "idle", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, null, 0, 0, 0, Alias, null, false);
    public OpenSearchRegistryProjection(HttpClient client, string baseUrl, string? username, string? password) { client.BaseAddress = new(baseUrl); client.Timeout = TimeSpan.FromSeconds(15); if (!string.IsNullOrWhiteSpace(username)) client.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))); _client = client; }
    public async Task EnsureAsync(CancellationToken ct) { using var found = await _client.GetAsync($"_alias/{Alias}", ct); if (found.IsSuccessStatusCode) return; var index = $"{Alias}-v1"; using (var create = await _client.PutAsJsonAsync(index, Definition(), ct)) create.EnsureSuccessStatusCode(); using var add = await _client.PostAsJsonAsync("_aliases", new { actions = new[] { new { add = new { index, alias = Alias } } } }, ct); add.EnsureSuccessStatusCode(); }
    public async Task UpsertAsync(string tenant, RegistryObservation x, CancellationToken ct) { await _gate.WaitAsync(ct); try { using var r = await _client.PutAsJsonAsync($"{Alias}/_doc/{tenant}-{x.EventId}", Document(tenant, x), ct); r.EnsureSuccessStatusCode(); } finally { _gate.Release(); } }
    public async Task<RegistryEventPage> SearchAsync(string tenant, RegistrySearchRequest q, CancellationToken ct)
    {
        var filters = new List<object> { new { term = new { tenant_id = tenant } } };
        if (q.EndpointId is not null) filters.Add(new { term = new { endpoint_id = q.EndpointId } }); if (q.From is not null || q.To is not null) filters.Add(new { range = new { observed_at = new { gte = q.From, lt = q.To } } }); if (!string.IsNullOrWhiteSpace(q.Hive)) filters.Add(new { term = new { hive = q.Hive } }); if (q.Operation is not null) filters.Add(new { term = new { operation = q.Operation.ToString()!.ToLowerInvariant() } }); if (!string.IsNullOrWhiteSpace(q.ValueType)) filters.Add(new { term = new { value_type = q.ValueType } }); if (!string.IsNullOrWhiteSpace(q.Collector)) filters.Add(new { term = new { collector_source = q.Collector } }); if (!string.IsNullOrWhiteSpace(q.ContentHash)) filters.Add(new { term = new { content_hash = q.ContentHash } });
        var terms = new[] { q.KeyPath, q.ValueName, q.Process, q.User, q.DataQuality }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(Escape).ToArray();
        var must = terms.Length == 0
            ? Array.Empty<object>()
            : new object[]
            {
                new
                {
                    simple_query_string = new
                    {
                        query = string.Join(' ', terms),
                        fields = new[]
                        {
                            "key_path",
                            "previous_key_path",
                            "value_name",
                            "process",
                            "user_sid",
                            "data_quality",
                        },
                        default_operator = "and",
                    },
                },
            };
        var body = new Dictionary<string, object?>
        {
            { "size", Math.Clamp(q.PageSize, 1, 500) },
            { "query", new { @bool = new { filter = filters, must } } },
            {
                "sort",
                new object[]
                {
                    new { observed_at = new { order = "desc" } },
                    new { event_id = new { order = "desc" } },
                }
            },
        };
        if (!string.IsNullOrWhiteSpace(q.Cursor)) body["search_after"] = JsonSerializer.Deserialize<object[]>(TenantCursor.Unprotect(tenant, q.Cursor)); using var response = await _client.PostAsJsonAsync($"{Alias}/_search", body, ct); response.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); var values = new List<RegistryObservation>(); string? cursor = null; foreach (var hit in doc.RootElement.GetProperty("hits").GetProperty("hits").EnumerateArray()) { values.Add(JsonSerializer.Deserialize<RegistryObservation>(hit.GetProperty("_source").GetProperty("event_data").GetRawText(), Json)!); cursor = TenantCursor.Protect(tenant, hit.GetProperty("sort").GetRawText()); }
        return new(values, cursor);
    }
    public async Task<ProcessProjectionRebuildResult> RebuildAsync(IReadOnlyList<RegistryObservation> events, CancellationToken ct)
    {
        await _gate.WaitAsync(ct); var id = Guid.NewGuid(); var started = DateTimeOffset.UtcNow; var index = $"{Alias}-v{started:yyyyMMddHHmmss}"; _progress = new(id, index, "global", "running", started, started, null, events.Count, 0, 0, Alias, null, true); try { using (var create = await _client.PutAsJsonAsync(index, Definition(), ct)) create.EnsureSuccessStatusCode(); var count = 0; foreach (var batch in events.Chunk(500)) { var b = new StringBuilder(); foreach (var x in batch) { var tenant = Tenant(x); b.AppendLine(JsonSerializer.Serialize(new { index = new { _index = index, _id = $"{tenant}-{x.EventId}" } }, Json)); b.AppendLine(JsonSerializer.Serialize(Document(tenant, x), Json)); } using var content = new StringContent(b.ToString(), Encoding.UTF8, "application/x-ndjson"); using var bulk = await _client.PostAsync("_bulk", content, ct); bulk.EnsureSuccessStatusCode(); count += batch.Length; _progress = _progress with { IndexedCount = count, UpdatedAt = DateTimeOffset.UtcNow }; } using (var refresh = await _client.PostAsync($"{index}/_refresh", null, ct)) refresh.EnsureSuccessStatusCode(); var actions = new List<object>(); using (var current = await _client.GetAsync($"_alias/{Alias}", ct)) { if (current.IsSuccessStatusCode) { using var d = JsonDocument.Parse(await current.Content.ReadAsStringAsync(ct)); foreach (var old in d.RootElement.EnumerateObject()) actions.Add(new { remove = new { index = old.Name, alias = Alias } }); } } actions.Add(new { add = new { index, alias = Alias } }); using (var swap = await _client.PostAsJsonAsync("_aliases", new { actions }, ct)) swap.EnsureSuccessStatusCode(); var completed = DateTimeOffset.UtcNow; _progress = _progress with { State = "completed", IndexedCount = count, CurrentAlias = index, UpdatedAt = completed, CompletedAt = completed }; return new(index, count, completed - started, true); } catch (Exception e) { var failed = DateTimeOffset.UtcNow; _progress = _progress with { State = "failed", FailureCount = _progress.FailureCount + 1, UpdatedAt = failed, CompletedAt = failed, ErrorSummary = e.GetType().Name }; throw; } finally { _gate.Release(); }
    }
    private static string Tenant(RegistryObservation x) => x.CorrelationId?.StartsWith("tenant:", StringComparison.Ordinal) == true ? x.CorrelationId[7..] : throw new InvalidOperationException("Registry rebuild requires tenant correlation metadata.");
    public RegistryProjectionRebuildProgress GetRebuildProgress() => _progress;
    public async Task<bool> HealthAsync(CancellationToken ct) { try { using var r = await _client.GetAsync("_cluster/health", ct); return r.IsSuccessStatusCode; } catch (HttpRequestException) { return false; } }
    private static object Document(string tenant, RegistryObservation x) => new { tenant_id = tenant, endpoint_id = x.EndpointId, event_id = x.EventId, key_entity_id = x.RegistryKeyEntityId, value_entity_id = x.RegistryValueEntityId, hive = x.Hive, key_path = x.KeyPath, previous_key_path = x.PreviousKeyPath, value_name = x.ValueName, value_type = x.Value.ValueType, operation = x.Kind.ToString().ToLowerInvariant(), native_operation = x.NativeOperation, process = x.Process?.ProcessEntityId ?? x.Process?.Image, user_sid = x.UserSid, content_hash = x.Value.Sha256, data_length = x.Value.DataLength, capture_state = x.Value.CaptureMode.ToString().ToLowerInvariant(), collector_source = x.CollectorSource, data_quality = x.DataQualityFlags, deleted = x.Deleted, observed_at = x.ObservedAt, event_data = x };
    private static object Definition() => new { settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } }, mappings = new { dynamic = "strict", properties = new Dictionary<string, object> { { "tenant_id", new { type = "keyword" } }, { "endpoint_id", new { type = "keyword" } }, { "event_id", new { type = "keyword" } }, { "key_entity_id", new { type = "keyword" } }, { "value_entity_id", new { type = "keyword" } }, { "hive", new { type = "keyword" } }, { "key_path", new { type = "text", fields = new { keyword = new { type = "keyword" } } } }, { "previous_key_path", new { type = "text" } }, { "value_name", new { type = "text", fields = new { keyword = new { type = "keyword" } } } }, { "value_type", new { type = "keyword" } }, { "operation", new { type = "keyword" } }, { "native_operation", new { type = "keyword" } }, { "process", new { type = "keyword" } }, { "user_sid", new { type = "keyword" } }, { "content_hash", new { type = "keyword" } }, { "data_length", new { type = "long" } }, { "capture_state", new { type = "keyword" } }, { "collector_source", new { type = "keyword" } }, { "data_quality", new { type = "keyword" } }, { "deleted", new { type = "boolean" } }, { "observed_at", new { type = "date" } }, { "event_data", new { type = "object", enabled = false } } } } };
    private static string Escape(string? value) => string.Concat((value ?? "").Take(256).Select(c => char.IsLetterOrDigit(c) || char.IsWhiteSpace(c) || c is '.' or '_' or '-' or '/' or '\\' or ':' ? c : ' '));
    public void Dispose() => _gate.Dispose();
}
