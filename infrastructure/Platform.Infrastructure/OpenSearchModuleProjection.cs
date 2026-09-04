using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchModuleProjection : IModuleProjection
{
    public const string Alias = "platform-module-events";
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly HttpClient _client;

    public OpenSearchModuleProjection(HttpClient client, string url, string? user, string? password)
    {
        client.BaseAddress = new(url); client.Timeout = TimeSpan.FromSeconds(15);
        if (!string.IsNullOrWhiteSpace(user)) client.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}")));
        _client = client;
    }

    public async Task EnsureAsync(CancellationToken ct)
    {
        using var found = await _client.GetAsync($"_alias/{Alias}", ct);
        if (found.IsSuccessStatusCode)
        {
            using var update = await _client.PutAsJsonAsync($"{Alias}/_mapping", new { properties = new { load_address = new { type = "unsigned_long" } } }, ct);
            update.EnsureSuccessStatusCode(); return;
        }
        var index = $"{Alias}-v1";
        using (var create = await _client.PutAsJsonAsync(index, Definition(), ct)) create.EnsureSuccessStatusCode();
        using var alias = await _client.PostAsJsonAsync("_aliases", new { actions = new[] { new { add = new { index, alias = Alias } } } }, ct);
        alias.EnsureSuccessStatusCode();
    }

    public async Task UpsertAsync(string tenant, ModuleObservation value, CancellationToken ct)
    {
        using var response = await _client.PutAsJsonAsync($"{Alias}/_doc/{tenant}-{value.EventId}", Doc(tenant, value), ct);
        response.EnsureSuccessStatusCode();
    }

    public async Task<ModuleEventPage> SearchAsync(string tenant, ModuleSearchRequest request, CancellationToken ct)
    {
        var filters = new List<object> { new { term = new { tenant_id = tenant } } };
        if (request.EndpointId is { } endpoint) filters.Add(new { term = new { endpoint_id = endpoint } });
        if (request.From is not null || request.To is not null) filters.Add(new { range = new { observed_at = new { gte = request.From, lte = request.To } } });
        if (request.Basename is { } basename) filters.Add(new { term = new { basename = basename.ToLowerInvariant() } });
        if (request.Sha256 is { } hash) filters.Add(new { term = new { sha256 = hash } });
        if (request.ImageType is { } imageType) filters.Add(new { term = new { image_type = imageType } });
        if (request.Mode is { } mode) filters.Add(new { term = new { mode = mode.ToString() } });
        if (request.Driver is { } driver) filters.Add(new { term = new { driver } });
        if (request.LoadAddress is { } address) filters.Add(new { term = new { load_address = address } });
        if (request.Architecture is { } architecture) filters.Add(new { term = new { architecture } });
        if (request.Quality is { } quality) filters.Add(new { term = new { data_quality = quality } });
        var terms = new[] { request.Process, request.Path, request.Signer, request.User }
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => (object)new { simple_query_string = new { query = Escape(x), fields = new[] { "process", "normalized_path", "signer", "user" } } }).ToArray();
        var body = new Dictionary<string, object?>
        {
            ["size"] = Math.Clamp(request.PageSize, 1, 500),
            ["query"] = new { @bool = new { filter = filters, must = terms } },
            ["sort"] = new object[] { new { observed_at = new { order = "desc" } }, new { event_id = new { order = "desc" } } }
        };
        if (!string.IsNullOrWhiteSpace(request.Cursor)) body["search_after"] = JsonSerializer.Deserialize<object[]>(TenantCursor.Unprotect(tenant, request.Cursor));
        using var response = await _client.PostAsJsonAsync($"{Alias}/_search", body, ct); response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); var list = new List<ModuleObservation>(); string? cursor = null;
        foreach (var hit in document.RootElement.GetProperty("hits").GetProperty("hits").EnumerateArray())
        {
            list.Add(JsonSerializer.Deserialize<ModuleObservation>(hit.GetProperty("_source").GetProperty("event_data").GetRawText(), Json)!);
            cursor = TenantCursor.Protect(tenant, hit.GetProperty("sort").GetRawText());
        }
        return new(list, cursor);
    }

    public async Task<bool> HealthAsync(CancellationToken ct) { try { using var response = await _client.GetAsync("_cluster/health", ct); return response.IsSuccessStatusCode; } catch { return false; } }
    static object Doc(string tenant, ModuleObservation value) => new { tenant_id = tenant, endpoint_id = value.EndpointId, event_id = value.EventId, module_entity_id = value.ModuleEntityId, process = value.Process?.ProcessEntityId ?? value.Process?.Image, normalized_path = value.NormalizedPath, basename = value.Basename.ToLowerInvariant(), sha256 = value.Hash.Value, signer = value.Signer.Subject, image_type = value.ImageType, mode = value.Mode.ToString(), driver = value.Driver, load_address = value.LoadAddress, architecture = value.Architecture, user = value.User, data_quality = value.DataQualityFlags, observed_at = value.ObservedAt, event_data = value };
    static object Definition() => new { settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } }, mappings = new { dynamic = "strict", properties = new Dictionary<string, object> { ["tenant_id"] = new { type = "keyword" }, ["endpoint_id"] = new { type = "keyword" }, ["event_id"] = new { type = "keyword" }, ["module_entity_id"] = new { type = "keyword" }, ["process"] = new { type = "keyword" }, ["normalized_path"] = new { type = "wildcard" }, ["basename"] = new { type = "keyword" }, ["sha256"] = new { type = "keyword" }, ["signer"] = new { type = "text" }, ["image_type"] = new { type = "keyword" }, ["mode"] = new { type = "keyword" }, ["driver"] = new { type = "boolean" }, ["load_address"] = new { type = "unsigned_long" }, ["architecture"] = new { type = "keyword" }, ["user"] = new { type = "keyword" }, ["data_quality"] = new { type = "keyword" }, ["observed_at"] = new { type = "date" }, ["event_data"] = new { type = "object", enabled = false } } } };
    static string Escape(string? value) => string.Concat((value ?? "").Take(256).Select(c => char.IsLetterOrDigit(c) || char.IsWhiteSpace(c) || c is '.' or '_' or '-' or '/' or '\\' or ':' ? c : ' '));
}
