using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchEndpointProjection : IEndpointProjection
{
    public const string Alias = "platform-endpoints";
    public const string Index = "platform-endpoints-v1";
    private readonly HttpClient _client;
    private ProjectionRebuildProgress _progress = new(
        false,
        null,
        0,
        0,
        null,
        DateTimeOffset.UtcNow,
        null
    );

    public OpenSearchEndpointProjection(
        HttpClient client,
        string baseUrl,
        string? username,
        string? password
    )
    {
        if (
            !Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
            || (
                uri.Scheme != "https"
                && Environment.GetEnvironmentVariable("PLATFORM_ENVIRONMENT") != "compose"
            )
        )
            throw new InvalidOperationException(
                "OpenSearch requires HTTPS outside the isolated Compose profile."
            );
        client.BaseAddress = uri;
        client.Timeout = TimeSpan.FromSeconds(10);
        if (!string.IsNullOrWhiteSpace(username))
            client.DefaultRequestHeaders.Authorization = new(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))
            );
        _client = client;
    }

    public async Task EnsureIndexAsync(CancellationToken ct)
    {
        var properties = Properties();
        using var exists = await _client.SendAsync(new(HttpMethod.Head, Index), ct);
        if (exists.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            using var create = await _client.PutAsJsonAsync(
                Index,
                new
                {
                    settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } },
                    mappings = new { dynamic = "strict", properties },
                },
                ct
            );
            create.EnsureSuccessStatusCode();
            using var alias = await _client.PostAsJsonAsync(
                "_aliases",
                new { actions = new[] { new { add = new { index = Index, alias = Alias } } } },
                ct
            );
            alias.EnsureSuccessStatusCode();
        }
        else
        {
            using var update = await _client.PutAsJsonAsync(
                $"{Index}/_mapping",
                new { properties },
                ct
            );
            update.EnsureSuccessStatusCode();
        }
    }

    public async Task UpsertAsync(EndpointView endpoint, string eventId, CancellationToken ct)
    {
        var body = new
        {
            tenant_id = endpoint.TenantId,
            endpoint_id = endpoint.Id,
            device_identity = endpoint.DeviceIdentity,
            hostname = endpoint.Hostname,
            platform = endpoint.Platform,
            os_version = endpoint.OsVersion,
            architecture = endpoint.Architecture,
            status = endpoint.Status.ToString().ToLowerInvariant(),
            agent_version = endpoint.AgentVersion,
            last_seen_at = endpoint.LastSeenAt,
            tags = endpoint.Inventory?.Tags ?? [],
            groups = endpoint.Inventory?.Groups ?? [],
            projection_version = 1,
            source_revision = endpoint.Revision,
            event_id = eventId,
        };
        using var response = await _client.PutAsJsonAsync(
            $"{Alias}/_doc/{endpoint.TenantId}-{endpoint.Id}",
            body,
            ct
        );
        response.EnsureSuccessStatusCode();
    }

    public async Task<EndpointPage> SearchAsync(
        string tenantId,
        int pageSize,
        string? cursor,
        string? query,
        EndpointStatus? status,
        CancellationToken ct
    )
    {
        pageSize = Math.Clamp(pageSize, 1, 500);
        var filters = new List<object> { new { term = new { tenant_id = tenantId } } };
        if (status is not null)
            filters.Add(new { term = new { status = status.ToString()!.ToLowerInvariant() } });
        var must = string.IsNullOrWhiteSpace(query)
            ? Array.Empty<object>()
            :
            [
                new
                {
                    simple_query_string = new
                    {
                        query = Escape(query),
                        fields = new[] { "hostname", "device_identity", "agent_version" },
                        default_operator = "and",
                    },
                },
            ];
        var request = new Dictionary<string, object?>
        {
            { "size", pageSize },
            { "query", new { @bool = new { filter = filters, must } } },
            {
                "sort",
                new object[]
                {
                    new Dictionary<string, object>
                    {
                        {
                            "last_seen_at",
                            new
                            {
                                order = "desc",
                                missing = "_last",
                                unmapped_type = "date",
                            }
                        },
                    },
                    new Dictionary<string, object> { { "endpoint_id", new { order = "asc" } } },
                }
            },
            { "_source", true },
        };
        if (!string.IsNullOrWhiteSpace(cursor))
        {
            try
            {
                request["search_after"] = JsonSerializer.Deserialize<object?[]>(
                    Encoding.UTF8.GetString(Convert.FromBase64String(cursor))
                );
            }
            catch (Exception e) when (e is FormatException or JsonException)
            {
                throw new EnrollmentConflictException(
                    "CURSOR_INVALID",
                    "Search cursor is invalid."
                );
            }
        }
        using var response = await _client.PostAsJsonAsync($"{Alias}/_search", request, ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var values = new List<EndpointView>();
        JsonElement? lastSort = null;
        foreach (
            var hit in doc.RootElement.GetProperty("hits").GetProperty("hits").EnumerateArray()
        )
        {
            var s = hit.GetProperty("_source");
            values.Add(
                new(
                    s.GetProperty("endpoint_id").GetGuid(),
                    tenantId,
                    s.GetProperty("device_identity").GetString()!,
                    s.GetProperty("hostname").GetString()!,
                    s.GetProperty("platform").GetString()!,
                    s.GetProperty("os_version").GetString()!,
                    s.GetProperty("architecture").GetString()!,
                    Enum.Parse<EndpointStatus>(s.GetProperty("status").GetString()!, true),
                    s.TryGetProperty("last_seen_at", out var seen)
                    && seen.ValueKind != JsonValueKind.Null
                        ? seen.GetDateTimeOffset()
                        : null,
                    s.GetProperty("agent_version").GetString()!,
                    [],
                    s.GetProperty("source_revision").GetInt64(),
                    null
                )
            );
            lastSort = hit.GetProperty("sort");
        }
        return new(
            values,
            lastSort is null
                ? null
                : Convert.ToBase64String(Encoding.UTF8.GetBytes(lastSort.Value.GetRawText()))
        );
    }

    public async Task<bool> HealthAsync(CancellationToken ct)
    {
        try
        {
            using var response = await _client.GetAsync("_cluster/health", ct);
            return response.IsSuccessStatusCode;
        }
        catch (HttpRequestException)
        {
            return false;
        }
    }

    public async Task<ProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<EndpointView> endpoints,
        CancellationToken ct
    )
    {
        var startedAt = DateTimeOffset.UtcNow;
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var index = $"platform-endpoints-v{startedAt:yyyyMMddHHmmss}";
        Interlocked.Exchange(
            ref _progress,
            new(true, index, endpoints.Count, 0, startedAt, startedAt, null)
        );
        try
        {
            using (
                var create = await _client.PutAsJsonAsync(
                    index,
                    new
                    {
                        settings = new
                        {
                            index = new { number_of_shards = 1, number_of_replicas = 0 },
                        },
                        mappings = new { dynamic = "strict", properties = Properties() },
                    },
                    ct
                )
            )
                create.EnsureSuccessStatusCode();
            var completed = 0;
            foreach (var endpoint in endpoints)
            {
                using var response = await _client.PutAsJsonAsync(
                    $"{index}/_doc/{endpoint.TenantId}-{endpoint.Id}",
                    Document(endpoint, "rebuild"),
                    ct
                );
                response.EnsureSuccessStatusCode();
                completed++;
                Interlocked.Exchange(
                    ref _progress,
                    new(
                        true,
                        index,
                        endpoints.Count,
                        completed,
                        startedAt,
                        DateTimeOffset.UtcNow,
                        null
                    )
                );
            }
            using (var refresh = await _client.PostAsync($"{index}/_refresh", null, ct))
                refresh.EnsureSuccessStatusCode();
            using var aliases = await _client.GetAsync($"_alias/{Alias}", ct);
            var actions = new List<object>();
            if (aliases.IsSuccessStatusCode)
            {
                using var document = JsonDocument.Parse(
                    await aliases.Content.ReadAsStringAsync(ct)
                );
                foreach (var old in document.RootElement.EnumerateObject())
                    actions.Add(new { remove = new { index = old.Name, alias = Alias } });
            }
            actions.Add(new { add = new { index, alias = Alias } });
            using (var swap = await _client.PostAsJsonAsync("_aliases", new { actions }, ct))
                swap.EnsureSuccessStatusCode();
            using var count = await _client.GetAsync($"{index}/_count", ct);
            count.EnsureSuccessStatusCode();
            using var countDocument = JsonDocument.Parse(await count.Content.ReadAsStringAsync(ct));
            var actual = countDocument.RootElement.GetProperty("count").GetInt32();
            if (actual != endpoints.Count)
                throw new InvalidOperationException(
                    "Projection rebuild verification count did not match PostgreSQL."
                );
            Interlocked.Exchange(
                ref _progress,
                new(false, index, endpoints.Count, actual, startedAt, DateTimeOffset.UtcNow, null)
            );
            return new(index, actual, System.Diagnostics.Stopwatch.GetElapsedTime(started), true);
        }
        catch (Exception e)
        {
            Interlocked.Exchange(
                ref _progress,
                new(
                    false,
                    index,
                    endpoints.Count,
                    _progress.CompletedDocuments,
                    startedAt,
                    DateTimeOffset.UtcNow,
                    e.GetType().Name
                )
            );
            throw;
        }
    }

    public ProjectionRebuildProgress GetRebuildProgress() => _progress;

    private static object Document(EndpointView endpoint, string eventId) =>
        new
        {
            tenant_id = endpoint.TenantId,
            endpoint_id = endpoint.Id,
            device_identity = endpoint.DeviceIdentity,
            hostname = endpoint.Hostname,
            platform = endpoint.Platform,
            os_version = endpoint.OsVersion,
            architecture = endpoint.Architecture,
            status = endpoint.Status.ToString().ToLowerInvariant(),
            agent_version = endpoint.AgentVersion,
            last_seen_at = endpoint.LastSeenAt,
            tags = endpoint.Inventory?.Tags ?? [],
            groups = endpoint.Inventory?.Groups ?? [],
            projection_version = 1,
            source_revision = endpoint.Revision,
            event_id = eventId,
        };

    private static Dictionary<string, object> Properties() =>
        new()
        {
            { "tenant_id", new { type = "keyword" } },
            { "endpoint_id", new { type = "keyword" } },
            { "device_identity", new { type = "keyword" } },
            {
                "hostname",
                new
                {
                    type = "text",
                    fields = new { keyword = new { type = "keyword", ignore_above = 253 } },
                }
            },
            { "platform", new { type = "keyword" } },
            { "os_version", new { type = "keyword" } },
            { "architecture", new { type = "keyword" } },
            { "status", new { type = "keyword" } },
            { "agent_version", new { type = "keyword" } },
            { "last_seen_at", new { type = "date" } },
            { "tags", new { type = "keyword" } },
            { "groups", new { type = "keyword" } },
            { "projection_version", new { type = "integer" } },
            { "source_revision", new { type = "long" } },
            { "event_id", new { type = "keyword" } },
        };

    private static string Escape(string value) =>
        string.Concat(
            value
                .Take(256)
                .Select(c =>
                    c
                        is '+'
                            or '-'
                            or '='
                            or '&'
                            or '|'
                            or '>'
                            or '<'
                            or '!'
                            or '('
                            or ')'
                            or '{'
                            or '}'
                            or '['
                            or ']'
                            or '^'
                            or '"'
                            or '~'
                            or '*'
                            or '?'
                            or ':'
                            or '\\'
                            or '/'
                        ? ' '
                        : c
                )
        );
}
