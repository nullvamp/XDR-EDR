using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

namespace OpenSecurityPlatform.Infrastructure;

public sealed class OpenSearchProcessProjection : IProcessProjection, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    public const string Alias = "platform-processes";
    private readonly HttpClient _client;
    private readonly SemaphoreSlim _writeGate = new(1, 1);

    public OpenSearchProcessProjection(
        HttpClient client,
        string baseUrl,
        string? username,
        string? password
    )
    {
        client.BaseAddress = new Uri(baseUrl);
        client.Timeout = TimeSpan.FromSeconds(15);
        if (!string.IsNullOrWhiteSpace(username))
            client.DefaultRequestHeaders.Authorization = new(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))
            );
        _client = client;
    }

    public async Task EnsureAsync(CancellationToken ct)
    {
        using var alias = await _client.GetAsync($"_alias/{Alias}", ct);
        if (alias.IsSuccessStatusCode)
            return;
        var index = $"{Alias}-v1";
        using (var create = await _client.PutAsJsonAsync(index, Definition(), ct))
            create.EnsureSuccessStatusCode();
        using var add = await _client.PostAsJsonAsync(
            "_aliases",
            new { actions = new[] { new { add = new { index, alias = Alias } } } },
            ct
        );
        add.EnsureSuccessStatusCode();
    }

    public async Task UpsertAsync(ProcessEntityView process, string eventId, CancellationToken ct)
    {
        await _writeGate.WaitAsync(ct);
        try
        {
            using var response = await _client.PutAsJsonAsync(
                $"{Alias}/_doc/{process.TenantId}-{process.EndpointId}-{process.ProcessEntityId}",
                Document(process, eventId),
                ct
            );
            response.EnsureSuccessStatusCode();
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async Task<ProcessPage> SearchAsync(
        string tenantId,
        ProcessSearchRequest request,
        CancellationToken ct
    )
    {
        var filters = new List<object>
        {
            new { term = new { tenant_id = tenantId } },
            new { range = new { start_time = new { gte = request.From, lte = request.To } } },
        };
        if (request.EndpointId is not null)
            filters.Add(new { term = new { endpoint_id = request.EndpointId } });
        if (request.ProcessId is not null)
            filters.Add(new { term = new { pid = request.ProcessId } });
        if (request.ParentProcessId is not null)
            filters.Add(new { term = new { parent_pid = request.ParentProcessId } });
        if (request.Signature is not null)
            filters.Add(
                new
                {
                    term = new
                    {
                        signature_state = request.Signature.ToString()!.ToLowerInvariant(),
                    },
                }
            );
        if (request.State == "running")
            filters.Add(
                new { @bool = new { must_not = new { exists = new { field = "exit_time" } } } }
            );
        else if (request.State == "exited")
            filters.Add(new { exists = new { field = "exit_time" } });
        var terms = new[]
        {
            request.ProcessName,
            request.Path,
            request.CommandLine,
            request.User,
            request.Sha256,
        }
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => Escape(x!))
            .ToArray();
        var must =
            terms.Length == 0
                ? Array.Empty<object>()
                :
                [
                    new
                    {
                        simple_query_string = new
                        {
                            query = string.Join(' ', terms),
                            fields = new[]
                            {
                                "executable_name",
                                "executable_path",
                                "command_line",
                                "user_name",
                                "sha256",
                            },
                            default_operator = "and",
                        },
                    },
                ];
        var body = new Dictionary<string, object?>
        {
            { "size", Math.Clamp(request.PageSize, 1, 500) },
            { "query", new { @bool = new { filter = filters, must } } },
            {
                "sort",
                new object[]
                {
                    new { start_time = new { order = "desc" } },
                    new { process_entity_id = new { order = "desc" } },
                }
            },
        };
        if (!string.IsNullOrWhiteSpace(request.Cursor))
            body["search_after"] = JsonSerializer.Deserialize<object[]>(
                TenantCursor.Unprotect(tenantId, request.Cursor)
            );
        using var response = await _client.PostAsJsonAsync($"{Alias}/_search", body, ct);
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var values = new List<ProcessEntityView>();
        string? cursor = null;
        foreach (
            var hit in json.RootElement.GetProperty("hits").GetProperty("hits").EnumerateArray()
        )
        {
            values.Add(
                JsonSerializer.Deserialize<ProcessEntityView>(
                    hit.GetProperty("_source").GetProperty("process").GetRawText(),
                    JsonOptions
                )!
            );
            cursor = TenantCursor.Protect(tenantId, hit.GetProperty("sort").GetRawText());
        }
        return new(values, cursor);
    }

    public async Task<ProcessProjectionRebuildResult> RebuildAsync(
        IReadOnlyList<ProcessEntityView> processes,
        CancellationToken ct
    )
    {
        await _writeGate.WaitAsync(ct);
        try
        {
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            var index = $"{Alias}-v{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
            using (var create = await _client.PutAsJsonAsync(index, Definition(), ct))
                create.EnsureSuccessStatusCode();
            foreach (var batch in processes.Chunk(500))
            {
                var body = new StringBuilder();
                foreach (var process in batch)
                {
                    var id = $"{process.TenantId}-{process.EndpointId}-{process.ProcessEntityId}";
                    body.AppendLine(
                        JsonSerializer.Serialize(
                            new { index = new { _index = index, _id = id } },
                            JsonOptions
                        )
                    );
                    body.AppendLine(
                        JsonSerializer.Serialize(Document(process, "rebuild"), JsonOptions)
                    );
                }
                using var content = new StringContent(
                    body.ToString(),
                    Encoding.UTF8,
                    "application/x-ndjson"
                );
                using var bulk = await _client.PostAsync("_bulk", content, ct);
                bulk.EnsureSuccessStatusCode();
                using var result = JsonDocument.Parse(await bulk.Content.ReadAsStringAsync(ct));
                if (result.RootElement.GetProperty("errors").GetBoolean())
                    throw new InvalidOperationException("Process projection bulk rebuild failed.");
            }
            using (var refresh = await _client.PostAsync($"{index}/_refresh", null, ct))
                refresh.EnsureSuccessStatusCode();
            using var current = await _client.GetAsync($"_alias/{Alias}", ct);
            var actions = new List<object>();
            if (current.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(await current.Content.ReadAsStringAsync(ct));
                foreach (var old in doc.RootElement.EnumerateObject())
                    actions.Add(new { remove = new { index = old.Name, alias = Alias } });
            }
            actions.Add(new { add = new { index, alias = Alias } });
            using (var swap = await _client.PostAsJsonAsync("_aliases", new { actions }, ct))
                swap.EnsureSuccessStatusCode();
            var count = await _client.GetFromJsonAsync<JsonElement>($"{index}/_count", ct);
            var actual = count.GetProperty("count").GetInt32();
            if (actual != processes.Count)
                throw new InvalidOperationException("Process projection rebuild count mismatch.");
            return new(index, actual, System.Diagnostics.Stopwatch.GetElapsedTime(started), true);
        }
        finally
        {
            _writeGate.Release();
        }
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

    private static object Document(ProcessEntityView p, string eventId) =>
        new
        {
            tenant_id = p.TenantId,
            endpoint_id = p.EndpointId,
            process_entity_id = p.ProcessEntityId,
            pid = p.ProcessId,
            parent_pid = p.ParentProcessId,
            executable_name = p.ExecutableName,
            executable_path = p.ExecutablePath,
            command_line = p.CommandLine,
            user_name = p.UserName,
            sha256 = p.ExecutableMetadata?.Sha256,
            signature_state = p.ExecutableMetadata?.SignatureState.ToString().ToLowerInvariant(),
            start_time = p.StartTime,
            exit_time = p.ExitTime,
            event_id = eventId,
            process = p,
        };

    private static object Definition() =>
        new
        {
            settings = new { index = new { number_of_shards = 1, number_of_replicas = 0 } },
            mappings = new
            {
                dynamic = "strict",
                properties = new Dictionary<string, object>
                {
                    { "tenant_id", new { type = "keyword" } },
                    { "endpoint_id", new { type = "keyword" } },
                    { "process_entity_id", new { type = "keyword" } },
                    { "pid", new { type = "integer" } },
                    { "parent_pid", new { type = "integer" } },
                    {
                        "executable_name",
                        new { type = "text", fields = new { keyword = new { type = "keyword" } } }
                    },
                    {
                        "executable_path",
                        new { type = "text", fields = new { keyword = new { type = "keyword" } } }
                    },
                    { "command_line", new { type = "text", index_options = "docs" } },
                    { "user_name", new { type = "keyword" } },
                    { "sha256", new { type = "keyword" } },
                    { "signature_state", new { type = "keyword" } },
                    { "start_time", new { type = "date" } },
                    { "exit_time", new { type = "date" } },
                    { "event_id", new { type = "keyword" } },
                    { "process", new { type = "object", enabled = false } },
                },
            },
        };

    private static string Escape(string value) =>
        string.Concat(
            value
                .Take(256)
                .Select(c =>
                    char.IsLetterOrDigit(c) || char.IsWhiteSpace(c) || c is '.' or '_' or '-'
                        ? c
                        : ' '
                )
        );

    public void Dispose() => _writeGate.Dispose();
}
